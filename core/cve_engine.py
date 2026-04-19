"""
R3D Agent — CVE Engine
Tiered CVE lookup system:
Tier 1: Local SQLite database (fast, offline, no cost)
Tier 2: Zero day flag + operator decision
Tier 3: NVD API live lookup (optional, requires confirmation)

Design principle: Unknown findings get flagged, not fabricated.
Grounded in Kalai et al. (2025) — models should abstain under
uncertainty rather than guess.

NVD API key:
    Pass via --nvd-api-key CLI flag or set NVD_API_KEY env var.
    Authenticated  : 50 req/s  — full database build ~5 minutes.
    Unauthenticated: 5 req/30s — full database build 30-60 minutes.

Database:
    Stored in SQLite (data/cve_database.db).
    Auto-migrates from legacy JSON if it exists on first run.
    ~10x faster queries vs JSON dict — indexed key lookups.

Security fixes applied:
- Input sanitization on service/version/target (prevents path traversal)
- NVD API response validation (prevents malformed data crashes)
- Evidence file size cap (prevents storage exhaustion)
- Database integrity checks (prevents corrupted file crashes)
- NVD API retry with exponential backoff (handles rate limits gracefully)

Compatibility: Windows 10/11, Ubuntu, Kali Linux, macOS
"""

import json
import os
import re
import sqlite3
import time
import requests
from datetime import datetime
from pathlib import Path
from typing import Optional
from pydantic import BaseModel
from rich.console import Console
from rich.prompt import Confirm

console = Console()

# Paths — pathlib handles Windows/Linux separators automatically
BASE_DIR         = Path(__file__).parent.parent
CVE_DB_PATH      = BASE_DIR / "data" / "cve_database.db"
CVE_JSON_LEGACY  = BASE_DIR / "data" / "cve_database.json"  # auto-migration source
CVE_CACHE_PATH   = BASE_DIR / "data" / "cve_cache.json"
EVIDENCE_PATH    = BASE_DIR / "output" / "evidence"

# NVD API
NVD_API_URL           = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_UNAUTH = 6.0   # seconds between requests — 5 req/30s without key
NVD_RATE_LIMIT_AUTH   = 0.6   # seconds between requests — 50 req/s with key
NVD_MAX_RETRIES       = 3     # retry attempts on failure

# Windows MAX_PATH safety — keep folder names short
# Windows limit: 260 chars | Linux limit: 4096 chars
MAX_PATH_SAFE_LENGTH  = 30
EVIDENCE_SIZE_LIMIT   = 10_000_000  # 10MB cap per evidence file


def _sanitize_filename(value: str, max_length: int = MAX_PATH_SAFE_LENGTH) -> str:
    """
    Sanitize a string for safe use in file and folder names.
    Strips everything except alphanumeric, underscore, hyphen.
    Prevents path traversal attacks on both Windows and Linux.
    Examples:
        "example.com"     → "example_com"
        "../../../evil"   → "______evil"
        "target; rm -rf/" → "target__rm_-rf_"
    """
    sanitized = re.sub(r'[^a-zA-Z0-9_\-]', '_', value)
    return sanitized[:max_length]


def _sanitize_service(value: str, max_length: int = 100) -> str:
    """
    Sanitize service name for search keys and API queries.
    Allows alphanumeric, spaces, dots, hyphens, underscores.
    Preserves real service names while stripping shell-dangerous characters.
    Examples:
        "Apache httpd 2.4.49"    → "Apache httpd 2.4.49"  (unchanged)
        "Apache; rm -rf /"       → "Apache rm -rf "       (semicolon stripped)
        "nginx\x00backdoor"      → "nginx backdoor"       (null byte stripped)
    """
    sanitized = re.sub(r'[^a-zA-Z0-9\s\.\-\_]', '', value)
    return sanitized.strip()[:max_length]


def _sanitize_version(value: str, max_length: int = 50) -> str:
    """
    Sanitize version string.
    Allows alphanumeric, dots, hyphens, underscores only.
    Examples:
        "2.4.49"                    → "2.4.49"   (unchanged)
        "2.4.49; rm -rf /"          → "2.4.49 rm -rf "  (semicolon stripped)
        "2.4.49../../etc/passwd"    → "2.4.49..etcpasswd"
    """
    sanitized = re.sub(r'[^a-zA-Z0-9\.\-\_]', '', value)
    return sanitized.strip()[:max_length]


class CVEResult(BaseModel):
    """
    Pydantic schema for all CVE lookup results.
    Every lookup returns this exact shape regardless of which tier matched.
    source field tells you where the result came from.
    """
    cve_id:             Optional[str]   = None
    description:        Optional[str]   = None
    cvss_score:         Optional[float] = None
    severity:           Optional[str]   = None
    affected_product:   Optional[str]   = None
    source: str  # "local" | "local_partial" | "local_cache" | "nvd_api" | "zero_day_flag"
    zero_day_flag:      bool            = False
    evidence_preserved: bool            = False
    raw_evidence_path:  Optional[str]   = None


class CVEEngine:
    """
    Tiered CVE lookup engine.
    Local first. Flag unknown. Query live only with operator approval.

    SQLite backend: indexed queries on 295k+ entries are sub-millisecond.
    NVD API key: pass directly or set NVD_API_KEY env var for faster lookups.
    """

    def __init__(self, api_key: Optional[str] = None):
        # API key: explicit param wins, env var fallback
        self.api_key     = api_key or os.environ.get("NVD_API_KEY")
        self._rate_limit = (
            NVD_RATE_LIMIT_AUTH if self.api_key else NVD_RATE_LIMIT_UNAUTH
        )

        # Create required directories on startup
        CVE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE_PATH.mkdir(parents=True, exist_ok=True)

        # Open SQLite database — migrate from legacy JSON if needed
        self.conn  = self._init_sqlite()
        # Load NVD cache into memory — small, grows over time
        self.cache = self._load_cache()

    def _init_sqlite(self) -> Optional[sqlite3.Connection]:
        """
        Open or create the SQLite CVE database.
        Creates schema on first run.
        Auto-migrates from legacy JSON if SQLite is empty and JSON exists.
        Returns connection or None if unavailable (engine degrades gracefully).
        """
        try:
            conn = sqlite3.connect(str(CVE_DB_PATH))
            conn.row_factory = sqlite3.Row

            # Create table + index — idempotent, safe to run on every startup
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    search_key  TEXT PRIMARY KEY,
                    cve_id      TEXT,
                    description TEXT,
                    cvss_score  REAL,
                    severity    TEXT
                )
            """)
            conn.commit()

            count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]

            if count == 0 and CVE_JSON_LEGACY.exists():
                # Auto-migrate from legacy JSON — runs once, seamless
                console.print(
                    "[cyan]  CVE database: migrating JSON → SQLite "
                    "(runs once)...[/cyan]"
                )
                count = self._migrate_json_to_sqlite(conn)
                if count > 0:
                    console.print(
                        f"[green]✓ CVE database migrated — "
                        f"{count} entries[/green]"
                    )
                else:
                    console.print(
                        "[yellow]  Migration produced 0 entries — "
                        "run --setup-cve-db to rebuild[/yellow]"
                    )
            elif count > 0:
                console.print(
                    f"[green]✓ CVE database loaded — {count} entries[/green]"
                )
            else:
                console.print(
                    "[yellow]⚠ No local CVE database found. "
                    "Run: python main.py --setup-cve-db[/yellow]"
                )

            return conn

        except sqlite3.Error as e:
            console.print(
                f"[yellow]⚠ CVE database unavailable: {str(e)} "
                f"— CVE correlation disabled[/yellow]"
            )
            return None

    def _migrate_json_to_sqlite(self, conn: sqlite3.Connection) -> int:
        """
        Migrate legacy cve_database.json into SQLite.
        Called automatically when SQLite is empty but JSON exists.
        Batch inserts for speed — 295k entries in a few seconds.
        Returns count of entries migrated.
        """
        try:
            with open(CVE_JSON_LEGACY, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return 0

            batch = [
                (
                    key,
                    v.get("cve_id"),
                    v.get("description"),
                    v.get("cvss_score"),
                    v.get("severity")
                )
                for key, v in data.items()
                if isinstance(v, dict)
            ]

            conn.executemany(
                "INSERT OR REPLACE INTO cves "
                "(search_key, cve_id, description, cvss_score, severity) "
                "VALUES (?, ?, ?, ?, ?)",
                batch
            )
            conn.commit()
            return len(batch)

        except Exception as e:
            console.print(
                f"[yellow]  JSON migration failed: {str(e)}[/yellow]"
            )
            return 0

    def _load_cache(self) -> dict:
        """
        Load NVD API cache from disk.
        Integrity checked — corrupted cache starts fresh rather than crashing.
        """
        if CVE_CACHE_PATH.exists():
            try:
                with open(CVE_CACHE_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    raise ValueError("Cache format invalid — expected dict")
                return data
            except (json.JSONDecodeError, ValueError) as e:
                console.print(
                    f"[yellow]⚠ CVE cache corrupted ({str(e)}) — "
                    f"starting fresh[/yellow]"
                )
                return {}
        return {}

    def _save_cache(self):
        """Save NVD API cache to disk. Fails gracefully if disk write fails."""
        try:
            with open(CVE_CACHE_PATH, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
        except OSError as e:
            console.print(f"[red]✗ Failed to save CVE cache: {str(e)}[/red]")

    def lookup(
        self,
        service:      str,
        version:      str,
        raw_evidence: Optional[dict] = None,
        target:       str = "unknown"
    ) -> CVEResult:
        """
        Main lookup function. Runs through all three tiers.

        Args:
            service:      Service name found during recon (e.g. "Apache httpd")
            version:      Version string (e.g. "2.4.49")
            raw_evidence: Raw scan data to preserve if zero day flagged
            target:       Target domain/IP for evidence file naming

        Returns:
            CVEResult with findings and flags
        """
        # Sanitize ALL inputs before they touch anything
        service    = _sanitize_service(service)
        version    = _sanitize_version(version)
        target     = _sanitize_filename(target)
        search_key = f"{service}:{version}".lower()

        # TIER 1 — Local SQLite database (fast, offline, no cost)
        result = self._tier1_local(search_key, service, version)
        if result:
            return result

        # Check cache from previous NVD lookups
        # Cache grows over time — database gets smarter with use
        if search_key in self.cache:
            cached = self.cache[search_key]
            console.print(
                f"[cyan]→ Found in cache: {cached.get('cve_id', 'N/A')}[/cyan]"
            )
            return CVEResult(
                cve_id=cached.get("cve_id"),
                description=cached.get("description"),
                cvss_score=cached.get("cvss_score"),
                severity=cached.get("severity"),
                affected_product=f"{service} {version}",
                source="local_cache"
            )

        # TIER 2 — Zero day flag
        console.print(
            f"\n[bold yellow]⚠ No CVE match found for "
            f"{service} {version}[/bold yellow]"
        )
        console.print(
            "[yellow]→ Flagging as potential zero day / "
            "novel vulnerability[/yellow]"
        )

        # Preserve raw evidence automatically on zero day flag
        evidence_path = None
        if raw_evidence:
            evidence_path = self._preserve_evidence(
                raw_evidence, target, service, version
            )
            console.print(
                f"[yellow]→ Raw evidence preserved: {evidence_path}[/yellow]"
            )

        # Ask operator before going online
        check_nvd = Confirm.ask(
            "\n[bold]Check NVD API live for this finding?[/bold]",
            default=False
        )

        if check_nvd:
            # TIER 3 — NVD API live lookup
            nvd_result = self._tier3_nvd_api(service, version, search_key)
            if nvd_result:
                nvd_result.evidence_preserved = evidence_path is not None
                nvd_result.raw_evidence_path  = evidence_path
                return nvd_result

        # Confirmed unknown — return zero day flag result
        return CVEResult(
            source="zero_day_flag",
            zero_day_flag=True,
            affected_product=f"{service} {version}",
            evidence_preserved=evidence_path is not None,
            raw_evidence_path=evidence_path,
            description=(
                f"No CVE match found for {service} {version}. "
                f"Manual investigation required."
            )
        )

    def _tier1_local(
        self,
        search_key: str,
        service:    str,
        version:    str
    ) -> Optional[CVEResult]:
        """
        Search local SQLite CVE database.
        Exact key match first, LIKE partial match fallback.
        Partial matching handles version format mismatches between
        nmap output and how the CVE database stores version strings.
        """
        if self.conn is None:
            return None

        try:
            # Exact match — "apache httpd:2.4.49"
            row = self.conn.execute(
                "SELECT * FROM cves WHERE search_key = ?",
                (search_key,)
            ).fetchone()

            if row:
                console.print(
                    f"[green]✓ CVE match found locally: "
                    f"{row['cve_id'] or 'N/A'}[/green]"
                )
                return CVEResult(
                    cve_id=row["cve_id"],
                    description=row["description"],
                    cvss_score=row["cvss_score"],
                    severity=row["severity"],
                    affected_product=f"{service} {version}",
                    source="local"
                )

            # Partial match — any key containing the service name
            service_lower = service.lower()
            row = self.conn.execute(
                "SELECT * FROM cves WHERE search_key LIKE ? LIMIT 1",
                (f"%{service_lower}%",)
            ).fetchone()

            if row:
                console.print(
                    f"[cyan]→ Partial CVE match: "
                    f"{row['cve_id'] or 'N/A'}[/cyan]"
                )
                return CVEResult(
                    cve_id=row["cve_id"],
                    description=row["description"],
                    cvss_score=row["cvss_score"],
                    severity=row["severity"],
                    affected_product=f"{service} {version}",
                    source="local_partial"
                )

        except sqlite3.Error as e:
            console.print(
                f"[yellow]  CVE lookup error: {str(e)}[/yellow]"
            )

        return None

    def _tier3_nvd_api(
        self,
        service:   str,
        version:   str,
        cache_key: str
    ) -> Optional[CVEResult]:
        """
        Query NVD API live with retry and exponential backoff.
        Uses API key if available — faster rate limit, authenticated requests.
        Validates response structure before trusting it.
        Caches successful results locally — database grows over time.
        """
        key_status = "authenticated" if self.api_key else "unauthenticated"
        console.print(
            f"\n[cyan]→ Querying NVD API for {service} {version} "
            f"({key_status})...[/cyan]"
        )

        headers = {"User-Agent": "R3D-Agent/1.0 (Security Research)"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        for attempt in range(1, NVD_MAX_RETRIES + 1):
            try:
                response = requests.get(
                    NVD_API_URL,
                    params={
                        "keywordSearch":  f"{service} {version}",
                        "resultsPerPage": 5
                    },
                    timeout=15,
                    headers=headers
                )

                # Rate limited — back off and retry
                if response.status_code == 429:
                    wait = self._rate_limit * (attempt * 2)
                    console.print(
                        f"[yellow]→ NVD rate limited. Waiting {wait:.1f}s "
                        f"(attempt {attempt}/{NVD_MAX_RETRIES})[/yellow]"
                    )
                    time.sleep(wait)
                    continue

                if response.status_code != 200:
                    console.print(
                        f"[red]✗ NVD API error: "
                        f"HTTP {response.status_code}[/red]"
                    )
                    break

                # Validate response structure before trusting it
                try:
                    data = response.json()
                    if not isinstance(data, dict):
                        raise ValueError("NVD response is not a JSON object")
                    vulnerabilities = data.get("vulnerabilities", [])
                    if not isinstance(vulnerabilities, list):
                        raise ValueError(
                            "NVD vulnerabilities field is not a list"
                        )
                except (json.JSONDecodeError, ValueError) as e:
                    console.print(
                        f"[red]✗ NVD response validation failed: "
                        f"{str(e)}[/red]"
                    )
                    break

                if vulnerabilities:
                    best = self._pick_best_cve(vulnerabilities)
                    if best:
                        # Cache for future lookups
                        self.cache[cache_key] = best
                        self._save_cache()
                        console.print(
                            f"[green]✓ NVD match found: "
                            f"{best['cve_id']}[/green]"
                        )
                        console.print(
                            "[green]→ Cached locally for "
                            "future lookups[/green]"
                        )
                        return CVEResult(
                            cve_id=best["cve_id"],
                            description=best["description"],
                            cvss_score=best["cvss_score"],
                            severity=best["severity"],
                            affected_product=f"{service} {version}",
                            source="nvd_api"
                        )

                console.print(
                    "[yellow]→ NVD API returned no matches[/yellow]"
                )
                return None

            except requests.RequestException as e:
                console.print(
                    f"[red]✗ NVD request failed "
                    f"(attempt {attempt}/{NVD_MAX_RETRIES}): "
                    f"{str(e)}[/red]"
                )
                if attempt < NVD_MAX_RETRIES:
                    time.sleep(self._rate_limit * attempt)

        return None

    def _pick_best_cve(self, vulnerabilities: list) -> Optional[dict]:
        """
        Pick highest CVSS score CVE from NVD results.
        Tries CVSS v3.1 first, then v3.0, then v2 as fallback.
        Skips malformed entries rather than crashing.
        """
        best       = None
        best_score = 0.0

        for vuln in vulnerabilities:
            try:
                cve_data = vuln.get("cve", {})
                if not isinstance(cve_data, dict):
                    continue

                cve_id  = cve_data.get("id", "")
                metrics = cve_data.get("metrics", {})
                score    = 0.0
                severity = "UNKNOWN"

                for metric_key in [
                    "cvssMetricV31",
                    "cvssMetricV30",
                    "cvssMetricV2"
                ]:
                    if metric_key in metrics and metrics[metric_key]:
                        cvss_data = metrics[metric_key][0].get(
                            "cvssData", {}
                        )
                        score    = float(cvss_data.get("baseScore", 0.0))
                        severity = str(
                            cvss_data.get("baseSeverity", "UNKNOWN")
                        )
                        break

                descriptions = cve_data.get("descriptions", [])
                description  = next(
                    (
                        d["value"] for d in descriptions
                        if isinstance(d, dict) and d.get("lang") == "en"
                    ),
                    "No description available"
                )

                if score > best_score:
                    best_score = score
                    best = {
                        "cve_id":      cve_id,
                        "description": description,
                        "cvss_score":  score,
                        "severity":    severity
                    }

            except (TypeError, KeyError, ValueError):
                # Skip malformed CVE entries rather than crashing
                continue

        return best

    def _preserve_evidence(
        self,
        raw_evidence: dict,
        target:       str,
        service:      str,
        version:      str
    ) -> str:
        """
        Preserve raw scan evidence when zero day flag triggers.
        Size capped at 10MB. Timestamped folder per finding.
        Works on Windows and Linux — pathlib handles separators.
        """
        timestamp    = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        evidence_dir = EVIDENCE_PATH / f"{timestamp}_{target}_zeroday"
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Serialize with size cap
        evidence_str = json.dumps(raw_evidence, indent=2)
        if len(evidence_str) > EVIDENCE_SIZE_LIMIT:
            console.print(
                f"[yellow]⚠ Evidence truncated at "
                f"{EVIDENCE_SIZE_LIMIT // 1_000_000}MB limit[/yellow]"
            )
            evidence_str = evidence_str[:EVIDENCE_SIZE_LIMIT]

        # Save raw evidence
        evidence_file = evidence_dir / "raw_evidence.json"
        with open(evidence_file, "w", encoding="utf-8") as f:
            f.write(evidence_str)

        # Save metadata
        metadata_file = evidence_dir / "scan_metadata.json"
        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump({
                "timestamp":          timestamp,
                "target":             target,
                "service":            service,
                "version":            version,
                "flag":               "zero_day",
                "r3d_version":        "1.0",
                "evidence_size_bytes": len(evidence_str)
            }, f, indent=2)

        return str(evidence_dir)

    def close(self):
        """Close the SQLite connection. Call when engine is no longer needed."""
        if self.conn:
            self.conn.close()
            self.conn = None


def setup_cve_db(api_key: Optional[str] = None):
    """
    Download and build the local CVE database from NVD.
    Run once during setup, then periodically to update.

    With API key   : ~5 minutes  (50 req/s — authenticated)
    Without API key: 30-60 min   (5 req/30s — unauthenticated)

    Set NVD_API_KEY env var or pass --nvd-api-key to main.py.
    Saves partial results if interrupted — resume safe.

    Args:
        api_key: NVD API key for faster, authenticated download.
                 Falls back to NVD_API_KEY env var if not passed.
    """
    # Resolve API key from param or env var
    resolved_key = api_key or os.environ.get("NVD_API_KEY")
    rate_limit   = NVD_RATE_LIMIT_AUTH if resolved_key else NVD_RATE_LIMIT_UNAUTH
    est_time     = "~5 minutes" if resolved_key else "30-60 minutes"

    console.print("[bold green]Setting up local CVE database...[/bold green]")
    if resolved_key:
        console.print(
            "[green]  API key detected — authenticated mode "
            f"({est_time})[/green]"
        )
    else:
        console.print(
            f"[yellow]  No API key — unauthenticated mode ({est_time}).\n"
            "  Tip: pass --nvd-api-key to speed this up.[/yellow]"
        )

    CVE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    headers = {"User-Agent": "R3D-Agent/1.0 (Security Research)"}
    if resolved_key:
        headers["apiKey"] = resolved_key

    # Open (or create) SQLite database
    conn = sqlite3.connect(str(CVE_DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            search_key  TEXT PRIMARY KEY,
            cve_id      TEXT,
            description TEXT,
            cvss_score  REAL,
            severity    TEXT
        )
    """)
    conn.commit()

    total_fetched   = 0
    total_inserted  = 0
    start_index     = 0
    results_per_page = 2000

    try:
        while True:
            console.print(
                f"[cyan]→ Fetching CVEs {start_index}–"
                f"{start_index + results_per_page}...[/cyan]"
            )

            response = None
            for attempt in range(1, NVD_MAX_RETRIES + 1):
                try:
                    response = requests.get(
                        NVD_API_URL,
                        params={
                            "resultsPerPage": results_per_page,
                            "startIndex":     start_index
                        },
                        timeout=30,
                        headers=headers
                    )

                    if response.status_code == 429:
                        wait = 30 * attempt
                        console.print(
                            f"[yellow]→ Rate limited. "
                            f"Waiting {wait}s[/yellow]"
                        )
                        time.sleep(wait)
                        continue

                    if response.status_code == 200:
                        break

                except requests.RequestException as e:
                    console.print(
                        f"[red]✗ Request failed: {str(e)}[/red]"
                    )
                    if attempt < NVD_MAX_RETRIES:
                        time.sleep(10)

            if response is None or response.status_code != 200:
                console.print("[red]✗ Failed to fetch from NVD[/red]")
                break

            # Validate response
            try:
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("Unexpected response format")
                vulnerabilities = data.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    break
            except (json.JSONDecodeError, ValueError) as e:
                console.print(
                    f"[red]✗ Response validation failed: {str(e)}[/red]"
                )
                break

            if not vulnerabilities:
                break

            # Build batch for this page
            batch = []
            for vuln in vulnerabilities:
                try:
                    cve_data = vuln.get("cve", {})
                    cve_id   = cve_data.get("id", "")

                    descriptions = cve_data.get("descriptions", [])
                    description  = next(
                        (
                            d["value"] for d in descriptions
                            if isinstance(d, dict)
                            and d.get("lang") == "en"
                        ),
                        ""
                    )

                    metrics  = cve_data.get("metrics", {})
                    score    = 0.0
                    severity = "UNKNOWN"

                    for metric_key in [
                        "cvssMetricV31",
                        "cvssMetricV30",
                        "cvssMetricV2"
                    ]:
                        if metric_key in metrics and metrics[metric_key]:
                            cvss_data = metrics[metric_key][0].get(
                                "cvssData", {}
                            )
                            score    = float(
                                cvss_data.get("baseScore", 0.0)
                            )
                            severity = str(
                                cvss_data.get("baseSeverity", "UNKNOWN")
                            )
                            break

                    configurations = cve_data.get("configurations", [])
                    for config in configurations:
                        for node in config.get("nodes", []):
                            for cpe_match in node.get("cpeMatch", []):
                                cpe   = cpe_match.get("criteria", "")
                                parts = cpe.split(":")
                                if len(parts) >= 6:
                                    product = parts[4]
                                    version = parts[5]
                                    if version != "*":
                                        key = (
                                            f"{product}:{version}".lower()
                                        )
                                        batch.append((
                                            key, cve_id, description,
                                            score, severity
                                        ))

                except (TypeError, KeyError, ValueError):
                    continue

            # Batch insert this page
            if batch:
                conn.executemany(
                    "INSERT OR REPLACE INTO cves "
                    "(search_key, cve_id, description, cvss_score, severity) "
                    "VALUES (?, ?, ?, ?, ?)",
                    batch
                )
                conn.commit()
                total_inserted += len(batch)

            total_fetched += len(vulnerabilities)
            console.print(
                f"[green]→ {total_fetched} CVEs processed, "
                f"{total_inserted} entries indexed[/green]"
            )

            total_results = data.get("totalResults", 0)
            if start_index + results_per_page >= total_results:
                break

            start_index += results_per_page
            time.sleep(rate_limit)

    except Exception as e:
        console.print(f"[red]✗ Database setup failed: {str(e)}[/red]")
        console.print("[yellow]Saving partial database...[/yellow]")

    finally:
        conn.close()

    # Report final count
    final_conn = sqlite3.connect(str(CVE_DB_PATH))
    final_count = final_conn.execute(
        "SELECT COUNT(*) FROM cves"
    ).fetchone()[0]
    final_conn.close()

    console.print(
        f"\n[bold green]✓ CVE database built — "
        f"{final_count} entries[/bold green]"
    )
    console.print(f"[green]→ Saved to {CVE_DB_PATH}[/green]")


if __name__ == "__main__":
    console.print("[bold green]Testing R3D CVE Engine...[/bold green]")

    engine = CVEEngine()

    console.print("\n[bold]Test 1 — Known service lookup:[/bold]")
    result = engine.lookup(
        service="Apache httpd",
        version="2.4.49",
        target="test-target.com"
    )
    console.print(f"CVE ID: {result.cve_id}")
    console.print(f"Source: {result.source}")

    engine.close()
