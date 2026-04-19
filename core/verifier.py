"""
R3D Agent -- Verifier Module
The quality gate that sits between raw LLM output and the final reports.
If the LLM hallucinated a CVE ID, inflated a severity, or produced two
near-identical findings, this catches it before it reaches the PDF.

Only reviews LLM attack findings — OSINT, traditional recon, and GRC
output is deterministic (Python-authoritative) and passes straight through.
That's why you'll see "11/11 passed — deterministic findings" on a run
with no AI surfaces. That's correct behavior, not a broken gate.

What gets checked (LLM findings only):
    1. CVE ID validation   -- direct NVD API lookup by ID, confirms it exists
    2. Severity sanity     -- anything below 3.0 gets cut, 3-5 gets flagged
    3. Evidence check      -- confirms the conversation log file was saved
    4. Semantic dedup      -- difflib similarity check, 0.85 threshold

Key design decisions:
    Fail open on CVE       -- if NVD is unreachable, finding survives
    Unverified bucket      -- removed findings go to telemetry, not deleted
    difflib for dedup      -- no Ollama dependency on the verifier path
    _copy_finding()        -- immutable copy before modifying, handles
                             both Pydantic v1 (.dict()) and v2 (.model_dump())
    aggregated.target      -- used over findings[0].target to handle
                             edge case where findings list is empty

Compatibility: Windows 10/11, Ubuntu, Kali Linux
"""

import json
import requests
from difflib import SequenceMatcher
from datetime import datetime
from pathlib import Path
from typing import Optional
from rich.console import Console

from core.findings import Finding, FindingsAggregator, AggregatedFindings
from core.llm_client import query_llm, LLMResponse

console = Console()

# Paths
BASE_DIR    = Path(__file__).parent.parent
OUTPUT_DIR  = BASE_DIR / "output"
LOGS_DIR    = OUTPUT_DIR / "attack_logs"
REPORTS_DIR = OUTPUT_DIR / "reports"

# Verification thresholds
SEVERITY_REMOVE_THRESHOLD  = 3.0
SEVERITY_FLAG_THRESHOLD    = 5.0
DEDUP_SIMILARITY_THRESHOLD = 0.85

# NVD API -- direct CVE ID lookup
NVD_CVE_URL      = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
NVD_REQUEST_TIMEOUT = 10


# ------------------------------------------------------------------ #
# PYDANTIC COMPATIBILITY HELPERS
# ------------------------------------------------------------------ #

def _copy_finding(finding: Finding, updates: dict) -> Finding:
    """
    Create updated Finding copy.
    Fix 3: handles pydantic v1 (.copy()) and v2 (.model_copy()).
    Finding is immutable -- never mutate directly.
    """
    if hasattr(finding, "model_copy"):
        return finding.model_copy(update=updates)
    elif hasattr(finding, "copy"):
        return finding.copy(update=updates)
    else:
        try:
            data = _finding_to_dict(finding)
            data.update(updates)
            return Finding(**data)
        except Exception:
            return finding


def _finding_to_dict(finding: Finding) -> dict:
    """
    Convert Finding to dict safely.
    Fix 2: handles pydantic v1 (.dict()) and v2 (.model_dump()).
    """
    if hasattr(finding, "model_dump"):
        return finding.model_dump()
    elif hasattr(finding, "dict"):
        return finding.dict()
    else:
        return {
            k: v for k, v in finding.__dict__.items()
            if not k.startswith("_")
        }


# ------------------------------------------------------------------ #
# VERIFIER
# ------------------------------------------------------------------ #

class Verifier:
    """
    Quality gate for LLM-generated findings.

    Only verifies findings from source_module='llm_attack'.
    All other findings pass through unchanged.

    Fail open on CVE: if NVD API unavailable keep CVE as-is.
    Only strips CVE when NVD actively returns no results.

    Uses _copy_finding() for all Finding updates.
    Rebuilds FindingsAggregator after verification.
    """

    def __init__(self):
        self.nvd_available     = True
        self.ollama_available  = True
        self.stats = {
            "total_reviewed":      0,
            "passed":              0,
            "flagged_uncertain":   0,
            "removed":             0,
            "cve_stripped":        0,
            "duplicates_removed":  0,
            "severity_downgraded": 0,
        }
        self.unverified_findings: list[dict] = []

    # ------------------------------------------------------------------ #
    # CVE VALIDATION
    # ------------------------------------------------------------------ #

    def _validate_cve(self, finding: Finding) -> Finding:
        """
        Validate CVE ID via direct NVD API call.
        Fix 1: direct NVD API -- cve_engine has no cve_override param.

        Fail open:
        - NVD unavailable/timeout -> keep CVE as-is
        - 200 with data           -> confirmed, keep
        - 200 with no data        -> not found, strip
        - 404                     -> not found, strip
        - any other status        -> fail open, keep
        """
        if not finding.cve_id:
            return finding

        if not self.nvd_available:
            return finding

        cve_id = finding.cve_id.strip()

        try:
            url  = NVD_CVE_URL.format(cve_id=cve_id)
            resp = requests.get(
                url,
                timeout=NVD_REQUEST_TIMEOUT,
                headers={"User-Agent": "R3D-Verifier/1.0"}
            )

            if resp.status_code == 200:
                try:
                    data          = resp.json()
                    total_results = data.get("totalResults", 0)
                    if total_results > 0:
                        console.print(
                            f"[dim]    CVE confirmed: {cve_id}[/dim]"
                        )
                        return finding
                    else:
                        return self._strip_cve(
                            finding, "not found in NVD"
                        )
                except Exception:
                    return finding

            elif resp.status_code == 404:
                return self._strip_cve(finding, "404 from NVD")

            else:
                return finding

        except requests.Timeout:
            console.print(
                "[yellow]  Verifier: NVD timeout -- "
                "CVE validation skipped for session[/yellow]"
            )
            self.nvd_available = False
            return finding

        except requests.ConnectionError:
            console.print(
                "[yellow]  Verifier: NVD unreachable -- "
                "CVE validation skipped[/yellow]"
            )
            self.nvd_available = False
            return finding

        except Exception:
            return finding

    def _strip_cve(self, finding: Finding, reason: str) -> Finding:
        """Strip CVE ID and downgrade severity. Called only on NVD confirmation."""
        console.print(
            f"[yellow]    CVE stripped: "
            f"{finding.cve_id} ({reason})[/yellow]"
        )
        self.stats["cve_stripped"] += 1
        new_score = max(
            finding.severity_score - 1.5,
            SEVERITY_FLAG_THRESHOLD
        )
        return _copy_finding(finding, {
            "cve_id":         None,
            "cvss_score":     None,
            "severity_score": new_score,
            "description": (
                f"{finding.description}\n"
                f"[VERIFIER: CVE {finding.cve_id} "
                f"not confirmed by NVD -- stripped]"
            )
        })

    # ------------------------------------------------------------------ #
    # SEVERITY SANITY CHECK
    # ------------------------------------------------------------------ #

    def _check_severity(
        self, finding: Finding
    ) -> tuple[Optional[Finding], str]:
        """
        Sanity check severity score.
        Below SEVERITY_REMOVE_THRESHOLD -> remove.
        Below SEVERITY_FLAG_THRESHOLD   -> flag uncertain.
        """
        score = finding.severity_score

        if score < SEVERITY_REMOVE_THRESHOLD:
            return None, "removed_low_severity"

        if score < SEVERITY_FLAG_THRESHOLD:
            flagged = _copy_finding(finding, {
                "description": (
                    f"{finding.description}\n"
                    f"[VERIFIER: Low confidence "
                    f"({score:.1f}) -- flagged uncertain]"
                )
            })
            return flagged, "flagged_uncertain"

        return finding, "passed"

    # ------------------------------------------------------------------ #
    # EVIDENCE CHECK
    # ------------------------------------------------------------------ #

    def _check_evidence(self, finding: Finding) -> Finding:
        """
        Check evidence file exists on disk.
        Never removes finding -- only adds note if missing.
        """
        if not finding.raw_evidence_path:
            return finding

        try:
            if not Path(finding.raw_evidence_path).exists():
                return _copy_finding(finding, {
                    "description": (
                        f"{finding.description}\n"
                        f"[VERIFIER: Evidence file not found "
                        f"-- manual review recommended]"
                    )
                })
        except Exception:
            pass

        return finding

    # ------------------------------------------------------------------ #
    # SEMANTIC DEDUP
    # ------------------------------------------------------------------ #

    def _is_duplicate(
        self, finding: Finding, verified: list[Finding]
    ) -> bool:
        """
        Check if finding is a near-duplicate within same finding_type.
        Primary: Ollama semantic check.
        Fallback: difflib SequenceMatcher.
        Skip entirely if both unavailable.
        """
        if not verified:
            return False

        same_type = [
            f for f in verified
            if f.finding_type == finding.finding_type
        ]
        if not same_type:
            return False

        for existing in same_type:
            if self.ollama_available:
                try:
                    if self._ollama_similarity(
                        finding.title, existing.title
                    ):
                        return True
                except Exception:
                    self.ollama_available = False

            title_ratio = SequenceMatcher(
                None,
                finding.title.lower(),
                existing.title.lower()
            ).ratio()

            desc_ratio = SequenceMatcher(
                None,
                finding.description[:200].lower(),
                existing.description[:200].lower()
            ).ratio()

            if (
                title_ratio > DEDUP_SIMILARITY_THRESHOLD and
                desc_ratio  > DEDUP_SIMILARITY_THRESHOLD
            ):
                return True

        return False

    def _ollama_similarity(
        self, title_a: str, title_b: str
    ) -> bool:
        """
        Ask Ollama if two findings describe the same issue.
        Raises on failure -- caller catches and disables Ollama.
        """
        result: LLMResponse = query_llm(
            prompt=(
                f"Are these two security findings describing "
                f"the same vulnerability?\n\n"
                f"Finding A: {title_a}\n"
                f"Finding B: {title_b}\n\n"
                f"Respond in JSON only:\n"
                f"{{\"duplicate\": true/false, "
                f"\"reasoning\": \"one sentence\"}}"
            ),
            system_prompt=(
                "You are a precise security analyst. "
                "Respond only in valid JSON."
            ),
            expect_json=True
        )

        if result and result.content:
            # query_llm returns content as a string even with expect_json=True.
            # Parse it here so .get() works correctly.
            content = result.content
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except (json.JSONDecodeError, ValueError):
                    return False
            if isinstance(content, dict):
                return bool(content.get("duplicate", False))

        return False

    # ------------------------------------------------------------------ #
    # MAIN VERIFY
    # ------------------------------------------------------------------ #

    def verify(
        self, aggregated: AggregatedFindings
    ) -> AggregatedFindings:
        """
        Verify all findings. Non-LLM pass through unchanged.
        LLM findings: CVE -> severity -> evidence -> dedup.

        Fix 4: uses aggregated.target not findings[0].target.
        Returns new AggregatedFindings with recalculated counts.
        """
        console.print(
            f"\n[cyan]  Verifier: reviewing "
            f"{aggregated.total_findings} findings...[/cyan]"
        )

        verified_findings: list[Finding] = []
        deterministic_count = 0

        for finding in aggregated.findings:
            # Non-LLM findings pass through unchanged — deterministic
            # sources (port scan, NVD, OSINT) don't need hallucination
            # checks. Track count for transparent summary output.
            if finding.source_module != "llm_attack":
                verified_findings.append(finding)
                deterministic_count += 1
                continue

            self.stats["total_reviewed"] += 1
            current = finding

            # Step 1 -- CVE validation
            current = self._validate_cve(current)

            # Step 2 -- Severity check
            current, disposition = self._check_severity(current)

            if current is None:
                self.stats["removed"] += 1
                self.unverified_findings.append({
                    "reason":    "low_severity",
                    "finding":   _finding_to_dict(finding),
                    "timestamp": datetime.now().isoformat()
                })
                console.print(
                    f"[dim]    Removed (low severity): "
                    f"{finding.title[:50]}[/dim]"
                )
                continue

            if disposition == "flagged_uncertain":
                self.stats["flagged_uncertain"] += 1
                console.print(
                    f"[yellow]    Flagged: "
                    f"{current.title[:50]}[/yellow]"
                )

            # Step 3 -- Evidence check
            current = self._check_evidence(current)

            # Step 4 -- Semantic dedup
            if self._is_duplicate(current, verified_findings):
                self.stats["duplicates_removed"] += 1
                self.unverified_findings.append({
                    "reason":    "duplicate",
                    "finding":   _finding_to_dict(finding),
                    "timestamp": datetime.now().isoformat()
                })
                console.print(
                    f"[dim]    Duplicate: "
                    f"{current.title[:50]}[/dim]"
                )
                continue

            self.stats["passed"] += 1
            verified_findings.append(current)

        # Fix 4: use aggregated.target directly
        new_aggregator = FindingsAggregator(
            target=aggregated.target
        )
        for f in verified_findings:
            new_aggregator.add_finding(f)

        new_aggregated = new_aggregator.aggregate()

        self._save_verification_report(
            aggregated.total_findings,
            new_aggregated.total_findings
        )
        self._print_summary(
            aggregated.total_findings,
            new_aggregated.total_findings,
            deterministic_count
        )

        return new_aggregated

    # ------------------------------------------------------------------ #
    # REPORTING
    # ------------------------------------------------------------------ #

    def _save_verification_report(
        self, total_before: int, total_after: int
    ):
        """Save verification report to telemetry JSON. Never raises."""
        try:
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            timestamp   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            report_path = (
                REPORTS_DIR /
                f"{timestamp}_verification_report.json"
            )
            report = {
                "timestamp":           datetime.now().isoformat(),
                "findings_before":     total_before,
                "findings_after":      total_after,
                "findings_removed":    total_before - total_after,
                "stats":               self.stats,
                "unverified_findings": self.unverified_findings
            }
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            console.print(
                f"[dim]  Verification report: {report_path}[/dim]"
            )
        except Exception as e:
            console.print(
                f"[yellow]  Verification report failed: {e}[/yellow]"
            )

    def _print_summary(
        self,
        total_before: int,
        total_after: int,
        deterministic_count: int = 0
    ):
        """Print clean verification summary."""
        console.print("\n[green]  Verifier complete[/green]")
        if deterministic_count > 0:
            console.print(
                f"[dim]    Deterministic findings (port scan / OSINT / NVD): "
                f"{deterministic_count} — passed through, no LLM review needed[/dim]"
            )
        if self.stats['total_reviewed'] == 0:
            console.print(
                "[dim]    LLM findings reviewed: 0 "
                "(no AI surfaces found this engagement)[/dim]"
            )
        else:
            console.print(f"[dim]    LLM findings reviewed: {self.stats['total_reviewed']}[/dim]")
            console.print(f"[dim]    Passed:     {self.stats['passed']}[/dim]")
            console.print(f"[dim]    Flagged:    {self.stats['flagged_uncertain']}[/dim]")
            console.print(f"[dim]    Removed:    {self.stats['removed']}[/dim]")
            console.print(f"[dim]    Duplicates: {self.stats['duplicates_removed']}[/dim]")
            console.print(f"[dim]    CVE stripped: {self.stats['cve_stripped']}[/dim]")
        console.print(f"[dim]    Total: {total_before} -> {total_after} findings[/dim]")


# ------------------------------------------------------------------ #
# TEST
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    console.print(
        "[bold green]R3D Verifier -- Module Load Test[/bold green]\n"
    )
    console.print(
        "[yellow]NOTE: CVE validation makes live NVD API calls. "
        "Requires internet.[/yellow]\n"
    )

    aggregator = FindingsAggregator(target="example.com")

    aggregator.add_finding(Finding(
        title="Prompt injection confirmed",
        description="Direct injection succeeded. Confidence: 85%",
        finding_type="prompt_injection",
        source_module="llm_attack",
        target="example.com",
        severity_score=8.0
    ))

    aggregator.add_finding(Finding(
        title="Possible minor context shift",
        description="Very minor behavioral change. Confidence: 20%",
        finding_type="context_manipulation",
        source_module="llm_attack",
        target="example.com",
        severity_score=2.0
    ))

    aggregator.add_finding(Finding(
        title="Port 22 SSH exposed",
        description="SSH on default port",
        finding_type="exposed_port",
        source_module="traditional_recon",
        target="example.com",
        severity_score=7.5
    ))

    aggregated = aggregator.aggregate()
    console.print(f"Before: {aggregated.total_findings} findings\n")

    verifier  = Verifier()
    verified  = verifier.verify(aggregated)

    console.print(f"\nAfter: {verified.total_findings} findings")
    console.print("[green]Module loaded successfully.[/green]")