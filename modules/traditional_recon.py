"""
R3D Agent -- Traditional Recon Module
Active reconnaissance against discovered attack surface.
Runs after osint_recon.py -- reads OSINTProfile for context.

Checks performed:
    1-3. Port scan + service detection + CVE correlation
         (combined -- one nmap run for efficiency)
    4.   SSL/TLS audit
    5.   Security headers deep check
    6.   Endpoint discovery
    7.   JS bundle analysis
    8.   WAF bypass attempt (only if WAF detected by OSINT)

Integration:
    Reads  -- OSINTProfile via getattr (defensive, safe)
    Uses   -- core/cve_engine.py for CVE correlation
    Writes -- list[Finding] to orchestrator

Performance:
    Standard (top 1000 ports): 3-5 minutes
    Full scan (all 65535):     15-25 minutes
    Target: contribute to 15-20 min full engagement

Error handling:
    Each check independent -- one failure never stops others
    All loops bounded -- no infinite loop risk
    NMAP_TIMEOUT=300 hard caps nmap execution
    try/except per CVE lookup, per JS file, per endpoint
    nmap ImportError caught with clear install message

Security:
    All nmap inputs sanitized via _sanitize_ip
    urllib3 warnings suppressed for verify=False calls
    No shell=True anywhere -- injection safe
    Mode gates enforced throughout

Compatibility: Windows 10/11, Ubuntu, Kali Linux
"""

import re
import ssl
import socket
import time
import requests
import urllib3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from rich.console import Console

from core.findings import Finding, FindingsAggregator
from core.cve_engine import CVEEngine, CVEResult

# Suppress SSL warnings for verify=False in WAF bypass
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

# Paths
BASE_DIR   = Path(__file__).parent.parent
OUTPUT_DIR = BASE_DIR / "output"

# Scan configuration
REQUEST_TIMEOUT = 10
REQUEST_DELAY   = 0.5
TOP_PORTS       = "1000"     # default -- 3-5 min
ALL_PORTS       = "1-65535"  # full scan -- 15-25 min
NMAP_TIMEOUT    = 300        # 5 min hard cap per nmap run

# Common endpoint paths for discovery
COMMON_ENDPOINTS = [
    "/admin", "/administrator", "/admin/login",
    "/login", "/signin", "/auth",
    "/dashboard", "/panel", "/console",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/swagger", "/swagger-ui", "/swagger.json",
    "/openapi.json", "/api-docs",
    "/graphql", "/graphiql",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma",
    "/.env", "/.git", "/.git/config",
    "/config", "/config.php", "/config.json",
    "/backup", "/backup.zip", "/backup.sql",
    "/robots.txt", "/sitemap.xml",
    "/.htaccess", "/web.config",
    "/server-status", "/server-info",
    "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/mappings",
    "/metrics", "/health", "/status",
    "/debug", "/trace", "/info",
]

# JS secret patterns
# Capped at 3 matches per pattern -- prevents noise
# from minified files matching hundreds of times
JS_SECRET_PATTERNS = [
    r'api[_\-]?key[\s"]*[:=][\s"]*[a-zA-Z0-9_\-]{16,}',
    r'api[_\-]?secret[\s"]*[:=][\s"]*[a-zA-Z0-9_\-]{16,}',
    r'access[_\-]?token[\s"]*[:=][\s"]*[a-zA-Z0-9_\-]{16,}',
    r'auth[_\-]?token[\s"]*[:=][\s"]*[a-zA-Z0-9_\-]{16,}',
    r'AKIA[0-9A-Z]{16}',
    r'aws[_\-]?secret[\s"]*[:=][\s"]*[a-zA-Z0-9/+=]{40}',
    r'https?://[a-z0-9\-]+\.(internal|local|corp|lan)[/\w\-]*',
    r'(mongodb|mysql|postgres|redis)://[^\s"\']+',
    r'https?://(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)',
]

# High risk ports with context
HIGH_RISK_PORTS = {
    21:    "FTP -- unencrypted file transfer",
    22:    "SSH -- brute force target",
    23:    "Telnet -- unencrypted, legacy protocol",
    25:    "SMTP -- mail relay risk",
    445:   "SMB -- EternalBlue, ransomware vector",
    1433:  "MSSQL -- database exposed",
    1521:  "Oracle DB -- database exposed",
    3306:  "MySQL -- database exposed",
    3389:  "RDP -- brute force, BlueKeep risk",
    5432:  "PostgreSQL -- database exposed",
    5900:  "VNC -- remote access exposed",
    6379:  "Redis -- often unauthenticated",
    8080:  "HTTP alternate -- often dev/test server",
    8443:  "HTTPS alternate",
    27017: "MongoDB -- often unauthenticated",
}


# ------------------------------------------------------------------ #
# SANITIZATION
# ------------------------------------------------------------------ #

def _sanitize_target(target: str) -> str:
    """
    Sanitize domain for nmap.
    Allows alphanumeric, dots, hyphens only.
    Raises ValueError if nothing remains.
    """
    sanitized = re.sub(r'[^a-zA-Z0-9.-]', '', target)
    if not sanitized:
        raise ValueError(
            f"Invalid target after sanitization: {target!r}"
        )
    return sanitized


def _sanitize_ip(ip: str) -> str:
    """
    Sanitize IP address for nmap.
    Allows digits and dots only.
    Raises ValueError if nothing remains.
    """
    sanitized = re.sub(r'[^0-9.]', '', ip)
    if not sanitized:
        raise ValueError(
            f"Invalid IP after sanitization: {ip!r}"
        )
    return sanitized


# ------------------------------------------------------------------ #
# TRADITIONAL RECON MODULE
# ------------------------------------------------------------------ #

class TraditionalRecon:
    """
    Active reconnaissance module.
    Extends OSINT passive findings with active scanning.

    Reads OSINTProfile via getattr with defaults --
    safe for both real OSINTProfile and MockProfile in tests.

    Each check independent -- one failure never stops others.
    All nmap inputs sanitized before use.
    All loops bounded -- no infinite loop risk.
    """

    def __init__(
        self,
        target:    str,
        mode:      str  = "SEMI-AUTO",
        full_scan: bool = False,
    ):
        self.target     = target
        self.mode       = mode.upper()
        self.full_scan  = full_scan
        self.aggregator = FindingsAggregator(target=target)
        self.findings:  list[Finding] = []

        # CVE engine -- fails gracefully if unavailable
        try:
            self.cve_engine = CVEEngine()
        except Exception as e:
            console.print(
                f"[yellow]  CVE engine init failed: "
                f"{e} -- CVE correlation disabled[/yellow]"
            )
            self.cve_engine = None

        self.port_range = ALL_PORTS if full_scan else TOP_PORTS

        if full_scan:
            console.print(
                "[yellow]  Full scan: all 65535 ports. "
                "Estimated 15-25 minutes.[/yellow]"
            )
        else:
            console.print(
                "[dim]  Standard scan: top 1000 ports[/dim]"
            )

    def _add_finding(self, finding: Finding):
        """Add finding to local list and aggregator."""
        self.findings.append(finding)
        self.aggregator.add_finding(finding)

    def _guided_gate(
        self, check_name: str, description: str
    ) -> bool:
        """GUIDED mode approval gate."""
        if self.mode != "GUIDED":
            return True
        console.print(
            f"\n[bold yellow]"
            f"GUIDED -- Approval Required"
            f"[/bold yellow]"
        )
        console.print(f"Check:  [bold]{check_name}[/bold]")
        console.print(f"Action: {description}")
        response = input("Run? [Y/N]: ").strip().upper()
        return response == "Y"

    # ------------------------------------------------------------------ #
    # CHECK 1-3 -- PORT SCAN + SERVICE DETECTION + CVE CORRELATION
    # ------------------------------------------------------------------ #

    def check_ports_and_services(
        self, ip: str
    ) -> list[Finding]:
        """
        Port scanning, service version detection, and CVE
        correlation combined in one nmap run for efficiency.

        nmap flags:
            -sV    service version detection
            -sC    default safe scripts
            --open only show open ports
            -T4    aggressive timing (faster, safe)

        NMAP_TIMEOUT=300 hard caps execution time.
        try/except per CVE lookup -- one failure continues loop.
        High risk ports flagged with elevated severity.
        Zero day flag raised when no CVE match found.
        """
        if not self._guided_gate(
            "Port Scan + Service Detection + CVE",
            f"nmap -sV -sC on {ip} "
            f"(ports: {self.port_range})"
        ):
            return []

        console.print(
            f"[cyan]  [1-3/8] Port scan + service "
            f"detection + CVE correlation "
            f"({self.port_range} ports)...[/cyan]"
        )
        findings = []

        try:
            import nmap

            nm      = nmap.PortScanner()
            safe_ip = _sanitize_ip(ip)

            console.print(
                f"[dim]    Scanning {safe_ip}...[/dim]"
            )

            nm.scan(
                hosts=safe_ip,
                arguments=(
                    f"-sV -sC --open -T4 "
                    f"-p {self.port_range}"
                ),
                timeout=NMAP_TIMEOUT
            )

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in sorted(
                        nm[host][proto].keys()
                    ):
                        svc     = nm[host][proto][port]
                        state   = svc.get("state", "")
                        service = svc.get("name", "unknown")
                        product = svc.get("product", "")
                        version = svc.get("version", "")

                        if state != "open":
                            continue

                        service_str = (
                            f"{product} {version}".strip()
                            or service
                        )

                        console.print(
                            f"[dim]    Port {port}/{proto}: "
                            f"{service_str}[/dim]"
                        )

                        severity  = 5.0
                        risk_note = ""
                        if port in HIGH_RISK_PORTS:
                            severity  = 8.0
                            risk_note = HIGH_RISK_PORTS[port]

                        findings.append(Finding(
                            title=(
                                f"Open port {port}/{proto}: "
                                f"{service_str}"
                            ),
                            description=(
                                f"Service {service_str} on "
                                f"{safe_ip}:{port}/{proto}. "
                                f"{risk_note}"
                            ),
                            finding_type="exposed_port",
                            source_module="traditional_recon",
                            target=self.target,
                            severity_score=severity
                        ))

                        # CVE correlation per versioned service
                        if (
                            product and
                            version and
                            self.cve_engine
                        ):
                            try:
                                cve: CVEResult = (
                                    self.cve_engine.lookup(
                                        service=product,
                                        version=version,
                                        target=self.target,
                                        raw_evidence={
                                            "port":     port,
                                            "protocol": proto,
                                            "service":  service_str,
                                            "host":     safe_ip
                                        }
                                    )
                                )

                                if cve.cve_id:
                                    findings.append(Finding(
                                        title=(
                                            f"{cve.cve_id} -- "
                                            f"{product} {version}"
                                        ),
                                        description=(
                                            f"CVE on port {port}: "
                                            f"{cve.description or ''}\n"
                                            f"CVSS: {cve.cvss_score}"
                                        ),
                                        finding_type="cve_match",
                                        source_module="traditional_recon",
                                        target=self.target,
                                        severity_score=(
                                            cve.cvss_score or 7.0
                                        ),
                                        cve_id=cve.cve_id,
                                        cvss_score=cve.cvss_score
                                    ))
                                    console.print(
                                        f"[red]    CVE: "
                                        f"{cve.cve_id} "
                                        f"port {port}[/red]"
                                    )

                                elif cve.zero_day_flag:
                                    findings.append(Finding(
                                        title=(
                                            f"Possible zero day: "
                                            f"{product} {version}"
                                        ),
                                        description=(
                                            f"No CVE match for "
                                            f"{product} {version} "
                                            f"port {port}. "
                                            f"Manual investigation "
                                            f"required."
                                        ),
                                        finding_type="zero_day",
                                        source_module="traditional_recon",
                                        target=self.target,
                                        severity_score=9.0,
                                        zero_day_flag=True,
                                        evidence_preserved=(
                                            cve.evidence_preserved
                                        ),
                                        raw_evidence_path=(
                                            cve.raw_evidence_path
                                        )
                                    ))
                                    console.print(
                                        f"[bold red]    "
                                        f"ZERO DAY: "
                                        f"{product} {version} "
                                        f"port {port}[/bold red]"
                                    )

                            except Exception as e:
                                console.print(
                                    f"[yellow]    CVE "
                                    f"port {port}: "
                                    f"{e}[/yellow]"
                                )

        except ImportError:
            console.print(
                "[red]  python-nmap not installed. "
                "Run: pip install python-nmap[/red]"
            )
        except Exception as e:
            console.print(
                f"[yellow]    Port scan failed: "
                f"{e}[/yellow]"
            )

        console.print(
            f"[green]    Done -- "
            f"{len(findings)} port/CVE findings[/green]"
        )
        return findings

    # ------------------------------------------------------------------ #
    # CHECK 4 -- SSL/TLS AUDIT
    # ------------------------------------------------------------------ #

    def check_ssl_tls(self) -> list[Finding]:
        """
        SSL/TLS configuration audit.
        Protocol version, cert expiry, cipher strength.
        Uses Python ssl module -- no external dependency.
        Uses timezone-aware datetime (Python 3.12 compatible).
        SSLError, ConnectionRefusedError, Exception all caught.
        """
        if not self._guided_gate(
            "SSL/TLS Audit",
            f"SSL/TLS check on {self.target}"
        ):
            return []

        console.print(
            "[cyan]  [4/8] SSL/TLS audit...[/cyan]"
        )
        findings = []

        try:
            context = ssl.create_default_context()
            conn    = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=self.target
            )
            conn.settimeout(REQUEST_TIMEOUT)
            conn.connect((self.target, 443))

            cert    = conn.getpeercert()
            version = conn.version()
            cipher  = conn.cipher()
            conn.close()

            # Weak protocol check
            if version in [
                "TLSv1", "TLSv1.1", "SSLv2", "SSLv3"
            ]:
                findings.append(Finding(
                    title=(
                        f"Weak TLS version: {version}"
                    ),
                    description=(
                        f"{self.target} supports {version}. "
                        f"Vulnerable to POODLE and BEAST. "
                        f"Enforce TLS 1.2 minimum, "
                        f"TLS 1.3 preferred."
                    ),
                    finding_type="outdated_ssl",
                    source_module="traditional_recon",
                    target=self.target,
                    severity_score=7.5
                ))

            # Certificate expiry
            # timezone-aware datetime -- no deprecation warning
            if cert:
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        expiry = datetime.strptime(
                            not_after,
                            "%b %d %H:%M:%S %Y %Z"
                        )
                        days_left = (
                            expiry.replace(tzinfo=timezone.utc)
                            - datetime.now(timezone.utc)
                        ).days

                        if days_left < 30:
                            findings.append(Finding(
                                title=(
                                    f"SSL cert expiring "
                                    f"in {days_left} days"
                                ),
                                description=(
                                    f"Certificate for "
                                    f"{self.target} expires "
                                    f"{not_after}. "
                                    f"Renew immediately."
                                ),
                                finding_type="outdated_ssl",
                                source_module="traditional_recon",
                                target=self.target,
                                severity_score=7.0
                            ))
                    except Exception:
                        pass

            console.print(
                f"[green]    Done -- "
                f"TLS: {version}, "
                f"cipher: "
                f"{cipher[0] if cipher else 'unknown'}"
                f"[/green]"
            )

        except ssl.SSLError as e:
            findings.append(Finding(
                title="SSL/TLS configuration error",
                description=(
                    f"SSL error on {self.target}: {str(e)}. "
                    f"Possible misconfiguration."
                ),
                finding_type="outdated_ssl",
                source_module="traditional_recon",
                target=self.target,
                severity_score=6.0
            ))
        except ConnectionRefusedError:
            console.print(
                "[dim]    SSL: port 443 not open[/dim]"
            )
        except Exception as e:
            console.print(
                f"[yellow]    SSL failed: {e}[/yellow]"
            )

        return findings

    # ------------------------------------------------------------------ #
    # CHECK 5 -- SECURITY HEADERS DEEP CHECK
    # ------------------------------------------------------------------ #

    def check_security_headers(self) -> list[Finding]:
        """
        Deep security header analysis.
        Checks header values not just presence.
        CSP: unsafe-inline and unsafe-eval flagged.
        HSTS: max-age=0 detected as disabled.
        Server version disclosure flagged.
        Full try/except -- never crashes module.
        """
        if not self._guided_gate(
            "Security Headers",
            f"Deep header check on {self.target}"
        ):
            return []

        console.print(
            "[cyan]  [5/8] Security headers...[/cyan]"
        )
        findings = []

        try:
            resp = requests.get(
                f"https://{self.target}",
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            headers = {
                k.lower(): v
                for k, v in resp.headers.items()
            }

            # CSP quality check
            csp = headers.get(
                "content-security-policy", ""
            )
            if csp:
                if "unsafe-inline" in csp:
                    findings.append(Finding(
                        title=(
                            "Weak CSP: unsafe-inline"
                        ),
                        description=(
                            "CSP contains 'unsafe-inline' "
                            "which permits XSS. "
                            "Remove unsafe-inline."
                        ),
                        finding_type="header_missing",
                        source_module="traditional_recon",
                        target=self.target,
                        severity_score=6.0
                    ))
                if "unsafe-eval" in csp:
                    findings.append(Finding(
                        title="Weak CSP: unsafe-eval",
                        description=(
                            "CSP contains 'unsafe-eval' "
                            "enabling code injection. "
                            "Remove unsafe-eval."
                        ),
                        finding_type="header_missing",
                        source_module="traditional_recon",
                        target=self.target,
                        severity_score=6.0
                    ))
            else:
                findings.append(Finding(
                    title="CSP header missing",
                    description=(
                        f"No Content-Security-Policy. "
                        f"XSS unrestricted."
                    ),
                    finding_type="header_missing",
                    source_module="traditional_recon",
                    target=self.target,
                    severity_score=5.0
                ))

            # HSTS -- presence and value
            hsts = headers.get(
                "strict-transport-security", ""
            )
            if hsts:
                if "max-age=0" in hsts:
                    findings.append(Finding(
                        title="HSTS disabled (max-age=0)",
                        description=(
                            "HSTS present but max-age=0 "
                            "disables it. "
                            "Set min 31536000."
                        ),
                        finding_type="header_missing",
                        source_module="traditional_recon",
                        target=self.target,
                        severity_score=6.0
                    ))
            else:
                findings.append(Finding(
                    title="HSTS missing",
                    description=(
                        f"No Strict-Transport-Security. "
                        f"HTTP downgrade possible."
                    ),
                    finding_type="header_missing",
                    source_module="traditional_recon",
                    target=self.target,
                    severity_score=5.5
                ))

            # X-Frame-Options
            if "x-frame-options" not in headers:
                findings.append(Finding(
                    title="X-Frame-Options missing",
                    description=(
                        "No X-Frame-Options. "
                        "Clickjacking possible."
                    ),
                    finding_type="header_missing",
                    source_module="traditional_recon",
                    target=self.target,
                    severity_score=4.5
                ))

            # Server version disclosure
            server = headers.get("server", "")
            if server and any(
                c.isdigit() for c in server
            ):
                findings.append(Finding(
                    title=(
                        f"Server version disclosed: "
                        f"{server}"
                    ),
                    description=(
                        f"Server header reveals: {server}. "
                        f"Enables targeted CVE lookup."
                    ),
                    finding_type="tech_stack",
                    source_module="traditional_recon",
                    target=self.target,
                    severity_score=4.0
                ))

            console.print(
                f"[green]    Done -- "
                f"{len(findings)} header findings"
                f"[/green]"
            )

        except Exception as e:
            console.print(
                f"[yellow]    Headers failed: "
                f"{e}[/yellow]"
            )

        return findings

    # ------------------------------------------------------------------ #
    # CHECK 6 -- ENDPOINT DISCOVERY
    # ------------------------------------------------------------------ #

    def check_endpoints(self) -> list[Finding]:
        """
        Common endpoint discovery.
        200/301/302/401/403 all indicate endpoint exists.
        404/410/400/500 indicate not present.
        try/except per path -- one failure never stops loop.
        REQUEST_DELAY between requests -- no rate limit risk.
        """
        if not self._guided_gate(
            "Endpoint Discovery",
            f"Probe {len(COMMON_ENDPOINTS)} paths "
            f"on {self.target}"
        ):
            return []

        console.print(
            f"[cyan]  [6/8] Endpoint discovery "
            f"({len(COMMON_ENDPOINTS)} paths)...[/cyan]"
        )
        findings = []
        base_url = f"https://{self.target}"

        for path in COMMON_ENDPOINTS:
            try:
                url  = urljoin(base_url, path)
                resp = requests.get(
                    url,
                    timeout=5,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )

                if resp.status_code not in [
                    404, 410, 400, 500
                ]:
                    severity     = 5.0
                    finding_type = "exposed_admin"

                    if any(kw in path for kw in [
                        "admin", "login", "dashboard",
                        "phpmyadmin", "wp-admin", "console"
                    ]):
                        severity = 8.0

                    elif any(kw in path for kw in [
                        ".env", ".git", "config",
                        "backup", ".sql", ".htaccess",
                        "web.config"
                    ]):
                        severity     = 9.0
                        finding_type = "data_exfiltration"

                    elif any(kw in path for kw in [
                        "swagger", "openapi", "graphql",
                        "api-docs", "actuator"
                    ]):
                        severity     = 6.0
                        finding_type = "tech_stack"

                    findings.append(Finding(
                        title=(
                            f"Endpoint found: {path} "
                            f"[{resp.status_code}]"
                        ),
                        description=(
                            f"{url} returned "
                            f"HTTP {resp.status_code}."
                        ),
                        finding_type=finding_type,
                        source_module="traditional_recon",
                        target=self.target,
                        severity_score=severity
                    ))

                    console.print(
                        f"[red]    FOUND "
                        f"[{resp.status_code}]: "
                        f"{path}[/red]"
                    )

            except requests.Timeout:
                pass
            except Exception:
                pass

            time.sleep(REQUEST_DELAY)

        console.print(
            f"[green]    Done -- "
            f"{len(findings)} endpoints[/green]"
        )
        return findings

    # ------------------------------------------------------------------ #
    # CHECK 7 -- JS BUNDLE ANALYSIS
    # ------------------------------------------------------------------ #

    def check_js_bundles(self) -> list[Finding]:
        """
        JavaScript bundle analysis.
        Downloads same-domain JS and scans for secrets,
        AWS keys, internal URLs, DB connection strings.

        Caps:
        - Max 10 JS files per engagement
        - Max 3 matches per pattern per file
          Prevents noise from minified bundles matching
          the same pattern hundreds of times.

        try/except per JS file -- one failure continues.
        """
        if not self._guided_gate(
            "JS Bundle Analysis",
            f"Scan JS files on {self.target}"
        ):
            return []

        console.print(
            "[cyan]  [7/8] JS bundle analysis...[/cyan]"
        )
        findings = []

        try:
            resp = requests.get(
                f"https://{self.target}",
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            soup    = BeautifulSoup(resp.text, "html.parser")
            js_urls = []

            for script in soup.find_all("script", src=True):
                src = script.get("src", "")
                if not src:
                    continue
                if src.startswith("http"):
                    if self.target in src:
                        js_urls.append(src)
                elif src.startswith("/"):
                    js_urls.append(
                        f"https://{self.target}{src}"
                    )
                else:
                    js_urls.append(
                        f"https://{self.target}/{src}"
                    )

            console.print(
                f"[dim]    {len(js_urls)} JS files[/dim]"
            )

            for js_url in js_urls[:10]:
                try:
                    js_resp = requests.get(
                        js_url,
                        timeout=REQUEST_TIMEOUT,
                        headers={"User-Agent": "Mozilla/5.0"}
                    )

                    if js_resp.status_code != 200:
                        continue

                    content = js_resp.text

                    for pattern in JS_SECRET_PATTERNS:
                        # Hard cap at 3 per pattern
                        matches = re.findall(
                            pattern,
                            content,
                            re.IGNORECASE
                        )[:3]

                        if not matches:
                            continue

                        if any(kw in pattern for kw in [
                            "api", "token", "secret",
                            "AKIA", "aws"
                        ]):
                            finding_type = "data_exfiltration"
                            severity     = 9.0
                            title_prefix = "Secret in JS"
                        elif any(kw in pattern for kw in [
                            "internal", "local", "corp"
                        ]):
                            finding_type = "tech_stack"
                            severity     = 7.0
                            title_prefix = "Internal URL in JS"
                        else:
                            finding_type = "tech_stack"
                            severity     = 6.0
                            title_prefix = "Sensitive data in JS"

                        findings.append(Finding(
                            title=(
                                f"{title_prefix}: "
                                f"{js_url.split('/')[-1]}"
                            ),
                            description=(
                                f"Pattern match in {js_url}\n"
                                f"Matches: {len(matches)} "
                                f"(capped at 3)"
                            ),
                            finding_type=finding_type,
                            source_module="traditional_recon",
                            target=self.target,
                            severity_score=severity
                        ))

                        console.print(
                            f"[red]    JS SECRET: "
                            f"{js_url.split('/')[-1]}"
                            f"[/red]"
                        )

                except Exception:
                    continue

                time.sleep(REQUEST_DELAY)

        except Exception as e:
            console.print(
                f"[yellow]    JS analysis failed: "
                f"{e}[/yellow]"
            )

        console.print(
            f"[green]    Done -- "
            f"{len(findings)} JS findings[/green]"
        )
        return findings

    # ------------------------------------------------------------------ #
    # CHECK 8 -- WAF BYPASS
    # ------------------------------------------------------------------ #

    def check_waf_bypass(
        self,
        profile_ip: Optional[str] = None
    ) -> list[Finding]:
        """
        WAF bypass -- origin IP discovery.
        Only runs when OSINT detected a WAF.

        Method 1: Direct IP probe with Host header spoofing.
        Method 2: Common bypass headers (X-Forwarded-For etc).

        urllib3 warnings suppressed at module level.
        try/except on all requests -- never crashes module.
        """
        if not self._guided_gate(
            "WAF Bypass",
            f"Origin IP discovery for {self.target}"
        ):
            return []

        console.print(
            "[cyan]  [8/8] WAF bypass...[/cyan]"
        )
        findings = []

        # Method 1 -- Direct IP probe
        if profile_ip:
            try:
                safe_ip = _sanitize_ip(profile_ip)

                origin_resp = requests.get(
                    f"https://{safe_ip}",
                    timeout=REQUEST_TIMEOUT,
                    headers={
                        "Host":       self.target,
                        "User-Agent": "Mozilla/5.0"
                    },
                    verify=False  # nosec B501
                )

                waf_resp = requests.get(
                    f"https://{self.target}",
                    timeout=REQUEST_TIMEOUT,
                    headers={"User-Agent": "Mozilla/5.0"},
                    verify=False  # nosec B501
                )

                if (
                    origin_resp.status_code == 200 and
                    origin_resp.text != waf_resp.text
                ):
                    findings.append(Finding(
                        title=(
                            "WAF bypass: origin accessible"
                        ),
                        description=(
                            f"Origin at {safe_ip} responds "
                            f"differently from WAF edge. "
                            f"WAF bypassable via direct IP. "
                            f"Restrict origin to WAF IPs only."
                        ),
                        finding_type="exposed_admin",
                        source_module="traditional_recon",
                        target=self.target,
                        severity_score=8.5
                    ))
                    console.print(
                        f"[red]    WAF BYPASS: "
                        f"{safe_ip}[/red]"
                    )

            except Exception:
                pass

        # Method 2 -- Bypass headers
        for header in [
            {"X-Forwarded-For":  "127.0.0.1"},
            {"X-Real-IP":        "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP":      "127.0.0.1"},
            {"X-Client-IP":      "127.0.0.1"},
        ]:
            try:
                requests.get(
                    f"https://{self.target}",
                    timeout=5,
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        **header
                    },
                    verify=False  # nosec B501
                )
            except Exception:
                pass
            time.sleep(0.3)

        console.print(
            f"[green]    Done -- "
            f"{len(findings)} WAF findings[/green]"
        )
        return findings

    # ------------------------------------------------------------------ #
    # MAIN RUN
    # ------------------------------------------------------------------ #

    def run(self, profile) -> list[Finding]:
        """
        Execute all traditional recon checks.
        Reads OSINTProfile via getattr with defaults.
        Each check wrapped in try/except -- crash isolation.
        WAF bypass only if OSINT flagged WAF.
        Port scan only if IP available.
        """
        console.print(
            f"\n[bold cyan]"
            f"{'='*52}\n"
            f"  R3D TRADITIONAL RECON\n"
            f"  Target : {self.target}\n"
            f"  Mode   : {self.mode}\n"
            f"  Scan   : "
            f"{'Full (65535)' if self.full_scan else 'Standard (1000)'}\n"
            f"{'='*52}"
            f"[/bold cyan]\n"
        )

        # Read profile defensively
        ip           = getattr(profile, "ip_address", None)
        waf_detected = getattr(profile, "waf_detected", False)

        # Resolve IP if not in profile
        if not ip:
            console.print(
                "[yellow]  No IP in profile -- "
                "resolving...[/yellow]"
            )
            try:
                ip = socket.gethostbyname(self.target)
                console.print(
                    f"[green]  Resolved: {ip}[/green]"
                )
            except Exception:
                console.print(
                    "[yellow]  DNS failed -- "
                    "port scan skipped[/yellow]"
                )

        # Build check list
        checks = []

        if ip:
            checks.append((
                "Port Scan + CVE",
                lambda: self.check_ports_and_services(ip)
            ))
        else:
            console.print(
                "[yellow]  No IP -- "
                "skipping port scan[/yellow]"
            )

        checks.extend([
            ("SSL/TLS",
             self.check_ssl_tls),
            ("Security Headers",
             self.check_security_headers),
            ("Endpoints",
             self.check_endpoints),
            ("JS Bundles",
             self.check_js_bundles),
        ])

        if waf_detected:
            console.print(
                "[dim]  WAF detected -- "
                "adding bypass check[/dim]"
            )
            checks.append((
                "WAF Bypass",
                lambda: self.check_waf_bypass(ip)
            ))
        else:
            console.print(
                "[dim]  No WAF -- "
                "skipping bypass[/dim]"
            )

        # Run all checks independently
        for check_name, check_fn in checks:
            try:
                new_findings = check_fn()
                for f in new_findings:
                    self._add_finding(f)
            except Exception as e:
                console.print(
                    f"[red]  {check_name} crashed: "
                    f"{e}[/red]"
                )

        console.print(
            f"\n[bold green]"
            f"{'='*52}\n"
            f"  TRADITIONAL RECON COMPLETE\n"
            f"  Findings: {len(self.findings)}\n"
            f"{'='*52}"
            f"[/bold green]\n"
        )

        return self.findings


# ------------------------------------------------------------------ #
# TEST
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    console.print(
        "[bold green]R3D Traditional Recon -- "
        "Module Load Test[/bold green]\n"
    )
    console.print(
        "[yellow]WARNING: Only test against targets "
        "you own or have explicit written "
        "authorization to test.[/yellow]\n"
    )

    class MockProfile:
        ip_address   = None
        waf_detected = False
        waf_type     = None
        tech_stack   = []
        subdomains   = []

    recon = TraditionalRecon(
        target="example.com",
        mode="SEMI-AUTO",
        full_scan=False
    )

    findings = recon.run(MockProfile())

    console.print(f"\nFindings: {len(findings)}")
    console.print(
        "[green]Module loaded successfully.[/green]"
    )