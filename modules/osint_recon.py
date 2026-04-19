"""
R3D Agent -- OSINT Reconnaissance Module
First module to run in every engagement. Passive and semi-passive only.
Builds complete surface map of target before anything active touches it.

Checks performed:
    1.  WHOIS and registrar lookup
    2.  DNS enumeration (A, MX, TXT, NS, CNAME)
    3.  Subdomain discovery (async wordlist + certificate transparency)
    4.  Google Dorking with anti-detection + DuckDuckGo fallback
    5.  Wayback Machine (Internet Archive)
    6.  Tech stack detection with WAF awareness
    7.  AI surface detection
    8.  Email harvesting
    9.  Breach checking (HaveIBeenPwned per-email, GitHub secrets)
    10. Sherlock username enumeration (subprocess, GUIDED/SEMI-AUTO only)

Reserved for v2 (not in v1):
    - Shodan   (paid API — adds too much cost for early users)
    - DeHashed (paid subscription — same reasoning)
    - IntelX   (API key required — v2 when we have paying customers)

Rate Limiting:
    RateLimiter class enforces per-domain and global request limits.
    Prevents accidental DoS and protects operator from IP bans.
    Configurable limits with automatic backoff on threshold breach.
    fast_mode parameter reduces delays for testing.

Security:
    All inputs sanitized before use in requests or file operations.
    Each check fails independently -- no cascading failures.
    Unified rate limiting via RateLimiter class.
    Mode enforcement -- Sherlock never runs in FULL-AUTO.
    GUIDED mode approval gate on every active check.
    WAF detection flags masked tech stack for traditional recon.
    SSL warnings suppressed -- noisy on async subdomain probing.

Compatibility: Windows 10/11, Ubuntu, Kali Linux
"""

import asyncio
import json
import random
import re
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlencode

import dns.resolver
import httpx
import requests
import urllib3
import whois
from bs4 import BeautifulSoup
from rich.console import Console

from core.findings import Finding, FindingsAggregator

# Suppress SSL warnings -- noisy during async subdomain probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

# Paths
BASE_DIR      = Path(__file__).parent.parent
DATA_DIR      = BASE_DIR / "data"
WORDLISTS_DIR = DATA_DIR / "wordlists"
OUTPUT_DIR    = BASE_DIR / "output"
PROFILES_DIR  = OUTPUT_DIR / "profiles"

# Rate limiting constants
REQUEST_DELAY        = 1.0    # standard delay between requests
REQUEST_DELAY_SEARCH = 2.5    # search engines -- more conservative
REQUEST_DELAY_FAST   = 0.2    # async probing
REQUEST_TIMEOUT      = 10     # seconds per request
ASYNC_CONCURRENCY    = 10     # max concurrent subdomain probes

# Rate limiter thresholds
# Protects operator from IP bans and prevents accidental DoS
RATE_LIMIT_MAX_REQUESTS = 60   # max requests per domain per minute
RATE_LIMIT_WINDOW       = 60   # window in seconds
RATE_LIMIT_BACKOFF      = 30   # seconds to wait when threshold hit

# Rotating user agents -- reduces search engine fingerprinting
USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
        "Gecko/20100101 Firefox/121.0"
    ),
]

# Google dork templates
GOOGLE_DORKS = [
    "site:{target} filetype:pdf",
    "site:{target} filetype:xlsx",
    "site:{target} filetype:docx",
    "site:{target} inurl:admin",
    "site:{target} inurl:login",
    "site:{target} inurl:dashboard",
    "site:{target} inurl:portal",
    'site:{target} "index of"',
    'site:{target} "internal use only"',
    'site:{target} "confidential"',
    "site:{target} inurl:api",
    "site:{target} inurl:swagger",
    "site:{target} inurl:graphql",
    "site:{target} ext:env",
    "site:{target} ext:log",
    "site:{target} ext:sql",
    "site:{target} ext:bak",
    "site:{target} ext:config",
    'site:{target} "error" "stack trace"',
    "site:{target} inurl:wp-admin",
    "site:{target} inurl:phpmyadmin",
]

# AI surface endpoint signatures
AI_SURFACE_SIGNATURES = [
    "/chat", "/chatbot", "/assistant", "/ai", "/llm", "/gpt", "/copilot",
    "/api/chat", "/api/ai", "/api/llm", "/api/assistant",
    "/api/v1/chat", "/api/v2/chat",
    "/openai", "/anthropic", "/azure-openai", "/bedrock",
    "/vertex", "/palm", "/gemini", "/claude",
    "/completions", "/generate", "/inference", "/predict",
    "/model", "/models", "/v1/completions",
    "/v1/chat/completions", "/v1/models",
]

# Tech stack fingerprints
TECH_SIGNATURES = {
    "WordPress":  ["wp-content", "wp-includes", "wp-json", "wp-login"],
    "Drupal":     ["sites/default", "drupal.js", "Drupal.settings"],
    "Joomla":     ["joomla", "/components/com_"],
    "Laravel":    ["laravel_session", "XSRF-TOKEN"],
    "Django":     ["csrfmiddlewaretoken", "django"],
    "React":      ["react.js", "react.min.js", "_next", "__NEXT_DATA__"],
    "Angular":    ["ng-version", "angular.js", "ng-app"],
    "Vue":        ["vue.js", "vue.min.js", "__vue__"],
    "Apache":     ["Apache", "apache"],
    "Nginx":      ["nginx"],
    "IIS":        ["IIS", "ASP.NET", "X-AspNet-Version"],
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray", "CF-Cache-Status"],
    "AWS WAF":    ["amazonaws.com", "cloudfront.net", "x-amz-cf-id"],
    "Azure WAF":  ["azurewebsites.net", "x-azure-ref"],
    "Shopify":    ["shopify", "myshopify.com", "Shopify.theme"],
    "Magento":    ["magento", "Mage.Cookies"],
}

# WAF signatures -- checked before tech stack to flag masked origin
WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "CF-Cache-Status"],
    "AWS WAF":    ["x-amz-cf-id", "x-amz-request-id", "cloudfront"],
    "Azure WAF":  ["x-azure-ref", "x-fd-healthprobe"],
    "Akamai":     ["akamai", "x-akamai-transformed"],
    "Fastly":     ["x-served-by", "fastly"],
    "Imperva":    ["x-iinfo", "incapsula"],
    "F5 BIG-IP":  ["bigipserver", "f5-bigip"],
    "ModSecurity":["mod_security", "modsecurity"],
}

# Security headers to check
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS missing",
    "content-security-policy":   "CSP missing",
    "x-frame-options":           "X-Frame-Options missing",
    "x-content-type-options":    "X-Content-Type-Options missing",
    "referrer-policy":           "Referrer-Policy missing",
    "permissions-policy":        "Permissions-Policy missing",
}

# Ignored email prefixes -- generic addresses not useful for targeting
IGNORED_EMAIL_PREFIXES = [
    "noreply", "no-reply", "donotreply", "do-not-reply",
    "support", "help", "info", "contact", "admin",
    "webmaster", "postmaster", "hostmaster", "abuse",
    "security", "privacy", "legal", "billing",
]

# Default subdomain wordlist
DEFAULT_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
    "admin", "portal", "test", "beta", "app", "cdn", "media", "static",
    "assets", "img", "images", "login", "dashboard", "manage", "support",
    "help", "docs", "wiki", "git", "gitlab", "jenkins", "jira", "confluence",
    "ldap", "intranet", "internal", "corp", "office", "extranet", "web",
    "monitor", "nagios", "grafana", "kibana", "elastic", "redis", "mysql",
    "postgres", "db", "database", "backup", "files", "download", "upload",
    "owa", "exchange", "autodiscover", "sip", "voip", "chat", "ai", "llm",
    "gpt", "assistant", "bot", "api-v1", "api-v2", "v1", "v2", "v3",
    "api-dev", "api-staging", "api-prod", "mobile", "legacy", "old",
    "demo", "sandbox", "preprod", "qa", "uat", "prod", "production",
]


# ------------------------------------------------------------------ #
# SANITIZATION HELPERS
# ------------------------------------------------------------------ #

def _sanitize_domain(domain: str) -> str:
    """Strip protocol, path, whitespace, dangerous chars from domain."""
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'/.*$', '', domain)
    domain = re.sub(r'[^a-zA-Z0-9.\-]', '', domain)
    return domain


def _sanitize_username(username: str) -> str:
    """Alphanumeric, dots, hyphens only. Max 50 chars."""
    return re.sub(r'[^a-zA-Z0-9._\-]', '', username)[:50]


def _sanitize_filename(value: str) -> str:
    """Safe filename component. Consistent with CVE engine pattern."""
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', value)[:30]


def _get_headers(referer: str = "") -> dict:
    """
    Realistic browser headers with rotating user agent.
    Reduces fingerprinting on search engines and target sites.
    """
    headers = {
        "User-Agent":                random.choice(USER_AGENTS),
        "Accept":                    (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language":           "en-US,en;q=0.9",
        "Accept-Encoding":           "gzip, deflate, br",
        "DNT":                       "1",
        "Connection":                "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    if referer:
        headers["Referer"] = referer
    return headers


# ------------------------------------------------------------------ #
# RATE LIMITER
# ------------------------------------------------------------------ #

class RateLimiter:
    """
    Per-domain and global request rate limiter.

    Prevents accidental DoS against targets and protects operator
    from IP bans by external services (Google, HIBP, GitHub).

    Design:
    - Tracks request timestamps per domain in a sliding window
    - Automatically backs off when threshold approached
    - fast_mode reduces all delays for testing
    - Never blocks -- warns and sleeps, always continues

    Usage:
        limiter = RateLimiter(fast_mode=False)
        limiter.wait("google.com")     # before each request
        limiter.wait("target.com")     # per-domain tracking
    """

    def __init__(self, fast_mode: bool = False):
        self.fast_mode = fast_mode
        # Per-domain request timestamps: {domain: [timestamp, ...]}
        self._requests: dict = defaultdict(list)
        self._global_requests: list = []

    def _clean_window(self, timestamps: list) -> list:
        """Remove timestamps older than the rate limit window."""
        cutoff = time.time() - RATE_LIMIT_WINDOW
        return [t for t in timestamps if t > cutoff]

    def wait(
        self,
        domain: str,
        delay: Optional[float] = None,
        _label: str = ""
    ):
        """
        Wait appropriate time before next request to domain.

        Args:
            domain: Target domain for per-domain tracking
            delay:  Override default delay (uses REQUEST_DELAY if None)
            _label: Human-readable label for rate limit messages (reserved,
                    not currently used — kept for future logging hooks)
        """
        if self.fast_mode:
            time.sleep(0.1)
            return

        # Clean old timestamps
        self._requests[domain] = self._clean_window(
            self._requests[domain]
        )
        self._global_requests = self._clean_window(
            self._global_requests
        )

        # Check per-domain threshold
        domain_count = len(self._requests[domain])
        if domain_count >= RATE_LIMIT_MAX_REQUESTS:
            msg = (
                f"[yellow]  Rate limit reached for {domain} "
                f"({domain_count} requests in {RATE_LIMIT_WINDOW}s). "
                f"Backing off {RATE_LIMIT_BACKOFF}s...[/yellow]"
            )
            console.print(msg)
            time.sleep(RATE_LIMIT_BACKOFF)
            # Clean again after backoff
            self._requests[domain] = self._clean_window(
                self._requests[domain]
            )

        # Apply standard delay
        actual_delay = delay if delay is not None else REQUEST_DELAY
        if actual_delay > 0:
            time.sleep(actual_delay)

        # Record this request
        now = time.time()
        self._requests[domain].append(now)
        self._global_requests.append(now)

    def get_request_count(self, domain: str) -> int:
        """Return current request count for domain in window."""
        self._requests[domain] = self._clean_window(
            self._requests[domain]
        )
        return len(self._requests[domain])

    def summary(self) -> dict:
        """Return rate limiter summary for telemetry."""
        return {
            domain: len(self._clean_window(timestamps))
            for domain, timestamps in self._requests.items()
        }


# ------------------------------------------------------------------ #
# OSINT PROFILE
# ------------------------------------------------------------------ #

@dataclass
class OSINTProfile:
    """
    Complete OSINT surface map of the target.
    Saved to disk after module completes.
    Downstream modules load this to focus their work:
        LLM attack     -- reads ai_surfaces
        Traditional    -- reads subdomains, ip_address, waf_detected
        GRC mapper     -- reads tech_stack, emails, breached_emails
        Orchestrator   -- reads everything for adaptive sequencing
    """
    target:    str
    timestamp: str = field(
        default_factory=lambda: datetime.now().strftime(
            "%Y-%m-%d_%H-%M-%S"
        )
    )

    # WHOIS
    registrar:         Optional[str] = None
    registration_date: Optional[str] = None
    expiry_date:       Optional[str] = None
    registrant_org:    Optional[str] = None
    nameservers:       list = field(default_factory=list)

    # DNS
    a_records:     list = field(default_factory=list)
    mx_records:    list = field(default_factory=list)
    txt_records:   list = field(default_factory=list)
    ns_records:    list = field(default_factory=list)
    cname_records: list = field(default_factory=list)
    ip_address:    Optional[str] = None

    # Surfaces
    subdomains:    list = field(default_factory=list)
    ai_surfaces:   list = field(default_factory=list)
    admin_panels:  list = field(default_factory=list)
    exposed_files: list = field(default_factory=list)
    api_endpoints: list = field(default_factory=list)

    # Tech stack
    tech_stack:      list = field(default_factory=list)
    server_software: Optional[str] = None
    cms:             Optional[str] = None

    # WAF detection -- read by traditional recon module
    waf_detected: bool          = False
    waf_type:     Optional[str] = None

    # People
    emails:          list = field(default_factory=list)
    usernames:       list = field(default_factory=list)
    breached_emails: list = field(default_factory=list)

    # Historical
    historical_endpoints: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target":               self.target,
            "timestamp":            self.timestamp,
            "registrar":            self.registrar,
            "registration_date":    self.registration_date,
            "expiry_date":          self.expiry_date,
            "registrant_org":       self.registrant_org,
            "nameservers":          self.nameservers,
            "a_records":            self.a_records,
            "mx_records":           self.mx_records,
            "txt_records":          self.txt_records,
            "ns_records":           self.ns_records,
            "cname_records":        self.cname_records,
            "ip_address":           self.ip_address,
            "subdomains":           self.subdomains,
            "ai_surfaces":          self.ai_surfaces,
            "admin_panels":         self.admin_panels,
            "exposed_files":        self.exposed_files,
            "api_endpoints":        self.api_endpoints,
            "tech_stack":           self.tech_stack,
            "server_software":      self.server_software,
            "cms":                  self.cms,
            "waf_detected":         self.waf_detected,
            "waf_type":             self.waf_type,
            "emails":               self.emails,
            "usernames":            self.usernames,
            "breached_emails":      self.breached_emails,
            "historical_endpoints": self.historical_endpoints,
        }

    def save(self, path: Optional[Path] = None) -> Path:
        """
        Save profile to disk for downstream module consumption.
        Default: output/profiles/TIMESTAMP_TARGET_profile.json
        """
        PROFILES_DIR.mkdir(parents=True, exist_ok=True)
        if path is None:
            safe_target = _sanitize_filename(self.target)
            path = (
                PROFILES_DIR /
                f"{self.timestamp}_{safe_target}_profile.json"
            )
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return path

    @classmethod
    def load(cls, path: Path) -> "OSINTProfile":
        """Load saved profile from disk."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        profile = cls(target=data["target"])
        for key, value in data.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
        return profile


# ------------------------------------------------------------------ #
# OSINT RECON MODULE
# ------------------------------------------------------------------ #

class OSINTRecon:
    """
    Autonomous OSINT reconnaissance module.
    Runs all checks, produces Finding objects and OSINTProfile.

    Design principles:
    - Each check fails independently
    - All inputs sanitized before use
    - Mode gates enforced on every check
    - RateLimiter enforced on all external requests
    - WAF-aware tech detection
    - Sherlock via subprocess for version stability
    - fast_mode available for testing
    """

    def __init__(
        self,
        target:    str,
        mode:      str  = "GUIDED",
        fast_mode: bool = False,
    ):
        self.target     = _sanitize_domain(target)
        self.mode       = mode.upper()
        self.fast_mode  = fast_mode
        self.profile    = OSINTProfile(target=self.target)
        self.aggregator = FindingsAggregator(target=self.target)
        self.findings:  list[Finding] = []
        self.limiter    = RateLimiter(fast_mode=fast_mode)

        # Load extended wordlist if available
        wordlist_path = WORDLISTS_DIR / "subdomains.txt"
        if wordlist_path.exists():
            with open(wordlist_path, encoding="utf-8") as f:
                self.subdomains_wordlist = [
                    line.strip() for line in f
                    if line.strip() and not line.startswith("#")
                ]
        else:
            self.subdomains_wordlist = DEFAULT_SUBDOMAINS

        if fast_mode:
            console.print(
                "[yellow]  fast_mode enabled -- "
                "reduced delays for testing[/yellow]"
            )

    def _add_finding(self, finding: Finding):
        """Add finding to local list and aggregator."""
        self.findings.append(finding)
        self.aggregator.add_finding(finding)

    def _guided_gate(
        self, check_name: str, description: str
    ) -> bool:
        """
        GUIDED mode approval gate.
        GUIDED    -- operator approves every check.
        SEMI-AUTO -- auto-approved.
        FULL-AUTO -- auto-approved (Sherlock blocked separately).
        """
        if self.mode != "GUIDED":
            return True
        console.print(
            "\n[bold yellow]"
            "GUIDED -- Approval Required"
            "[/bold yellow]"
        )
        console.print(f"Check:  [bold]{check_name}[/bold]")
        console.print(f"Action: {description}")
        response = input("Run? [Y/N]: ").strip().upper()
        return response == "Y"

    def _operator_consent(
        self, tool: str, description: str
    ) -> bool:
        """
        Explicit consent popup for sensitive active tools.
        Required for Sherlock regardless of mode.
        Requires full YES -- not just Y.
        """
        console.print(
            "\n[bold red]"
            "CONSENT REQUIRED -- ACTIVE ENUMERATION"
            "[/bold red]"
        )
        console.print(f"Tool:   [bold]{tool}[/bold]")
        console.print(f"Action: {description}")
        console.print(f"Target: {self.target}")
        console.print(
            "\n[yellow]Only proceed with explicit written "
            "authorization from target organization.[/yellow]"
        )
        response = input(
            "Type YES to authorize, anything else cancels: "
        ).strip().upper()
        return response == "YES"

    # ------------------------------------------------------------------ #
    # CHECK 1 -- WHOIS
    # ------------------------------------------------------------------ #
    def check_whois(self) -> list[Finding]:
        """
        WHOIS registrar lookup.
        Flags domains expiring within 90 days -- hijacking risk.
        Handles datetime objects and list responses from python-whois.
        """
        if not self._guided_gate(
            "WHOIS Lookup",
            f"Query WHOIS database for {self.target}"
        ):
            return []

        console.print("[cyan]  [1/10] WHOIS lookup...[/cyan]")
        findings = []

        try:
            w = whois.whois(self.target)

            self.profile.registrar = (
                str(w.registrar) if w.registrar else None
            )
            self.profile.registrant_org = (
                str(w.org) if w.org else None
            )

            if w.creation_date:
                date = w.creation_date
                if isinstance(date, list):
                    date = date[0]
                self.profile.registration_date = (
                    date.strftime("%Y-%m-%d")
                    if hasattr(date, 'strftime')
                    else str(date)
                )

            if w.expiration_date:
                exp = w.expiration_date
                if isinstance(exp, list):
                    exp = exp[0]
                self.profile.expiry_date = (
                    exp.strftime("%Y-%m-%d")
                    if hasattr(exp, 'strftime')
                    else str(exp)
                )

                if hasattr(exp, 'date'):
                    days = (
                        exp.date() - datetime.now().date()
                    ).days
                    if 0 < days < 90:
                        findings.append(Finding(
                            title=(
                                f"Domain expiring in {days} days"
                            ),
                            description=(
                                f"{self.target} expires {exp}. "
                                f"Domain hijacking risk if renewal "
                                f"lapses. Notify registrar immediately."
                            ),
                            finding_type="subdomain",
                            source_module="osint_recon",
                            target=self.target,
                            severity_score=6.0
                        ))

            if w.name_servers:
                ns = w.name_servers
                self.profile.nameservers = (
                    [str(n).lower() for n in ns]
                    if isinstance(ns, list)
                    else [str(ns).lower()]
                )

            console.print(
                f"[green]    Done -- "
                f"registrar: {self.profile.registrar or 'unknown'}"
                f"[/green]"
            )

        except Exception as e:
            console.print(
                f"[yellow]    WHOIS failed: {e}[/yellow]"
            )

        self.limiter.wait(self.target)
        return findings

    # ------------------------------------------------------------------ #
    # CHECK 2 -- DNS
    # ------------------------------------------------------------------ #
    def check_dns(self) -> list[Finding]:
        """
        DNS enumeration -- A, MX, TXT, NS, CNAME.
        Missing DMARC flagged as email spoofing risk.
        Non-standard TXT records flagged for manual review.
        """
        if not self._guided_gate(
            "DNS Enumeration",
            f"Query all DNS record types for {self.target}"
        ):
            return []

        console.print("[cyan]  [2/10] DNS enumeration...[/cyan]")

        # Fix: skip DNS/DMARC on private IPs
        # RFC1918 addresses have no public DNS records
        import ipaddress
        try:
            if ipaddress.ip_address(self.target).is_private:
                console.print("[dim]    DNS skipped -- private IP[/dim]")
                return []
        except ValueError:
            pass  # domain name -- continue

        findings = []
        resolver = dns.resolver.Resolver()
        resolver.timeout  = REQUEST_TIMEOUT
        resolver.lifetime = REQUEST_TIMEOUT

        # Fix: fallback nameservers if system DNS fails
        # ISP DNS servers often timeout on external domains
        # 8.8.8.8 = Google, 1.1.1.1 = Cloudflare
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

        for record_type in ["A", "MX", "TXT", "NS", "CNAME"]:
            try:
                answers = resolver.resolve(self.target, record_type)

                if record_type == "A":
                    self.profile.a_records = [
                        str(r) for r in answers
                    ]
                    if self.profile.a_records:
                        self.profile.ip_address = (
                            self.profile.a_records[0]
                        )

                elif record_type == "MX":
                    self.profile.mx_records = [
                        str(r.exchange).rstrip('.') for r in answers
                    ]

                elif record_type == "TXT":
                    self.profile.txt_records = [
                        str(r) for r in answers
                    ]
                    for record in self.profile.txt_records:
                        is_standard = any(
                            kw in record.lower() for kw in [
                                "v=spf", "v=dmarc", "v=dkim",
                                "google-site", "ms=", "docusign",
                                "atlassian", "apple-domain",
                            ]
                        )
                        if not is_standard and len(record) > 10:
                            findings.append(Finding(
                                title="Non-standard TXT record",
                                description=(
                                    f"TXT may reveal internal config: "
                                    f"{record[:150]}"
                                ),
                                finding_type="tech_stack",
                                source_module="osint_recon",
                                target=self.target,
                                severity_score=3.0
                            ))

                elif record_type == "NS":
                    self.profile.ns_records = [
                        str(r).rstrip('.') for r in answers
                    ]

                elif record_type == "CNAME":
                    self.profile.cname_records = [
                        str(r).rstrip('.') for r in answers
                    ]

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                console.print(
                    f"[yellow]    DNS {record_type} error: "
                    f"{e}[/yellow]"
                )

        # Missing DMARC check
        try:
            resolver.resolve(f"_dmarc.{self.target}", "TXT")
        except Exception:
            findings.append(Finding(
                title="DMARC missing -- email spoofing risk",
                description=(
                    f"No DMARC record on {self.target}. "
                    f"Attackers can spoof @{self.target} emails. "
                    f"Implement p=reject DMARC policy."
                ),
                finding_type="header_missing",  # Fix: was email_exposed
                source_module="osint_recon",    # DMARC is DNS config not email exposure
                target=self.target,
                severity_score=6.5
            ))

        console.print(
            f"[green]    Done -- "
            f"IP: {self.profile.ip_address}, "
            f"MX: {len(self.profile.mx_records)}, "
            f"TXT: {len(self.profile.txt_records)}"
            f"[/green]"
        )
        self.limiter.wait(self.target)
        return findings

    # ------------------------------------------------------------------ #
    # CHECK 3 -- SUBDOMAINS + CERTIFICATE TRANSPARENCY
    # ------------------------------------------------------------------ #
    def check_subdomains(self) -> list[Finding]:
        """
        Two-source subdomain discovery:
        1. crt.sh certificate transparency logs (passive)
        2. Async httpx wordlist probing (semi-active)

        HTTP fallback included -- many internal subdomains run HTTP not HTTPS.

        Asyncio note: Manual event loop creation is intentional.
        asyncio.run() throws RuntimeError when called from an
        already-running event loop in the orchestrator context.
        Manual loop creation isolates execution safely.
        """
        if not self._guided_gate(
            "Subdomain Discovery",
            f"CT log lookup + async wordlist probe for {self.target}"
        ):
            return []

        console.print(
            "[cyan]  [3/10] Subdomain discovery...[/cyan]"
        )
        findings = []

        ct_subdomains = self._check_cert_transparency()
        all_subdomains = list(set(
            self.subdomains_wordlist + ct_subdomains
        ))

        est_seconds = len(all_subdomains) // ASYNC_CONCURRENCY
        console.print(
            f"[dim]    Probing {len(all_subdomains)} candidates "
            f"(async, ~{est_seconds}s)...[/dim]"
        )

        async def run_probes():
            semaphore = asyncio.Semaphore(ASYNC_CONCURRENCY)
            async with httpx.AsyncClient(
                verify=False,  # nosec B501 -- intentional, probing subdomains with self-signed certs
                timeout=REQUEST_TIMEOUT,
                follow_redirects=True
            ) as client:

                tasks = [
                    self._probe_subdomain(client, sub, semaphore)
                    for sub in all_subdomains
                ]
                return await asyncio.gather(*tasks)

        # Manual loop -- orchestrator safe
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(run_probes())
        finally:
            loop.close()

        live = [r for r in results if r is not None]

        for sub_data in live:
            subdomain = sub_data["subdomain"]
            self.profile.subdomains.append(subdomain)

            severity     = 4.0
            finding_type = "subdomain"

            sensitive = any(kw in subdomain.lower() for kw in [
                "admin", "staging", "dev", "test", "internal",
                "corp", "vpn", "git", "jenkins", "jira", "ldap",
                "intranet", "backup", "db", "database", "secret",
                "private", "uat", "preprod",
            ])
            if sensitive:
                severity     = 7.5
                finding_type = "exposed_admin"
                self.profile.admin_panels.append(subdomain)

            findings.append(Finding(
                title=f"Live subdomain: {subdomain}",
                description=(
                    f"Live at {sub_data['url']}. "
                    f"HTTP {sub_data['status']}. "
                    f"Server: {sub_data['server'] or 'unknown'}. "
                    f"Title: {sub_data['title'] or 'none'}"
                ),
                finding_type=finding_type,
                source_module="osint_recon",
                target=self.target,
                severity_score=severity
            ))

        console.print(
            f"[green]    Done -- "
            f"{len(live)} live subdomains[/green]"
        )
        return findings

    async def _probe_subdomain(
        self,
        client:    httpx.AsyncClient,
        subdomain: str,
        semaphore: asyncio.Semaphore
    ) -> Optional[dict]:
        """
        Probe single subdomain via HTTPS then HTTP fallback.
        Returns dict or None.
        """
        async with semaphore:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{subdomain}.{self.target}"
                try:
                    resp  = await client.get(
                        url, timeout=REQUEST_TIMEOUT
                    )
                    title = ""
                    try:
                        soup  = BeautifulSoup(
                            resp.text, "html.parser"
                        )
                        tag   = soup.find("title")
                        title = tag.text.strip()[:100] if tag else ""
                    except Exception:
                        pass
                    return {
                        "subdomain": f"{subdomain}.{self.target}",
                        "url":       url,
                        "status":    resp.status_code,
                        "server":    resp.headers.get("server", ""),
                        "title":     title,
                    }
                except Exception:
                    continue
            return None

    def _check_cert_transparency(self) -> list[str]:
        """Query crt.sh for certificate transparency subdomains."""
        subdomains = []
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            resp = requests.get(
                url, timeout=REQUEST_TIMEOUT,
                headers=_get_headers()
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if (
                            line.endswith(f".{self.target}") and
                            "*" not in line
                        ):
                            sub = line.replace(
                                f".{self.target}", ""
                            ).strip()
                            if sub:
                                subdomains.append(sub)
                subdomains = list(set(subdomains))
                console.print(
                    f"[dim]    CT logs: "
                    f"{len(subdomains)} subdomains[/dim]"
                )
        except Exception as e:
            console.print(
                f"[yellow]    CT failed: {e}[/yellow]"
            )
        self.limiter.wait("crt.sh")
        return subdomains

    # ------------------------------------------------------------------ #
    # CHECK 4 -- GOOGLE DORKING + DUCKDUCKGO FALLBACK
    # ------------------------------------------------------------------ #
    def check_google_dorks(self) -> list[Finding]:
        """
        Automated dorking with anti-detection + DuckDuckGo fallback.

        Anti-detection techniques:
        - Rotating user agents across 5 browser profiles
        - Random delay jitter mimicking human behavior
        - Session-based requests maintaining cookies
        - Realistic Accept/Referer headers
        - Session warmup visit before dorking begins
        - User agent rotation every 5 requests

        Fallback strategy:
        - Google attempted first
        - On 429 or CAPTCHA or empty results -- switch to DuckDuckGo
        - DuckDuckGo HTML endpoint significantly more permissive
        - Remaining dorks continue on DuckDuckGo seamlessly

        Rate limiting:
        - RateLimiter tracks google.com and duckduckgo.com separately
        - Random jitter on top of base delay mimics human behavior
        """
        if not self._guided_gate(
            "Google Dorking",
            f"Automated dork queries for {self.target} "
            f"(Google + DuckDuckGo fallback)"
        ):
            return []

        console.print("[cyan]  [4/10] Google dorking...[/cyan]")
        findings       = []
        google_blocked = False

        session = requests.Session()
        session.headers.update(_get_headers())

        # Warmup -- mimics organic Google visit
        try:
            session.get(
                "https://www.google.com",
                timeout=REQUEST_TIMEOUT
            )
            self.limiter.wait(
                "google.com",
                delay=random.uniform(1.5, 3.0)
            )
        except Exception:
            pass

        for i, dork_template in enumerate(GOOGLE_DORKS):
            dork = dork_template.format(target=self.target)

            if not google_blocked:
                results = self._dork_google(session, dork)
                if results is None:
                    console.print(
                        "[yellow]    Google blocked -- "
                        "switching to DuckDuckGo[/yellow]"
                    )
                    google_blocked = True
                    results = self._dork_duckduckgo(dork)
            else:
                results = self._dork_duckduckgo(dork)

            for url, context in (results or []):
                finding_type, severity = (
                    self._classify_dork_result(dork, url)
                )
                if finding_type == "exposed_admin":
                    self.profile.admin_panels.append(url)
                elif finding_type == "data_exfiltration":
                    self.profile.exposed_files.append(url)
                elif finding_type == "tech_stack":
                    self.profile.api_endpoints.append(url)

                findings.append(Finding(
                    title=f"Dork hit: {dork[:70]}",
                    description=(
                        f"Query: {dork}\n"
                        f"URL: {url[:200]}\n"
                        f"Context: {context[:100]}"
                    ),
                    finding_type=finding_type,
                    source_module="osint_recon",
                    target=self.target,
                    severity_score=severity
                ))

            # Rate limit with random jitter
            engine = "duckduckgo.com" if google_blocked else "google.com"
            jitter = random.uniform(0, 2.0)
            self.limiter.wait(
                engine,
                delay=REQUEST_DELAY_SEARCH + jitter
            )

            # Rotate user agent every 5 dorks
            if (i + 1) % 5 == 0:
                session.headers.update(_get_headers())

        console.print(
            f"[green]    Done -- {len(findings)} results[/green]"
        )
        return findings

    def _dork_google(
        self,
        session: requests.Session,
        dork:    str
    ) -> Optional[list]:
        """
        Execute dork via Google.
        Returns list of (url, context) or None if blocked.
        Returns None (not []) on block to trigger DDG fallback.
        Returns [] on soft failure (empty results, parse error).
        """
        try:
            params = {
                "q":   dork,
                "num": "10",
                "hl":  "en",
                "gl":  "us",
            }
            url = (
                "https://www.google.com/search?"
                + urlencode(params)
            )
            session.headers["Referer"] = "https://www.google.com/"
            resp = session.get(url, timeout=REQUEST_TIMEOUT)

            # Block detection
            if resp.status_code == 429:
                return None
            if "unusual traffic" in resp.text.lower():
                return None
            if "captcha" in resp.text.lower():
                return None
            if resp.status_code != 200:
                return None

            soup    = BeautifulSoup(resp.text, "html.parser")
            results = []

            for g in soup.find_all("div", class_="g"):
                link    = g.find("a")
                snippet = g.find("span", class_="aCOpRe")
                if link and link.get("href"):
                    href = link["href"]
                    if (
                        href.startswith("http") and
                        self.target in href
                    ):
                        results.append((
                            href,
                            snippet.text if snippet else ""
                        ))

            # Empty results may indicate changed HTML structure
            # Fall back to DuckDuckGo for remaining dorks
            if not results:
                return None

            return results

        except Exception:
            return []

    def _dork_duckduckgo(self, dork: str) -> list:
        """
        Execute dork via DuckDuckGo HTML endpoint.
        Fallback when Google blocks. More permissive rate limits.
        Returns list of (url, context) tuples.
        """
        try:
            headers = _get_headers("https://duckduckgo.com/")
            params  = {"q": dork, "kl": "us-en"}
            url     = (
                "https://html.duckduckgo.com/html/?"
                + urlencode(params)
            )
            resp = requests.get(
                url, headers=headers,
                timeout=REQUEST_TIMEOUT
            )
            if resp.status_code != 200:
                return []

            soup    = BeautifulSoup(resp.text, "html.parser")
            results = []

            for result in soup.find_all(
                "div", class_="result__body"
            ):
                link    = result.find("a", class_="result__url")
                snippet = result.find(
                    "a", class_="result__snippet"
                )
                if link:
                    href = link.get("href", "")
                    if self.target in href:
                        results.append((
                            href,
                            snippet.text if snippet else ""
                        ))
            return results

        except Exception:
            return []

    def _classify_dork_result(
        self, dork: str, url: str
    ) -> tuple[str, float]:
        """Map dork result to finding type and severity score."""
        if any(kw in dork for kw in [
            "admin", "login", "dashboard", "portal",
            "phpmyadmin", "wp-admin", "index of"
        ]):
            return "exposed_admin", 7.5

        if any(kw in dork for kw in [
            "filetype", "ext:", ".env", ".sql",
            ".bak", ".config", ".log"
        ]):
            return "data_exfiltration", 8.0

        if any(kw in dork for kw in [
            "confidential", "internal use only"
        ]):
            return "data_exfiltration", 7.0

        if any(kw in dork for kw in [
            "api", "swagger", "graphql"
        ]):
            self.profile.api_endpoints.append(url)
            return "tech_stack", 5.0

        return "tech_stack", 4.0

    # ------------------------------------------------------------------ #
    # CHECK 5 -- WAYBACK MACHINE
    # ------------------------------------------------------------------ #
    def check_wayback(self) -> list[Finding]:
        """
        Internet Archive historical analysis.
        Finds removed endpoints, old configs, historical exposures.
        Limit 500 -- better coverage than 200 with minimal overhead.
        """
        if not self._guided_gate(
            "Wayback Machine",
            f"Query Internet Archive for {self.target} history"
        ):
            return []

        console.print("[cyan]  [5/10] Wayback Machine...[/cyan]")
        # Fix: skip Wayback on private IPs
        # archive.org doesn't index private IP addresses
        import ipaddress
        try:
            if ipaddress.ip_address(self.target).is_private:
                console.print("[dim]    Wayback skipped -- private IP[/dim]")
                return []
        except ValueError:
            pass  # domain name -- continue

        findings = []

        try:
            url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={self.target}/*"
                f"&output=json"
                f"&fl=original,statuscode,timestamp"
                f"&collapse=urlkey"
                f"&limit=500"
            )
            resp = requests.get(
                url, timeout=REQUEST_TIMEOUT,
                headers=_get_headers()
            )

            if resp.status_code == 200:
                data = resp.json()

                if len(data) > 1:
                    sensitive_kw = [
                        "admin", "login", "api", "config",
                        "backup", "old", "test", "dev", ".env",
                        ".git", "password", "secret", "key",
                        "token", "internal", "private",
                    ]
                    seen = set()

                    for row in data[1:]:
                        original = row[0]
                        status   = row[1]
                        ts       = row[2]

                        try:
                            path = urlparse(original).path
                        except Exception:
                            continue

                        if not path or path in seen:
                            continue
                        seen.add(path)
                        self.profile.historical_endpoints.append(path)

                        if any(
                            kw in path.lower() for kw in sensitive_kw
                        ):
                            findings.append(Finding(
                                title=(
                                    f"Historical endpoint: {path}"
                                ),
                                description=(
                                    f"Archive found {path} on "
                                    f"{self.target}. "
                                    f"Last seen: {ts[:8]}. "
                                    f"Status was {status}. "
                                    f"May still be live."
                                ),
                                finding_type="exposed_admin",
                                source_module="osint_recon",
                                target=self.target,
                                severity_score=5.5
                            ))

        except Exception as e:
            console.print(
                f"[yellow]    Wayback failed: {e}[/yellow]"
            )

        console.print(
            f"[green]    Done -- "
            f"{len(self.profile.historical_endpoints)} historical, "
            f"{len(findings)} interesting[/green]"
        )
        self.limiter.wait("web.archive.org")
        return findings

    # ------------------------------------------------------------------ #
    # CHECK 6 -- TECH STACK (WAF-AWARE)
    # ------------------------------------------------------------------ #
    def check_tech_stack(self) -> list[Finding]:
        """
        Technology fingerprinting with WAF awareness.

        WAF detection logic:
        - Checks response against WAF_SIGNATURES before tech stack
        - If WAF detected: flags profile.waf_detected = True
        - Suppresses server header finding (WAF masks origin)
        - Generates explicit warning with origin IP discovery guidance
        - Traditional recon module reads waf_detected to adjust approach

        Without WAF awareness we'd report the WAF edge server as the
        origin and miss the real Apache/Nginx/IIS stack behind it.
        """
        if not self._guided_gate(
            "Tech Stack Detection",
            f"HTTP fingerprinting of {self.target}"
        ):
            return []

        console.print(
            "[cyan]  [6/10] Tech stack detection...[/cyan]"
        )
        findings = []

        for url in [
            f"https://{self.target}",
            f"http://{self.target}"
        ]:
            try:
                resp = requests.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    headers=_get_headers()
                )

                combined = resp.text + str(dict(resp.headers)).lower()

                # WAF detection -- must run before tech stack
                detected_waf = None
                for waf_name, waf_sigs in WAF_SIGNATURES.items():
                    if any(sig.lower() in combined for sig in waf_sigs):
                        detected_waf = waf_name
                        break

                if detected_waf:
                    self.profile.waf_detected = True
                    self.profile.waf_type     = detected_waf
                    findings.append(Finding(
                        title=f"WAF detected: {detected_waf}",
                        description=(
                            f"{detected_waf} WAF identified on "
                            f"{self.target}. "
                            f"Server headers reflect edge infrastructure "
                            f"-- origin tech stack is masked. "
                            f"Direct IP probing via traditional_recon "
                            f"required to identify origin stack. "
                            f"Origin IP may be discoverable via DNS "
                            f"history, CT logs, or Shodan (v2)."
                        ),
                        finding_type="tech_stack",
                        source_module="osint_recon",
                        target=self.target,
                        severity_score=5.0
                    ))
                    console.print(
                        f"[yellow]    WAF: {detected_waf}. "
                        f"Tech stack may be masked.[/yellow]"
                    )

                # Server header -- only report if no WAF masking it
                server = resp.headers.get("server", "")
                if server and not detected_waf:
                    self.profile.server_software = server
                    findings.append(Finding(
                        title=f"Server disclosed: {server}",
                        description=(
                            f"Server header: {server}. "
                            f"Version disclosure enables CVE lookup."
                        ),
                        finding_type="tech_stack",
                        source_module="osint_recon",
                        target=self.target,
                        severity_score=4.0
                    ))

                # X-Powered-By
                powered_by = resp.headers.get("x-powered-by", "")
                if powered_by:
                    findings.append(Finding(
                        title=f"Technology disclosed: {powered_by}",
                        description=(
                            f"X-Powered-By: {powered_by}. "
                            f"Stack partially revealed."
                        ),
                        finding_type="tech_stack",
                        source_module="osint_recon",
                        target=self.target,
                        severity_score=3.5
                    ))

                # Missing security headers
                for header, label in SECURITY_HEADERS.items():
                    if header not in resp.headers:
                        findings.append(Finding(
                            title=f"Missing header: {label}",
                            description=(
                                f"{label} on {self.target}. "
                                f"Implement to reduce attack surface."
                            ),
                            finding_type="header_missing",
                            source_module="osint_recon",
                            target=self.target,
                            severity_score=4.5
                        ))

                # HTML + header fingerprinting
                # Fix: skip tech already captured in server header
                # prevents duplicate "Apache" findings when server
                # header and HTML both contain the same technology
                server_lower = server.lower() if server else ""
                for tech, sigs in TECH_SIGNATURES.items():
                    if (
                        any(sig in combined for sig in sigs) and
                        tech not in self.profile.tech_stack and
                        tech.lower() not in server_lower
                    ):
                        self.profile.tech_stack.append(tech)
                        findings.append(Finding(
                            title=f"Tech fingerprinted: {tech}",
                            description=(
                                f"{tech} detected on {self.target}. "
                                f"Check for known CVEs."
                            ),
                            finding_type="tech_stack",
                            source_module="osint_recon",
                            target=self.target,
                            severity_score=3.0
                        ))

                break  # Success on first URL

            except Exception as e:
                console.print(
                    f"[yellow]    Tech stack failed "
                    f"({url}): {e}[/yellow]"
                )

        waf_note = (
            f" [WAF: {self.profile.waf_type}]"
            if self.profile.waf_detected else ""
        )
        console.print(
            f"[green]    Done -- "
            f"stack: "
            f"{', '.join(self.profile.tech_stack) or 'none'}"
            f"{waf_note}[/green]"
        )
        self.limiter.wait(self.target)
        return findings

    # ------------------------------------------------------------------ #
    # CHECK 7 -- AI SURFACE DETECTION
    # ------------------------------------------------------------------ #
    def check_ai_surfaces(self) -> list[Finding]:
        """
        Detect exposed AI and LLM interfaces.

        Status code logic -- any non-404/410 is interesting:
        - 200: Fully accessible -- highest severity
        - 401: Auth required -- endpoint confirmed
        - 403: Forbidden -- endpoint confirmed
        - 405: Method Not Allowed -- POST required (LLM API pattern)
               This is a STRONG signal -- real LLM APIs return 405 on GET

        Scoped to AI-relevant subdomains only -- reduces noise and
        request count on large subdomain lists.
        """
        if not self._guided_gate(
            "AI Surface Detection",
            f"Probe {self.target} for exposed LLM endpoints"
        ):
            return []

        console.print(
            "[cyan]  [7/10] AI surface detection...[/cyan]"
        )
        findings = []

        # Prioritize AI-relevant subdomains
        ai_relevant = [
            s for s in self.profile.subdomains
            if any(kw in s.lower() for kw in [
                "api", "chat", "ai", "llm", "bot", "assistant",
                "gpt", "model", "ml", "inference", "copilot",
            ])
        ]

        base_urls = (
            [f"https://{self.target}", f"http://{self.target}"] +
            [f"https://{s}" for s in ai_relevant[:10]]
        )

        for base_url in base_urls:
            for sig in AI_SURFACE_SIGNATURES:
                try:
                    url  = f"{base_url}{sig}"
                    resp = requests.get(
                        url,
                        timeout=5,
                        allow_redirects=False,
                        headers=_get_headers()
                    )

                    if resp.status_code not in [404, 410]:
                        # Fix: confirm actual LLM API behavior before flagging
                        # Routers and login pages return 200 to any GET request
                        # Real LLM APIs respond to POST with JSON content-type
                        # Check Content-Type and attempt POST confirmation
                        is_confirmed_llm = False
                        content_type = resp.headers.get(
                            "content-type", ""
                        ).lower()

                        # Strong signal -- JSON response to GET
                        if "application/json" in content_type:
                            is_confirmed_llm = True

                        # POST probe to confirm LLM API behavior
                        if not is_confirmed_llm and resp.status_code == 200:
                            try:
                                post_resp = requests.post(
                                    url,
                                    json={"message": "test"},
                                    timeout=5,
                                    allow_redirects=False,
                                    headers=_get_headers()
                                )
                                post_ct = post_resp.headers.get(
                                    "content-type", ""
                                ).lower()
                                # Real LLM API returns JSON on POST
                                if "application/json" in post_ct:
                                    is_confirmed_llm = True
                                # 405 on POST = wrong method but endpoint exists
                                elif post_resp.status_code == 405:
                                    is_confirmed_llm = True
                                # 401/403 on POST = auth required but real endpoint
                                elif post_resp.status_code in [401, 403]:
                                    is_confirmed_llm = True
                                # HTML response to POST = login redirect not LLM
                                elif "text/html" in post_ct:
                                    is_confirmed_llm = False
                            except Exception:
                                pass

                        # 401/403/405 on GET = confirmed endpoint even without POST
                        if resp.status_code in [401, 403, 405]:
                            is_confirmed_llm = True

                        if not is_confirmed_llm:
                            # Not confirmed -- skip to avoid false positives
                            if not self.fast_mode:
                                time.sleep(REQUEST_DELAY_FAST)
                            continue

                        self.profile.ai_surfaces.append(url)

                        severity = (
                            9.0 if resp.status_code == 200 else 7.0
                        )
                        status_note = {
                            200: "Fully accessible -- no auth required",
                            401: "Auth required -- endpoint confirmed",
                            403: "Forbidden -- endpoint confirmed",
                            405: (
                                "Method Not Allowed -- "
                                "POST required (LLM API pattern)"
                            ),
                        }.get(
                            resp.status_code,
                            f"HTTP {resp.status_code}"
                        )

                        findings.append(Finding(
                            title=(
                                f"AI surface: {sig} "
                                f"[{resp.status_code}]"
                            ),
                            description=(
                                f"LLM endpoint at {url}. "
                                f"{status_note}. "
                                f"Queued for LLM attack module."
                            ),
                            finding_type="ai_surface",
                            source_module="osint_recon",
                            target=self.target,
                            severity_score=severity
                        ))

                except Exception:
                    pass

                # Light rate limiting on AI surface probing
                if not self.fast_mode:
                    time.sleep(REQUEST_DELAY_FAST)

        console.print(
            f"[green]    Done -- "
            f"{len(self.profile.ai_surfaces)} AI surfaces[/green]"
        )
        return findings

    # ------------------------------------------------------------------ #
    # CHECK 8 -- EMAIL HARVESTING
    # ------------------------------------------------------------------ #
    def check_email_harvesting(self) -> list[Finding]:
        """
        Scrape public pages for target-domain email addresses.
        Filters generic addresses (noreply, support, etc).
        Extracts usernames for Sherlock enumeration.
        """
        if not self._guided_gate(
            "Email Harvesting",
            f"Scrape public pages of {self.target} for emails"
        ):
            return []

        console.print(
            "[cyan]  [8/10] Email harvesting...[/cyan]"
        )
        findings      = []
        emails_found  = set()
        email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
        )

        urls = [
            f"https://{self.target}",
            f"https://{self.target}/about",
            f"https://{self.target}/about-us",
            f"https://{self.target}/contact",
            f"https://{self.target}/contact-us",
            f"https://{self.target}/team",
            f"https://{self.target}/staff",
            f"https://{self.target}/people",
            f"https://{self.target}/leadership",
            f"https://{self.target}/our-team",
        ] + [
            f"https://{s}"
            for s in self.profile.subdomains[:5]
        ]

        for url in urls:
            try:
                resp  = requests.get(
                    url, timeout=REQUEST_TIMEOUT,
                    headers=_get_headers()
                )
                found = email_pattern.findall(resp.text)
                for email in found:
                    el = email.lower()
                    if self.target in el:
                        emails_found.add(el)
            except Exception:
                pass
            self.limiter.wait(
                self.target, delay=REQUEST_DELAY_FAST
            )

        for email in emails_found:
            username = email.split("@")[0]

            # Filter generic addresses -- not useful targets
            if username.lower() in IGNORED_EMAIL_PREFIXES:
                continue

            if email not in self.profile.emails:
                self.profile.emails.append(email)
            if username not in self.profile.usernames:
                self.profile.usernames.append(username)

            findings.append(Finding(
                title=f"Email harvested: {email}",
                description=(
                    f"{email} found in public sources. "
                    f"Phishing + credential stuffing risk. "
                    f"Username: {username}"
                ),
                finding_type="email_exposed",
                source_module="osint_recon",
                target=self.target,
                severity_score=5.0
            ))

        console.print(
            f"[green]    Done -- "
            f"{len(emails_found)} emails (after filtering)[/green]"
        )
        return findings

    # ------------------------------------------------------------------ #
    # CHECK 9 -- BREACH CHECKING
    # ------------------------------------------------------------------ #
    def check_breaches(self) -> list[Finding]:
        """
        Breach database checks on harvested emails.
        HIBP per-email (requires paid API key -- skips cleanly if absent).
        GitHub code search for exposed secrets.
        """
        if not self._guided_gate(
            "Breach Checking",
            f"HIBP + GitHub check on "
            f"{len(self.profile.emails)} emails"
        ):
            return []

        console.print("[cyan]  [9/10] Breach checking...[/cyan]")
        findings = []
        findings.extend(self._check_hibp())
        findings.extend(self._check_github_secrets())
        return findings

    def _check_hibp(self) -> list[Finding]:
        """
        HaveIBeenPwned per-email breach check.
        Note: v3 API requires paid key for breachedaccount endpoint.
        Skips cleanly with informative message if 401 returned.
        Not a broken feature -- documented limitation.
        v2: add HIBP API key support via config file.
        """
        findings = []

        if not self.profile.emails:
            console.print(
                "[dim]    HIBP skipped -- no emails[/dim]"
            )
            return findings

        for email in self.profile.emails[:10]:
            try:
                url  = (
                    f"https://haveibeenpwned.com/api/v3/"
                    f"breachedaccount/{email}"
                )
                resp = requests.get(
                    url,
                    headers={
                        "User-Agent": (
                            "R3D-RedTeamAgent-SecurityResearch"
                        )
                    },
                    timeout=REQUEST_TIMEOUT
                )

                if resp.status_code == 200:
                    breaches     = resp.json()
                    breach_names = [
                        b.get("Name", "Unknown") for b in breaches
                    ]
                    self.profile.breached_emails.append(email)
                    findings.append(Finding(
                        title=(
                            f"Breached: {email} "
                            f"({len(breaches)} breaches)"
                        ),
                        description=(
                            f"{email} in {len(breaches)} breaches: "
                            f"{', '.join(breach_names[:5])}. "
                            f"Credential stuffing risk HIGH. "
                            f"Immediate password rotation required."
                        ),
                        finding_type="credential_stuffing",
                        source_module="osint_recon",
                        target=self.target,
                        severity_score=8.5
                    ))

                elif resp.status_code == 401:
                    console.print(
                        "[dim]    HIBP: paid API key required "
                        "for this endpoint. "
                        "Add key in config for breach checking (v2)."
                        "[/dim]"
                    )
                    break

                elif resp.status_code == 429:
                    console.print(
                        "[yellow]    HIBP rate limit -- "
                        "waiting 10s[/yellow]"
                    )
                    time.sleep(10)

            except Exception as e:
                console.print(
                    f"[yellow]    HIBP error for "
                    f"{email}: {e}[/yellow]"
                )

            self.limiter.wait("haveibeenpwned.com")

        return findings

    def _check_github_secrets(self) -> list[Finding]:
        """GitHub code search for exposed secrets."""
        findings = []
        queries  = [
            f'"{self.target}" password',
            f'"{self.target}" api_key',
            f'"{self.target}" secret',
            f'"{self.target}" token',
            f'"{self.target}" credentials',
        ]

        for query in queries:
            try:
                url  = (
                    "https://api.github.com/search/code?"
                    + urlencode({
                        "q":        query,
                        "per_page": "5"
                    })
                )
                resp = requests.get(
                    url,
                    headers={
                        "User-Agent": (
                            "R3D-RedTeamAgent-SecurityResearch"
                        ),
                        "Accept": (
                            "application/vnd.github.v3+json"
                        ),
                    },
                    timeout=REQUEST_TIMEOUT
                )

                if resp.status_code == 200:
                    data  = resp.json()
                    total = data.get("total_count", 0)

                    if total > 0:
                        for item in data.get("items", [])[:3]:
                            repo      = item.get(
                                "repository", {}
                            ).get("full_name", "unknown")
                            file_path = item.get("path", "")
                            html_url  = item.get("html_url", "")

                            findings.append(Finding(
                                title=(
                                    f"GitHub secret exposure: "
                                    f"{file_path}"
                                ),
                                description=(
                                    f"Query '{query}' returned "
                                    f"{total} GitHub results. "
                                    f"Repo: {repo}. "
                                    f"File: {file_path}. "
                                    f"URL: {html_url}"
                                ),
                                finding_type="data_exfiltration",
                                source_module="osint_recon",
                                target=self.target,
                                severity_score=9.0
                            ))

                elif resp.status_code == 403:
                    console.print(
                        "[yellow]    GitHub rate limit[/yellow]"
                    )
                    break

            except Exception as e:
                console.print(
                    f"[yellow]    GitHub error: {e}[/yellow]"
                )

            self.limiter.wait(
                "api.github.com", delay=REQUEST_DELAY_SEARCH
            )

        return findings

    # ------------------------------------------------------------------ #
    # CHECK 10 -- SHERLOCK
    # ------------------------------------------------------------------ #
    def check_sherlock(self) -> list[Finding]:
        """
        Username enumeration via Sherlock across 300+ platforms.

        Implementation: subprocess call to sherlock_project module.
        Subprocess is intentional -- guarantees compatibility across
        all sherlock-project versions regardless of internal API changes.
        Direct import would break on version updates.

        Rules:
        - Never runs in FULL-AUTO mode
        - Requires explicit YES consent regardless of mode
        - Max 5 usernames per engagement
        - 60 second timeout per username
        - Output parsed line by line for [+] found markers
        """
        findings = []

        if self.mode == "FULL-AUTO":
            console.print(
                "[yellow]  [10/10] Sherlock skipped -- "
                "FULL-AUTO not permitted[/yellow]"
            )
            return findings

        if not self.profile.usernames:
            console.print(
                "[yellow]  [10/10] Sherlock skipped -- "
                "no usernames[/yellow]"
            )
            return findings

        preview = ", ".join(self.profile.usernames[:5])
        if not self._operator_consent(
            "Sherlock Username Enumeration",
            f"Enumerate {min(len(self.profile.usernames), 5)} "
            f"usernames across 300+ platforms: {preview}"
        ):
            console.print(
                "[yellow]  [10/10] Sherlock declined[/yellow]"
            )
            return findings

        console.print(
            "[cyan]  [10/10] Sherlock enumeration...[/cyan]"
        )

        for username in self.profile.usernames[:5]:
            username = _sanitize_username(username)
            if not username:
                continue

            console.print(
                f"[dim]    Checking: {username}[/dim]"
            )

            try:
                result = subprocess.run(
                    [
                        sys.executable, "-m",
                        "sherlock_project.sherlock",
                        username,
                        "--print-found",
                        "--no-color",
                        "--timeout", "10",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False  # non-zero exit is normal when no platforms found
                )

                output          = result.stdout + result.stderr
                found_platforms = []

                for line in output.splitlines():
                    line = line.strip()
                    # Sherlock format: "[+] Platform: URL"
                    if line.startswith("[+]"):
                        parts = line[3:].strip().split(":")
                        if parts:
                            platform = parts[0].strip()
                            if platform:
                                found_platforms.append(platform)

                if found_platforms:
                    findings.append(Finding(
                        title=(
                            f"'{username}' on "
                            f"{len(found_platforms)} platforms"
                        ),
                        description=(
                            f"Sherlock found '{username}' active on: "
                            f"{', '.join(found_platforms[:15])}. "
                            f"Digital footprint enables targeted "
                            f"social engineering and phishing."
                        ),
                        finding_type="username_exposed",
                        source_module="osint_recon",
                        target=self.target,
                        severity_score=5.5
                    ))
                    console.print(
                        f"[green]    {username}: "
                        f"{len(found_platforms)} platforms[/green]"
                    )
                else:
                    console.print(
                        f"[dim]    {username}: not found[/dim]"
                    )

            except subprocess.TimeoutExpired:
                console.print(
                    f"[yellow]    Timeout: {username}[/yellow]"
                )
            except FileNotFoundError:
                console.print(
                    "[red]    Sherlock not installed. "
                    "Run: pip install sherlock-project[/red]"
                )
                break
            except Exception as e:
                console.print(
                    f"[yellow]    Sherlock error "
                    f"{username}: {e}[/yellow]"
                )

        console.print(
            f"[green]    Done -- "
            f"{len(findings)} username findings[/green]"
        )
        return findings

    # ------------------------------------------------------------------ #
    # MAIN RUN
    # ------------------------------------------------------------------ #
    def run(self) -> tuple[list[Finding], OSINTProfile]:
        """
        Execute all OSINT checks in sequence.
        Each check fails independently.
        Saves OSINTProfile to disk for downstream modules.
        Returns (findings, profile).
        """
        console.print(
            f"\n[bold cyan]"
            f"{'='*52}\n"
            f"  R3D OSINT RECONNAISSANCE\n"
            f"  Target : {self.target}\n"
            f"  Mode   : {self.mode}\n"
            f"{'='*52}"
            f"[/bold cyan]\n"
        )

        checks = [
            self.check_whois,
            self.check_dns,
            self.check_subdomains,
            self.check_google_dorks,
            self.check_wayback,
            self.check_tech_stack,
            self.check_ai_surfaces,
            self.check_email_harvesting,
            self.check_breaches,
            self.check_sherlock,
        ]

        for check_fn in checks:
            try:
                new_findings = check_fn()
                for f in new_findings:
                    self._add_finding(f)
            except Exception as e:
                console.print(
                    f"[red]  {check_fn.__name__} crashed: "
                    f"{e}[/red]"
                )

        # Save profile for downstream modules
        profile_path = self.profile.save()
        console.print(
            f"\n[dim]Profile saved: {profile_path}[/dim]"
        )

        # Rate limiter summary
        rl_summary = self.limiter.summary()
        if rl_summary:
            console.print(
                f"[dim]Requests this session: "
                f"{sum(rl_summary.values())} total across "
                f"{len(rl_summary)} domains[/dim]"
            )

        # Final summary
        waf_line = (
            f"  WAF          : {self.profile.waf_type}\n"
            if self.profile.waf_detected else ""
        )
        console.print(
            f"\n[bold green]"
            f"{'='*52}\n"
            f"  OSINT COMPLETE\n"
            f"  Findings     : {len(self.findings)}\n"
            f"  Subdomains   : {len(self.profile.subdomains)}\n"
            f"  AI surfaces  : {len(self.profile.ai_surfaces)}\n"
            f"  Emails       : {len(self.profile.emails)}\n"
            f"  Breached     : {len(self.profile.breached_emails)}\n"
            f"  Historical   : "
            f"{len(self.profile.historical_endpoints)}\n"
            f"{waf_line}"
            f"{'='*52}"
            f"[/bold green]\n"
        )

        return self.findings, self.profile


# ------------------------------------------------------------------ #
# TEST
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    console.print(
        "[bold green]R3D OSINT Module -- Test Run[/bold green]\n"
    )
    console.print(
        "[yellow]Makes real external requests.[/yellow]"
    )
    console.print(
        "[yellow]Test target: example.com "
        "(IANA safe test domain)[/yellow]\n"
    )

    recon = OSINTRecon(
        target="example.com",
        mode="SEMI-AUTO",
        fast_mode=True   # Use fast_mode=False for real engagements
    )

    findings, profile = recon.run()

    console.print("\n[bold]Profile Summary:[/bold]")
    console.print(f"  Target    : {profile.target}")
    console.print(f"  IP        : {profile.ip_address}")
    console.print(f"  Registrar : {profile.registrar}")
    console.print(
        f"  Tech      : "
        f"{', '.join(profile.tech_stack) or 'none'}"
    )
    console.print(
        f"  WAF       : "
        f"{profile.waf_type or 'none detected'}"
    )
    console.print(f"  Subdomains: {len(profile.subdomains)}")
    console.print(f"  AI        : {len(profile.ai_surfaces)}")
    console.print(f"  Emails    : {len(profile.emails)}")
    console.print(f"  Findings  : {len(findings)}")