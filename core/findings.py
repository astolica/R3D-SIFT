"""
R3D Agent — Findings Aggregator
Collects findings from all four modules, deduplicates,
scores severity, maps to MITRE ATT&CK and OWASP,
prioritizes zero day flags, and produces a clean
structured list for the report generator.

Frameworks mapped:
- MITRE ATT&CK (attack techniques)
- OWASP Top 10 Web (web vulnerabilities)
- OWASP LLM Top 10 (AI/LLM vulnerabilities)

Security fixes applied:
- Deterministic ID generation via hashlib.md5
- Pydantic field validators on title/description/finding_type
- Error handling on file save operations
- Corrected MITRE mapping for prompt injection
- TODO marker for GRC context scoring in v2

Compatibility: Windows 10/11, Ubuntu, Kali Linux, macOS
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, List
from pydantic import BaseModel, field_validator
from rich.console import Console
from rich.table import Table

console = Console()

# Output path
BASE_DIR = Path(__file__).parent.parent
FINDINGS_OUTPUT_PATH = BASE_DIR / "output"

# MITRE ATT&CK mapping — finding type to technique
# Reference: https://attack.mitre.org
MITRE_MAPPING = {
    "prompt_injection":         ("T1190", "Exploit Public-Facing Application"),
    "jailbreak":                ("T1059", "Command and Scripting Interpreter"),
    "trust_escalation":         ("T1078", "Valid Accounts"),
    "context_manipulation":     ("T1565", "Data Manipulation"),
    "data_exfiltration":        ("T1041", "Exfiltration Over C2 Channel"),
    "subdomain":                ("T1590.001", "DNS — Domain Properties"),
    "exposed_port":             ("T1046", "Network Service Discovery"),
    "exposed_admin":            ("T1190", "Exploit Public-Facing Application"),
    "outdated_ssl":             ("T1557", "Adversary-in-the-Middle"),
    "cve_match":                ("T1190", "Exploit Public-Facing Application"),
    "ai_surface":               ("T1590", "Gather Victim Network Information"),
    "email_exposed":            ("T1589.002", "Email Addresses"),
    "tech_stack":               ("T1592", "Gather Victim Host Information"),
    "username_exposed":         ("T1589.003", "Employee Names"),
    "zero_day":                 ("T1190", "Exploit Public-Facing Application"),
    "header_missing":           ("T1190", "Exploit Public-Facing Application"),
    "crescendo_attack":         ("T1078", "Valid Accounts"),
    "credential_stuffing":      ("T1110.004", "Credential Stuffing"),
    "default":                  ("T1592", "Gather Victim Host Information"),
}

# OWASP mapping — finding type to OWASP category
# LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications
# Web Top 10: https://owasp.org/www-project-top-ten
OWASP_MAPPING = {
    # OWASP LLM Top 10
    "prompt_injection":         ("LLM01", "Prompt Injection"),
    "jailbreak":                ("LLM01", "Prompt Injection"),
    "trust_escalation":         ("LLM02", "Insecure Output Handling"),
    "context_manipulation":     ("LLM01", "Prompt Injection"),
    "data_exfiltration":        ("LLM06", "Sensitive Information Disclosure"),
    "ai_surface":               ("LLM09", "Misinformation"),
    "crescendo_attack":         ("LLM01", "Prompt Injection"),

    # OWASP Web Top 10
    "exposed_admin":            ("A05", "Security Misconfiguration"),
    "outdated_ssl":             ("A02", "Cryptographic Failures"),
    "cve_match":                ("A06", "Vulnerable and Outdated Components"),
    "zero_day":                 ("A06", "Vulnerable and Outdated Components"),
    "header_missing":           ("A05", "Security Misconfiguration"),
    "exposed_port":             ("A05", "Security Misconfiguration"),
    "subdomain":                ("A05", "Security Misconfiguration"),
    "email_exposed":            ("A07", "Identification and Authentication Failures"),
    "username_exposed":         ("A07", "Identification and Authentication Failures"),
    "tech_stack":               ("A05", "Security Misconfiguration"),
    "credential_stuffing":      ("A07", "Identification and Authentication Failures"),
    "default":                  ("A05", "Security Misconfiguration"),
}

# Severity base scores by finding type (1-10)
# Adjusted by CVE CVSS score and zero day flag during scoring
BASE_SEVERITY = {
    "prompt_injection":     8,
    "jailbreak":            7,
    "trust_escalation":     9,
    "context_manipulation": 7,
    "data_exfiltration":    9,
    "crescendo_attack":     8,
    "zero_day":             9,
    "cve_match":            7,
    "exposed_admin":        8,
    "outdated_ssl":         6,
    "exposed_port":         5,
    "header_missing":       4,
    "subdomain":            3,
    "ai_surface":           6,
    "email_exposed":        5,
    "username_exposed":     4,
    "tech_stack":           3,
    "credential_stuffing":  7,
    "default":              3,
}


class Finding(BaseModel):
    """
    Single finding from any module.
    All four modules produce findings in this exact shape.
    Pydantic enforces field types and length limits.
    """
    # Core fields
    id: Optional[str] = None
    title: str
    description: str
    finding_type: str
    source_module: str      # "osint" | "llm_attack" | "traditional" | "grc"
    target: str

    # Severity
    severity_score: float = 0.0
    severity_label: str = "INFO"    # CRITICAL | HIGH | MEDIUM | LOW | INFO

    # Framework mappings
    mitre_technique: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    owasp_category: Optional[str] = None
    owasp_category_name: Optional[str] = None

    # CVE data (if applicable)
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None

    # Zero day flag
    zero_day_flag: bool = False
    evidence_preserved: bool = False
    raw_evidence_path: Optional[str] = None

    # Metadata
    timestamp: str = ""
    remediation: Optional[str] = None

    @field_validator('title')
    @classmethod
    def title_max_length(cls, v):
        """Cap title at 200 characters — prevents bloated PDF output."""
        return v[:200] if len(v) > 200 else v

    @field_validator('description')
    @classmethod
    def description_max_length(cls, v):
        """Cap description at 2000 characters."""
        return v[:2000] if len(v) > 2000 else v

    @field_validator('finding_type')
    @classmethod
    def finding_type_normalize(cls, v):
        """
        Force finding_type lowercase and stripped.
        Ensures 'Prompt_Injection' and 'prompt_injection'
        both match the same mapping key.
        """
        return v.lower().strip()

    def model_post_init(self, __context):
        """
        After construction: if severity_score was not set (still 0.0)
        look it up from BASE_SEVERITY table using finding_type.

        Fix: default severity_score=0.0 caused findings with no
        explicit score to land as INFO regardless of their type.
        A prompt_injection with no score is still an 8, not a 0.
        """
        if self.severity_score == 0.0 and self.finding_type:
            base = BASE_SEVERITY.get(
                self.finding_type,
                BASE_SEVERITY["default"]
            )
            # Use object.__setattr__ because pydantic model is frozen
            try:
                object.__setattr__(self, 'severity_score', float(base))
            except Exception:
                pass


class AggregatedFindings(BaseModel):
    """
    Complete findings package ready for report generation.
    Output of the aggregator, input to the report generator.
    """
    target: str
    scan_timestamp: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    zero_day_count: int
    findings: List[Finding]


class FindingsAggregator:
    """
    Collects, deduplicates, scores, maps, and prioritizes findings
    from all four R3D modules.
    """

    def __init__(self, target: str):
        self.target = target
        self.raw_findings: List[Finding] = []
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    def add_finding(self, finding: Finding):
        """Add a single finding from any module."""
        finding.timestamp = self.timestamp
        finding.id = self._generate_id(finding)
        self.raw_findings.append(finding)

    def add_findings(self, findings: List[Finding]):
        """Add multiple findings at once."""
        for finding in findings:
            self.add_finding(finding)

    def _generate_id(self, finding: Finding) -> str:
        """
        Generate a deterministic unique ID for deduplication.
        Uses hashlib.md5 — consistent across runs and platforms.
        Same finding from two modules = same ID = deduplicated.

        NOT using Python's built-in hash() — it is not deterministic
        across runs (changes each Python startup by design).
        """
        key = f"{finding.finding_type}:{finding.target}:{finding.title}"
        return hashlib.md5(key.encode()).hexdigest()[:8]

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """
        Remove duplicate findings.
        If same finding ID from multiple modules,
        keep the one with the highest severity score.
        """
        seen = {}
        for finding in findings:
            if finding.id not in seen:
                seen[finding.id] = finding
            else:
                if finding.severity_score > seen[finding.id].severity_score:
                    seen[finding.id] = finding
        return list(seen.values())

    def _score_severity(self, finding: Finding) -> Finding:
        """
        Calculate final severity score.

        Scoring logic:
        1. Start with base score for finding type
        2. If CVE match — use CVSS score if higher than base
        3. If zero day flag — elevate to minimum 9.0
        4. Assign severity label

        TODO v2 — incorporate GRC context (NERC CIP asset classification)
        into severity scoring. Critical infrastructure findings should
        receive a multiplier based on asset criticality rating.
        """
        base = BASE_SEVERITY.get(finding.finding_type, 3)
        score = float(base)

        # CVSS adjustment
        if finding.cvss_score and finding.cvss_score > score:
            score = finding.cvss_score

        # Zero day elevation
        if finding.zero_day_flag:
            score = max(score, 9.0)

        finding.severity_score = round(score, 1)

        # Assign label
        if score >= 9.0:
            finding.severity_label = "CRITICAL"
        elif score >= 7.0:
            finding.severity_label = "HIGH"
        elif score >= 5.0:
            finding.severity_label = "MEDIUM"
        elif score >= 3.0:
            finding.severity_label = "LOW"
        else:
            finding.severity_label = "INFO"

        return finding

    def _map_frameworks(self, finding: Finding) -> Finding:
        """
        Map finding to MITRE ATT&CK and OWASP frameworks.
        Falls back to default if specific type not in mapping.
        """
        mitre = MITRE_MAPPING.get(
            finding.finding_type,
            MITRE_MAPPING["default"]
        )
        finding.mitre_technique = mitre[0]
        finding.mitre_technique_name = mitre[1]

        owasp = OWASP_MAPPING.get(
            finding.finding_type,
            OWASP_MAPPING["default"]
        )
        finding.owasp_category = owasp[0]
        finding.owasp_category_name = owasp[1]

        return finding

    def _prioritize(self, findings: List[Finding]) -> List[Finding]:
        """
        Sort findings by priority:
        1. Zero day flags always first
        2. Severity score descending
        3. Alphabetical tiebreaker
        """
        return sorted(
            findings,
            key=lambda f: (
                not f.zero_day_flag,
                -f.severity_score,
                f.finding_type
            )
        )

    def _count_by_severity(self, findings: List[Finding]) -> tuple:
        """Count findings by severity label."""
        critical = sum(1 for f in findings if f.severity_label == "CRITICAL")
        high = sum(1 for f in findings if f.severity_label == "HIGH")
        medium = sum(1 for f in findings if f.severity_label == "MEDIUM")
        low = sum(1 for f in findings if f.severity_label == "LOW")
        info = sum(1 for f in findings if f.severity_label == "INFO")
        zero_days = sum(1 for f in findings if f.zero_day_flag)
        return critical, high, medium, low, info, zero_days

    def aggregate(self) -> AggregatedFindings:
        """
        Run the full aggregation pipeline:
        1. Score all findings
        2. Map to MITRE + OWASP
        3. Deduplicate
        4. Prioritize
        5. Return clean AggregatedFindings package
        """
        console.print(
            f"\n[bold cyan]Aggregating {len(self.raw_findings)} "
            f"raw findings...[/bold cyan]"
        )

        # Step 1 — Score and map every finding
        processed = []
        for finding in self.raw_findings:
            finding = self._score_severity(finding)
            finding = self._map_frameworks(finding)
            processed.append(finding)

        # Step 2 — Deduplicate
        deduplicated = self._deduplicate(processed)
        removed = len(processed) - len(deduplicated)
        if removed > 0:
            console.print(
                f"[yellow]→ Removed {removed} duplicate "
                f"findings[/yellow]"
            )

        # Step 3 — Prioritize
        prioritized = self._prioritize(deduplicated)

        # Step 4 — Count by severity
        critical, high, medium, low, info, zero_days = \
            self._count_by_severity(prioritized)

        console.print(
            f"[green]✓ Aggregation complete — "
            f"{len(prioritized)} findings[/green]"
        )

        self._display_summary(
            prioritized, critical, high, medium, low, info, zero_days
        )

        return AggregatedFindings(
            target=self.target,
            scan_timestamp=self.timestamp,
            total_findings=len(prioritized),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
            zero_day_count=zero_days,
            findings=prioritized
        )

    def _display_summary(
        self,
        findings: List[Finding],
        critical: int,
        high: int,
        medium: int,
        low: int,
        info: int,
        zero_days: int
    ):
        """Display rich summary table in terminal."""
        console.print()

        table = Table(title=f"R3D Findings Summary — {self.target}")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        if zero_days > 0:
            table.add_row(
                "[bold red]⚠ ZERO DAY FLAGS[/bold red]",
                f"[bold red]{zero_days}[/bold red]"
            )
        table.add_row("[bold red]CRITICAL[/bold red]", str(critical))
        table.add_row("[red]HIGH[/red]", str(high))
        table.add_row("[yellow]MEDIUM[/yellow]", str(medium))
        table.add_row("[green]LOW[/green]", str(low))
        table.add_row("[dim]INFO[/dim]", str(info))
        table.add_row("─────────", "─────")
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{len(findings)}[/bold]"
        )

        console.print(table)
        console.print()

        console.print("[bold]Top findings:[/bold]")
        for i, finding in enumerate(findings[:5], 1):
            color = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
                "INFO": "dim"
            }.get(finding.severity_label, "white")

            console.print(
                f"  {i}. [{color}]{finding.severity_label}"
                f"[/{color}] {finding.title} "
                f"[dim]({finding.mitre_technique} · "
                f"{finding.owasp_category})[/dim]"
            )

    def save_findings_json(
        self,
        aggregated: AggregatedFindings
    ) -> Optional[str]:
        """
        Save aggregated findings as JSON for report generator.
        Fails gracefully if disk write fails — never crashes the agent.
        """
        try:
            FINDINGS_OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
            output_file = (
                FINDINGS_OUTPUT_PATH /
                f"{self.timestamp}_{self.target}_findings.json"
            )
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(aggregated.model_dump(), f, indent=2)
            console.print(
                f"[green]→ Findings saved: {output_file}[/green]"
            )
            return str(output_file)
        except OSError as e:
            console.print(
                f"[red]✗ Failed to save findings: {str(e)}[/red]"
            )
            return None


if __name__ == "__main__":
    console.print(
        "[bold green]Testing R3D Findings Aggregator...[/bold green]"
    )

    aggregator = FindingsAggregator(target="test-target.com")

    # OSINT findings
    aggregator.add_findings([
        Finding(
            title="Exposed employee email addresses",
            description="3 employee emails discovered via OSINT",
            finding_type="email_exposed",
            source_module="osint",
            target="test-target.com"
        ),
        Finding(
            title="AI chatbot surface detected",
            description="Exposed LLM chatbot found at /chat endpoint",
            finding_type="ai_surface",
            source_module="osint",
            target="test-target.com"
        ),
        Finding(
            title="Subdomain discovered: admin.test-target.com",
            description="Admin subdomain exposed publicly",
            finding_type="subdomain",
            source_module="osint",
            target="test-target.com"
        ),
    ])

    # LLM attack findings
    aggregator.add_findings([
        Finding(
            title="Prompt injection vulnerability confirmed",
            description="LLM chatbot vulnerable to direct prompt injection",
            finding_type="prompt_injection",
            source_module="llm_attack",
            target="test-target.com"
        ),
        Finding(
            title="Trust escalation vector identified",
            description="Gradual trust accumulation bypasses guardrails",
            finding_type="trust_escalation",
            source_module="llm_attack",
            target="test-target.com"
        ),
    ])

    # Traditional recon findings
    aggregator.add_findings([
        Finding(
            title="CVE-2021-41773 — Apache path traversal",
            description="Apache 2.4.49 vulnerable to path traversal",
            finding_type="cve_match",
            source_module="traditional",
            target="test-target.com",
            cve_id="CVE-2021-41773",
            cvss_score=9.8
        ),
        Finding(
            title="Port 22 SSH exposed",
            description="SSH service exposed on default port",
            finding_type="exposed_port",
            source_module="traditional",
            target="test-target.com"
        ),
        Finding(
            title="Outdated TLS 1.0 in use",
            description="Server supports deprecated TLS 1.0",
            finding_type="outdated_ssl",
            source_module="traditional",
            target="test-target.com"
        ),
    ])

    # Zero day finding
    aggregator.add_finding(
        Finding(
            title="Unclassified service — possible zero day",
            description="CustomApp 0.0.1 — no CVE match found",
            finding_type="zero_day",
            source_module="traditional",
            target="test-target.com",
            zero_day_flag=True,
            evidence_preserved=True
        )
    )

    # Duplicate finding — should be removed
    aggregator.add_finding(
        Finding(
            title="Exposed employee email addresses",
            description="Duplicate from second OSINT pass",
            finding_type="email_exposed",
            source_module="osint",
            target="test-target.com"
        )
    )

    # Security test — oversized title (should be truncated)
    aggregator.add_finding(
        Finding(
            title="A" * 500,
            description="Testing field validator truncation",
            finding_type="default",
            source_module="osint",
            target="test-target.com"
        )
    )

    # Security test — uppercase finding_type (should be normalized)
    aggregator.add_finding(
        Finding(
            title="Uppercase type test",
            description="Finding type should be normalized to lowercase",
            finding_type="PROMPT_INJECTION",
            source_module="llm_attack",
            target="test-target.com"
        )
    )

    results = aggregator.aggregate()
    aggregator.save_findings_json(results)

    console.print(
        f"\n[bold green]Total: {results.total_findings}[/bold green]"
    )
    console.print(f"[red]Critical: {results.critical_count}[/red]")
    console.print(f"[red]High: {results.high_count}[/red]")
    console.print(f"[yellow]Medium: {results.medium_count}[/yellow]")
    console.print(f"[green]Low: {results.low_count}[/green]")
    console.print(
        f"[bold red]Zero days: {results.zero_day_count}[/bold red]"
    )