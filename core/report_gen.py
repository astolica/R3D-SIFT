"""
R3D Agent — Report Generator
Takes AggregatedFindings and produces:
1. Professional PDF executive report
2. XLSX risk register (NIST SP 800-53 + NERC CIP mapped)
3. Telemetry log (blue team artifact)

The PDF is for humans — executives, security architects, hiring managers.
The XLSX is for compliance — GRC analysts, auditors, regulators.
The telemetry log is for defenders — SOC analysts correlating against SIEM.

Security fixes applied:
- Consistent regex path sanitization (matches CVE engine pattern)
- Explicit None handling in XLSX column sizing
- Scan duration and version metadata in telemetry log
- TODO markers for v2 LLM-generated executive summary
- Unicode font (Arial) for PDF — supports all special characters

Compatibility: Windows 10/11, Ubuntu, Kali Linux, macOS
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional
from fpdf import FPDF
import pandas as pd
from rich.console import Console

from core.findings import AggregatedFindings, Finding

console = Console()

# Paths
BASE_DIR = Path(__file__).parent.parent
OUTPUT_PATH = BASE_DIR / "output"
REPORTS_PATH = OUTPUT_PATH / "reports"

# Font paths — Windows default
# Linux/Mac override handled in _get_font_paths()
FONT_REGULAR = "C:\\Windows\\Fonts\\arial.ttf"
FONT_BOLD = "C:\\Windows\\Fonts\\arialbd.ttf"
FONT_ITALIC = "C:\\Windows\\Fonts\\ariali.ttf"


def _get_font_paths() -> tuple:
    """
    Get font paths for current OS.
    Windows uses Arial from system fonts.
    Linux/Mac falls back to DejaVu if available, then Liberation.
    Returns (regular, bold, italic) font paths.
    """
    import platform
    system = platform.system()

    if system == "Windows":
        base = Path("C:/Windows/Fonts")
        return (
            str(base / "arial.ttf"),
            str(base / "arialbd.ttf"),
            str(base / "ariali.ttf")
        )
    elif system == "Linux":
        # Try DejaVu first (installed on most Linux distros including Kali)
        dejavu = Path("/usr/share/fonts/truetype/dejavu")
        if dejavu.exists():
            return (
                str(dejavu / "DejaVuSans.ttf"),
                str(dejavu / "DejaVuSans-Bold.ttf"),
                str(dejavu / "DejaVuSans-Oblique.ttf")
            )
        # Liberation fonts (fallback)
        liberation = Path("/usr/share/fonts/truetype/liberation")
        return (
            str(liberation / "LiberationSans-Regular.ttf"),
            str(liberation / "LiberationSans-Bold.ttf"),
            str(liberation / "LiberationSans-Italic.ttf")
        )
    else:
        # macOS
        base = Path("/Library/Fonts")
        return (
            str(base / "Arial.ttf"),
            str(base / "Arial Bold.ttf"),
            str(base / "Arial Italic.ttf")
        )


# NIST SP 800-53 control mapping
NIST_MAPPING = {
    "prompt_injection":     ["SI-10", "SI-3", "SA-11"],
    "jailbreak":            ["SI-10", "SI-3", "CA-8"],
    "trust_escalation":     ["AC-2", "AC-6", "IA-2"],
    "context_manipulation": ["SI-10", "SI-12", "AU-10"],
    "data_exfiltration":    ["AC-4", "SI-12", "AU-9"],
    "crescendo_attack":     ["SI-10", "AC-17", "CA-8"],
    "zero_day":             ["RA-5", "SI-2", "SA-10"],
    "cve_match":            ["RA-5", "SI-2", "SA-10"],
    "exposed_admin":        ["AC-17", "CM-7", "SC-7"],
    "outdated_ssl":         ["SC-8", "SC-23", "IA-8"],
    "exposed_port":         ["CM-7", "SC-7", "CA-9"],
    "header_missing":       ["SC-8", "SI-16", "CM-6"],
    "subdomain":            ["CM-8", "RA-5", "SC-7"],
    "ai_surface":           ["RA-5", "CA-8", "SI-10"],
    "email_exposed":        ["AT-2", "PL-4", "RA-5"],
    "username_exposed":     ["AT-2", "PL-4", "RA-5"],
    "tech_stack":           ["CM-8", "RA-5", "SA-10"],
    "credential_stuffing":  ["IA-5", "AC-7", "SI-10"],
    "default":              ["RA-5", "CA-8", "SI-2"],
}

# NERC CIP mapping
NERC_CIP_MAPPING = {
    "prompt_injection":     ["CIP-007-6", "CIP-010-4"],
    "jailbreak":            ["CIP-007-6", "CIP-010-4"],
    "trust_escalation":     ["CIP-004-7", "CIP-007-6"],
    "context_manipulation": ["CIP-007-6", "CIP-010-4"],
    "data_exfiltration":    ["CIP-011-3", "CIP-007-6"],
    "crescendo_attack":     ["CIP-007-6", "CIP-004-7"],
    "zero_day":             ["CIP-007-6", "CIP-010-4"],
    "cve_match":            ["CIP-007-6", "CIP-010-4"],
    "exposed_admin":        ["CIP-005-7", "CIP-007-6"],
    "outdated_ssl":         ["CIP-005-7", "CIP-007-6"],
    "exposed_port":         ["CIP-005-7", "CIP-007-6"],
    "header_missing":       ["CIP-007-6", "CIP-010-4"],
    "subdomain":            ["CIP-005-7", "CIP-007-6"],
    "ai_surface":           ["CIP-007-6", "CIP-010-4"],
    "email_exposed":        ["CIP-004-7", "CIP-011-3"],
    "username_exposed":     ["CIP-004-7", "CIP-011-3"],
    "tech_stack":           ["CIP-010-4", "CIP-007-6"],
    "credential_stuffing":  ["CIP-004-7", "CIP-007-6"],
    "default":              ["CIP-007-6", "CIP-010-4"],
}

# Remediation templates
# TODO v2 - replace with LLM-generated remediations via query_llm()
REMEDIATION_TEMPLATES = {
    "prompt_injection": (
        "Implement input validation and output filtering on all LLM "
        "interfaces. Deploy conversation-level monitoring that evaluates "
        "session trajectory not individual messages. Enforce strict context "
        "resets for extended sessions."
    ),
    "jailbreak": (
        "Apply multi-layer guardrail architecture. Single-session testing "
        "is insufficient - deploy red team suite with multi-turn sequences. "
        "Implement confidence thresholds that trigger human review."
    ),
    "trust_escalation": (
        "Implement conversation-level monitoring to detect gradual context "
        "accumulation. AI interfaces must not confirm or deny specific asset "
        "configurations regardless of stated requester identity. "
        "Periodic context resets mandatory for extended sessions."
    ),
    "context_manipulation": (
        "Deploy context integrity validation between conversation turns. "
        "Implement session fingerprinting to detect anomalous context shifts. "
        "Apply strict output filtering on all LLM responses."
    ),
    "data_exfiltration": (
        "Implement data loss prevention controls on all LLM output channels. "
        "Apply output filtering for PII patterns. Monitor and alert on "
        "large volume LLM responses. Restrict LLM access to sensitive data."
    ),
    "crescendo_attack": (
        "Deploy multi-turn conversation monitoring. Implement periodic "
        "context resets. AI interfaces must not accumulate sensitive "
        "operational context across extended sessions."
    ),
    "cve_match": (
        "Apply vendor patch immediately. If patch unavailable implement "
        "compensating controls: WAF rule, network segmentation, or service "
        "isolation. Track remediation against SLA defined in vulnerability "
        "management policy."
    ),
    "zero_day": (
        "Preserve all raw evidence. Initiate responsible disclosure process "
        "with affected vendor. Implement network-level compensating controls "
        "while awaiting vendor response. Document full timeline for "
        "compliance reporting."
    ),
    "exposed_admin": (
        "Restrict admin interface to internal network or VPN only. "
        "Implement MFA on all administrative access. Apply principle of "
        "least privilege. Review and rotate all administrative credentials."
    ),
    "outdated_ssl": (
        "Disable TLS 1.0 and TLS 1.1 immediately. Enforce TLS 1.2 minimum "
        "TLS 1.3 preferred. Update cipher suites to remove deprecated "
        "algorithms. Schedule quarterly SSL/TLS configuration reviews."
    ),
    "exposed_port": (
        "Review firewall rules and close unnecessary exposed ports. "
        "Apply network segmentation. Document all intentionally exposed "
        "services with business justification."
    ),
    "header_missing": (
        "Implement security headers: Content-Security-Policy, "
        "X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security. "
        "Automate header validation in CI/CD pipeline."
    ),
    "subdomain": (
        "Audit all subdomains and remove unused ones. Implement subdomain "
        "monitoring alerts. Review DNS zone for dangling records."
    ),
    "ai_surface": (
        "Inventory all AI/LLM deployments. Apply authentication to all "
        "AI interfaces. Implement rate limiting and abuse detection. "
        "Conduct LLM-specific red team assessment."
    ),
    "email_exposed": (
        "Remove exposed email addresses from public sources where possible. "
        "Implement email security controls including SPF, DKIM, DMARC. "
        "Train staff on phishing awareness."
    ),
    "username_exposed": (
        "Review publicly accessible employee information. Implement "
        "OSINT monitoring for exposed employee data. Train staff on "
        "information disclosure risks."
    ),
    "tech_stack": (
        "Review technology disclosure in HTTP headers and error pages. "
        "Suppress version information where possible. Maintain asset "
        "inventory with vulnerability tracking."
    ),
    "credential_stuffing": (
        "Implement MFA on all user-facing authentication. Deploy credential "
        "stuffing detection and rate limiting. Monitor for breached "
        "credentials via threat intelligence feeds."
    ),
    "default": (
        "Review finding in context of overall risk posture. Apply principle "
        "of least privilege. Document compensating controls if immediate "
        "remediation is not feasible."
    ),
}


def _sanitize_filename(value: str, max_length: int = 30) -> str:
    """
    Sanitize string for safe use in file and folder names.
    Consistent with CVE engine sanitization pattern.
    Prevents path traversal on Windows and Linux.
    """
    sanitized = re.sub(r'[^a-zA-Z0-9_\-]', '_', value)
    return sanitized[:max_length]


def _sanitize_for_pdf(text: str, max_length: int = 2000) -> str:
    """
    Sanitize text before passing to fpdf multi_cell or cell.

    Fixes:
    - Tab characters (\t) cause font missing glyph warning in fpdf
      Replace with 4 spaces which render cleanly
    - Null bytes crash fpdf entirely
    - Control characters cause rendering artifacts
    - Truncate to max_length to prevent right-side overflow on long lines

    Called on every string before it touches the PDF renderer.
    """
    if not text:
        return ""
    # Replace tabs with spaces -- fpdf has no tab glyph
    text = text.replace("\t", "    ")
    # Strip null bytes and control chars except newline
    text = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', text)
    # Truncate
    return text[:max_length]


class R3DReportPDF(FPDF):
    """
    Custom PDF class for R3D reports.
    Uses Arial Unicode font for full character support.
    """

    def __init__(self):
        super().__init__()
        # Load Unicode fonts for full character support
        # Handles em dashes, special chars in findings
        font_regular, font_bold, font_italic = _get_font_paths()
        try:
            self.add_font("Arial", "", font_regular, uni=True)
            self.add_font("Arial", "B", font_bold, uni=True)
            self.add_font("Arial", "I", font_italic, uni=True)
            self.font_name = "Arial"
        except Exception:
            # Fallback to Helvetica if font loading fails
            # Em dashes will be replaced with hyphens in this case
            self.font_name = "Helvetica"

    def header(self):
        """Page header - runs automatically on every page."""
        self.set_font(self.font_name, "B", 10)
        self.set_text_color(50, 50, 50)
        self.cell(0, 8, "R3D - Autonomous Red Team Agent", align="L")
        self.set_font(self.font_name, "", 9)
        self.set_text_color(150, 150, 150)
        self.cell(0, 8, "CONFIDENTIAL - AUTHORIZED USE ONLY", align="R")
        self.ln(2)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        """Page footer - runs automatically on every page."""
        self.set_y(-15)
        self.set_font(self.font_name, "", 8)
        self.set_text_color(150, 150, 150)
        self.cell(
            0, 10,
            f"Page {self.page_no()} | Generated by R3D Agent | HumdoesCyber",
            align="C"
        )

    def section_title(self, title: str):
        """Styled section heading with underline."""
        self.ln(4)
        self.set_font(self.font_name, "B", 13)
        self.set_text_color(30, 30, 30)
        self.cell(0, 8, title, ln=True)
        self.set_draw_color(50, 50, 50)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def finding_block(self, finding: Finding, index: int):
        """
        Render one complete finding block.
        Color coded by severity. Zero day findings get warning label.

        Fix: _sanitize_for_pdf() applied to all text fields before
        rendering. Prevents tab char glyph warnings and right-side
        overflow on long unbroken strings.
        """
        colors = {
            "CRITICAL": (220, 50, 50),
            "HIGH":     (220, 100, 50),
            "MEDIUM":   (220, 180, 50),
            "LOW":      (50, 180, 50),
            "INFO":     (100, 100, 100),
        }
        color = colors.get(finding.severity_label, (100, 100, 100))

        # Sanitize all text fields before touching renderer
        title       = _sanitize_for_pdf(finding.title, 150)
        description = _sanitize_for_pdf(finding.description, 1500)
        mitre       = _sanitize_for_pdf(
            f"{finding.mitre_technique or 'N/A'} - "
            f"{finding.mitre_technique_name or 'N/A'}", 100
        )
        owasp       = _sanitize_for_pdf(
            f"{finding.owasp_category or 'N/A'} - "
            f"{finding.owasp_category_name or 'N/A'}", 100
        )

        # Severity colored header bar
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font(self.font_name, "B", 10)
        label = f"  [{finding.severity_label}]"
        if finding.zero_day_flag:
            label += " ZERO DAY FLAG"
        self.cell(
            0, 7,
            f"{index}. {title}{label}",
            fill=True, ln=True
        )

        self.set_text_color(30, 30, 30)
        self.ln(1)

        # Description
        self.set_font(self.font_name, "B", 9)
        self.cell(35, 5, "Description:", ln=False)
        self.set_font(self.font_name, "", 9)
        self.multi_cell(0, 5, description)

        # MITRE
        self.set_font(self.font_name, "B", 9)
        self.cell(35, 5, "MITRE ATT&CK:", ln=False)
        self.set_font(self.font_name, "", 9)
        self.cell(0, 5, mitre, ln=True)

        # OWASP
        self.set_font(self.font_name, "B", 9)
        self.cell(35, 5, "OWASP:", ln=False)
        self.set_font(self.font_name, "", 9)
        self.cell(0, 5, owasp, ln=True)

        # CVE if present
        if finding.cve_id:
            self.set_font(self.font_name, "B", 9)
            self.cell(35, 5, "CVE:", ln=False)
            self.set_font(self.font_name, "", 9)
            self.cell(
                0, 5,
                _sanitize_for_pdf(
                    f"{finding.cve_id} (CVSS: {finding.cvss_score})", 60
                ),
                ln=True
            )

        # NIST controls
        nist = NIST_MAPPING.get(
            finding.finding_type, NIST_MAPPING["default"]
        )
        self.set_font(self.font_name, "B", 9)
        self.cell(35, 5, "NIST SP 800-53:", ln=False)
        self.set_font(self.font_name, "", 9)
        self.cell(0, 5, " | ".join(nist), ln=True)

        # NERC CIP
        nerc = NERC_CIP_MAPPING.get(
            finding.finding_type, NERC_CIP_MAPPING["default"]
        )
        self.set_font(self.font_name, "B", 9)
        self.cell(35, 5, "NERC CIP:", ln=False)
        self.set_font(self.font_name, "", 9)
        self.cell(0, 5, " | ".join(nerc), ln=True)

        # Remediation
        remediation = _sanitize_for_pdf(
            REMEDIATION_TEMPLATES.get(
                finding.finding_type,
                REMEDIATION_TEMPLATES["default"]
            ), 800
        )
        self.set_font(self.font_name, "B", 9)
        self.cell(35, 5, "Remediation:", ln=False)
        self.set_font(self.font_name, "", 9)
        self.multi_cell(0, 5, remediation)

        # Zero day evidence note
        if finding.zero_day_flag and finding.evidence_preserved:
            self.set_font(self.font_name, "I", 8)
            self.set_text_color(150, 50, 50)
            self.cell(
                0, 5,
                f"Raw evidence preserved at: "
                f"{finding.raw_evidence_path or 'output/evidence/'}",
                ln=True
            )
            self.set_text_color(30, 30, 30)

        self.ln(4)


class ReportGenerator:
    """
    Generates PDF, XLSX, and telemetry log from AggregatedFindings.
    All three outputs produced simultaneously from the same data.
    """

    def __init__(self, aggregated: AggregatedFindings):
        self.aggregated = aggregated
        self.timestamp = aggregated.scan_timestamp
        self.target = aggregated.target
        self.scan_start = aggregated.scan_timestamp
        self.scan_end = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        REPORTS_PATH.mkdir(parents=True, exist_ok=True)

    def generate_all(self) -> dict:
        """
        Generate all report outputs simultaneously.
        Each output fails independently.
        Returns dict with paths to all generated files.
        """
        console.print("\n[bold cyan]Generating reports...[/bold cyan]")

        results = {}

        pdf_path = self.generate_pdf()
        if pdf_path:
            results["pdf"] = pdf_path

        xlsx_path = self.generate_xlsx()
        if xlsx_path:
            results["xlsx"] = xlsx_path

        telemetry_path = self.generate_telemetry_log()
        if telemetry_path:
            results["telemetry"] = telemetry_path

        console.print(
            f"\n[bold green]Reports generated - "
            f"{len(results)} files[/bold green]"
        )
        for file_type, path in results.items():
            console.print(f"[green]  -> {file_type}: {path}[/green]")

        return results

    def generate_pdf(self) -> Optional[str]:
        """
        Generate executive PDF report.
        Structure:
        - Cover page
        - Executive summary
        - Findings sorted by priority
        - Methodology and disclaimer

        TODO v2 - generate executive summary via query_llm()
        """
        try:
            pdf = R3DReportPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()

            # COVER PAGE
            pdf.ln(20)
            pdf.set_font(pdf.font_name, "B", 24)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(
                0, 12, "R3D Red Team Assessment",
                align="C", ln=True
            )

            pdf.set_font(pdf.font_name, "", 14)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(
                0, 8, f"Target: {self.target}",
                align="C", ln=True
            )
            pdf.cell(
                0, 8,
                f"Date: {datetime.now().strftime('%B %d, %Y')}",
                align="C", ln=True
            )
            pdf.cell(
                0, 8, "Classification: CONFIDENTIAL",
                align="C", ln=True
            )

            pdf.ln(10)
            pdf.set_font(pdf.font_name, "B", 11)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(0, 7, "Findings Summary", align="C", ln=True)
            pdf.ln(2)

            summary_data = [
                ("Total Findings",  str(self.aggregated.total_findings)),
                ("Critical",        str(self.aggregated.critical_count)),
                ("High",            str(self.aggregated.high_count)),
                ("Medium",          str(self.aggregated.medium_count)),
                ("Low",             str(self.aggregated.low_count)),
                ("Zero Day Flags",  str(self.aggregated.zero_day_count)),
            ]

            for label, value in summary_data:
                pdf.set_font(pdf.font_name, "B", 10)
                pdf.cell(80, 6, label, align="R")
                pdf.set_font(pdf.font_name, "", 10)
                pdf.cell(0, 6, value, ln=True)

            # EXECUTIVE SUMMARY
            pdf.add_page()
            pdf.section_title("Executive Summary")

            pdf.set_font(pdf.font_name, "", 10)
            pdf.set_text_color(30, 30, 30)

            summary_text = (
                f"R3D conducted an autonomous red team assessment against "
                f"{self.target}. The assessment covered passive OSINT "
                f"reconnaissance, LLM attack surface analysis, traditional "
                f"network and web application security testing, and GRC "
                f"compliance gap analysis.\n\n"
                f"A total of {self.aggregated.total_findings} findings were "
                f"identified across all assessment phases. "
            )

            if self.aggregated.zero_day_count > 0:
                summary_text += (
                    f"{self.aggregated.zero_day_count} finding(s) were "
                    f"flagged as potential zero day vulnerabilities with no "
                    f"existing CVE match. Raw evidence has been preserved "
                    f"for responsible disclosure. "
                )

            if self.aggregated.critical_count > 0:
                summary_text += (
                    f"{self.aggregated.critical_count} critical severity "
                    f"finding(s) require immediate attention. "
                )

            summary_text += (
                f"\n\nAll findings are mapped to MITRE ATT&CK techniques, "
                f"OWASP categories, NIST SP 800-53 controls, and NERC CIP "
                f"standards where applicable. Remediation recommendations "
                f"are provided for each finding."
            )

            pdf.multi_cell(0, 6, summary_text)

            # FINDINGS
            pdf.add_page()
            pdf.section_title(
                f"Findings ({self.aggregated.total_findings} total)"
            )

            for i, finding in enumerate(self.aggregated.findings, 1):
                pdf.finding_block(finding, i)

            # METHODOLOGY AND DISCLAIMER
            pdf.add_page()
            pdf.section_title("Methodology and Disclaimer")

            pdf.set_font(pdf.font_name, "B", 10)
            pdf.cell(0, 6, "Assessment Methodology", ln=True)
            pdf.set_font(pdf.font_name, "", 9)
            pdf.multi_cell(0, 5, (
                "This assessment was conducted using R3D, an autonomous "
                "red team agent running locally on authorized hardware. "
                "All reconnaissance was conducted passively where possible. "
                "Active testing was performed only with explicit operator "
                "authorization in GUIDED or SEMI-AUTO mode.\n\n"
                "Modules executed: OSINT Reconnaissance, LLM Attack Surface "
                "Analysis, Traditional Red Team, GRC Compliance Mapping.\n\n"
                "CVE data sourced from NIST National Vulnerability Database. "
                "MITRE ATT&CK framework version 14. OWASP Top 10 Web (2021) "
                "and OWASP LLM Top 10 (2025)."
            ))

            pdf.ln(4)
            pdf.set_font(pdf.font_name, "B", 10)
            pdf.cell(0, 6, "Disclaimer", ln=True)
            pdf.set_font(pdf.font_name, "", 9)
            pdf.multi_cell(0, 5, (
                "This report was generated for authorized security assessment "
                "purposes only. All testing was conducted within approved "
                "scope. This document contains sensitive security findings "
                "and should be treated as confidential. Distribution should "
                "be limited to authorized personnel only.\n\n"
                "R3D and its creator accept no liability for unauthorized "
                "use of findings or techniques documented in this report."
            ))

            # Save PDF
            safe_target = _sanitize_filename(self.target)
            pdf_path = (
                REPORTS_PATH /
                f"{self.timestamp}_{safe_target}_report.pdf"
            )
            pdf.output(str(pdf_path))
            console.print(f"[green]PDF report generated[/green]")
            return str(pdf_path)

        except Exception as e:
            console.print(
                f"[red]PDF generation failed: {str(e)}[/red]"
            )
            return None

    def generate_xlsx(self) -> Optional[str]:
        """
        Generate XLSX risk register.
        Full compliance document with NIST and NERC CIP mappings.
        Auto-sized columns for readability.
        """
        try:
            rows = []
            for finding in self.aggregated.findings:
                nist = NIST_MAPPING.get(
                    finding.finding_type, NIST_MAPPING["default"]
                )
                nerc = NERC_CIP_MAPPING.get(
                    finding.finding_type, NERC_CIP_MAPPING["default"]
                )
                remediation = REMEDIATION_TEMPLATES.get(
                    finding.finding_type,
                    REMEDIATION_TEMPLATES["default"]
                )

                rows.append({
                    "Finding ID":       finding.id,
                    "Title":            finding.title,
                    "Severity":         finding.severity_label,
                    "Score":            finding.severity_score,
                    "Module":           finding.source_module,
                    "Finding Type":     finding.finding_type,
                    "Description":      finding.description,
                    "MITRE Technique":  finding.mitre_technique,
                    "MITRE Name":       finding.mitre_technique_name,
                    "OWASP Category":   finding.owasp_category,
                    "OWASP Name":       finding.owasp_category_name,
                    "NIST Controls":    " | ".join(nist),
                    "NERC CIP":         " | ".join(nerc),
                    "CVE ID":           finding.cve_id or "",
                    "CVSS Score":       finding.cvss_score or "",
                    "Zero Day Flag":    "YES" if finding.zero_day_flag else "NO",
                    "Evidence Path":    finding.raw_evidence_path or "",
                    "Remediation":      remediation,
                    "Target":           finding.target,
                    "Timestamp":        finding.timestamp,
                })

            df = pd.DataFrame(rows)

            safe_target = _sanitize_filename(self.target)
            xlsx_path = (
                REPORTS_PATH /
                f"{self.timestamp}_{safe_target}_risk_register.xlsx"
            )

            with pd.ExcelWriter(
                str(xlsx_path), engine="openpyxl"
            ) as writer:
                df.to_excel(
                    writer, index=False, sheet_name="Risk Register"
                )

                # Auto-size columns
                worksheet = writer.sheets["Risk Register"]
                for column in worksheet.columns:
                    max_length = max(
                        len(str(cell.value)) if cell.value is not None else 0
                        for cell in column
                    )
                    adjusted_width = min(max_length + 4, 60)
                    worksheet.column_dimensions[
                        column[0].column_letter
                    ].width = adjusted_width

            console.print(
                f"[green]XLSX risk register generated[/green]"
            )
            return str(xlsx_path)

        except Exception as e:
            console.print(
                f"[red]XLSX generation failed: {str(e)}[/red]"
            )
            return None

    def generate_telemetry_log(self) -> Optional[str]:
        """
        Generate blue team telemetry log.
        Documents every offensive action for SOC correlation.
        Includes scan duration for SIEM search window bounding.
        """
        try:
            telemetry = {
                "engagement_id":    f"R3D_{self.timestamp}",
                "target":           self.target,
                "scan_start":       self.scan_start,
                "scan_end":         self.scan_end,
                "r3d_version":      "1.0",
                "total_findings":   self.aggregated.total_findings,
                "generated_by":     "R3D Agent v1.0 - HumdoesCyber",
                "purpose": (
                    "Blue team artifact - correlate against SIEM logs "
                    "to validate detection coverage"
                ),
                "actions": []
            }

            for finding in self.aggregated.findings:
                telemetry["actions"].append({
                    "timestamp":        finding.timestamp,
                    "action_type":      finding.finding_type,
                    "source_module":    finding.source_module,
                    "target":           finding.target,
                    "finding_title":    finding.title,
                    "severity":         finding.severity_label,
                    "mitre_technique":  finding.mitre_technique,
                    "mitre_name":       finding.mitre_technique_name,
                    "owasp_category":   finding.owasp_category,
                    "owasp_name":       finding.owasp_category_name,
                    "zero_day_flag":    finding.zero_day_flag,
                    "detection_note": (
                        f"Verify detection rule for "
                        f"{finding.mitre_technique} - "
                        f"{finding.mitre_technique_name}"
                    )
                })

            safe_target = _sanitize_filename(self.target)
            telemetry_path = (
                REPORTS_PATH /
                f"{self.timestamp}_{safe_target}_telemetry.json"
            )

            with open(
                telemetry_path, "w", encoding="utf-8"
            ) as f:
                json.dump(telemetry, f, indent=2)

            console.print(
                f"[green]Telemetry log generated[/green]"
            )
            return str(telemetry_path)

        except Exception as e:
            console.print(
                f"[red]Telemetry log failed: {str(e)}[/red]"
            )
            return None


if __name__ == "__main__":
    console.print(
        "[bold green]Testing R3D Report Generator...[/bold green]"
    )

    from core.findings import FindingsAggregator, Finding

    aggregator = FindingsAggregator(target="test-target.com")

    aggregator.add_findings([
        Finding(
            title="Prompt injection vulnerability confirmed",
            description=(
                "LLM chatbot vulnerable to direct prompt injection "
                "via /chat endpoint. Guardrails bypassed in 3 attempts."
            ),
            finding_type="prompt_injection",
            source_module="llm_attack",
            target="test-target.com"
        ),
        Finding(
            title="CVE-2021-41773 - Apache path traversal",
            description=(
                "Apache 2.4.49 vulnerable to path traversal and "
                "remote code execution. CVSS 9.8 Critical."
            ),
            finding_type="cve_match",
            source_module="traditional",
            target="test-target.com",
            cve_id="CVE-2021-41773",
            cvss_score=9.8
        ),
        Finding(
            title="Trust escalation vector identified",
            description=(
                "Gradual trust accumulation bypasses LLM guardrails "
                "over multi-turn conversation. Novel vector outside "
                "OWASP LLM Top 10."
            ),
            finding_type="trust_escalation",
            source_module="llm_attack",
            target="test-target.com"
        ),
        Finding(
            title="Unclassified service - possible zero day",
            description=(
                "CustomApp 0.0.1 - no CVE match found in local "
                "database or NVD. Manual investigation required."
            ),
            finding_type="zero_day",
            source_module="traditional",
            target="test-target.com",
            zero_day_flag=True,
            evidence_preserved=True,
            raw_evidence_path="output/evidence/test_zeroday"
        ),
        Finding(
            title="Exposed admin panel",
            description=(
                "Admin interface accessible without authentication "
                "at /admin endpoint. No rate limiting detected."
            ),
            finding_type="exposed_admin",
            source_module="traditional",
            target="test-target.com"
        ),
        Finding(
            title="Outdated TLS 1.0 in use",
            description=(
                "Server supports deprecated TLS 1.0 protocol. "
                "Vulnerable to POODLE and BEAST attacks."
            ),
            finding_type="outdated_ssl",
            source_module="traditional",
            target="test-target.com"
        ),
    ])

    results = aggregator.aggregate()
    generator = ReportGenerator(results)
    output_files = generator.generate_all()

    console.print("\n[bold]Generated files:[/bold]")
    for file_type, path in output_files.items():
        console.print(f"  {file_type}: {path}")