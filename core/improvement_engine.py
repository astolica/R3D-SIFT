"""
R3D Agent -- Improvement Engine
Self-improvement loop. Reads engagement reports and suggests
targeted improvements to payloads and KB files.
Operator approves every suggestion -- nothing auto-modified.

What it reads:
    output/reports/*_verification_report.json
    output/reports/*_telemetry.json
    data/payloads/static_injections.json (payload IDs)
    data/llm_attack_kb/*.md (dedup against existing content)

What it produces:
    Trend table across all engagements
    Ranked suggestions (CRITICAL/HIGH/MEDIUM)
    Copy-paste ready KB text from Ollama
    Specific payload IDs to retire
    output/improvement_log.json (approved suggestions only)

What it never does:
    Auto-modify any file without operator YES
    Touch original_research.md
    Run automatically -- called via main.py --improve

Operator workflow:
    python main.py --improve
    -> Trend table shown
    -> Suggestions shown one by one ranked by priority
    -> Operator types Y/N for each
    -> Approved suggestions logged with status: approved
    -> Operator manually applies and marks status: applied

Minimum 3 engagements required before suggestions.
Deduplication against existing KB content before suggesting.

Compatibility: Windows 10/11, Ubuntu, Kali Linux
"""

import json
import re
from typing import Optional
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.llm_client import query_llm, LLMResponse

console = Console()

# Paths
BASE_DIR        = Path(__file__).parent.parent
OUTPUT_DIR      = BASE_DIR / "output"
REPORTS_DIR     = OUTPUT_DIR / "reports"
DATA_DIR        = BASE_DIR / "data"
KB_DIR          = DATA_DIR / "llm_attack_kb"
PAYLOADS_PATH   = DATA_DIR / "payloads" / "static_injections.json"
IMPROVEMENT_LOG = OUTPUT_DIR / "improvement_log.json"

# Thresholds
MIN_ENGAGEMENTS       = 3     # minimum before suggestions
CRITICAL_THRESHOLD    = 5     # pattern seen 5+ times
HIGH_THRESHOLD        = 3     # pattern seen 3-4 times
PAYLOAD_FAIL_THRESHOLD = 3    # payload blocked this many times = retire
KB_DEDUP_THRESHOLD    = 0.75  # similarity ratio = already exists
MAX_REPORTS           = 10    # max reports to analyze


# ------------------------------------------------------------------ #
# IMPROVEMENT ENGINE
# ------------------------------------------------------------------ #

class ImprovementEngine:
    """
    Self-improvement loop for R3D.

    Reads verifier reports to find patterns in what
    consistently fails, gets flagged, or gets removed.
    Generates ranked actionable suggestions.
    Operator approves every suggestion.
    Nothing ever auto-modified.
    """

    def __init__(self):
        self.suggestions: list[dict] = []
        self.approved:    list[dict] = []
        self.rejected:    list[dict] = []
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # REPORT LOADING
    # ------------------------------------------------------------------ #

    def _load_verification_reports(self) -> list[dict]:
        """
        Load most recent verification reports sorted by time.
        Never raises -- returns empty list on any failure.
        """
        reports = []
        try:
            files = sorted(
                REPORTS_DIR.glob("*_verification_report.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )[:MAX_REPORTS]

            for path in files:
                try:
                    with open(path, encoding="utf-8") as f:
                        data = json.load(f)
                        data["_file"] = path.name
                        reports.append(data)
                except Exception:
                    continue

        except Exception as e:
            console.print(
                f"[yellow]  Reports load failed: {e}[/yellow]"
            )

        return reports

    def _load_payloads(self) -> list[dict]:
        """
        Load static payload library.
        Returns empty list if file missing.
        """
        try:
            if PAYLOADS_PATH.exists():
                with open(PAYLOADS_PATH, encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    def _load_kb_content(self, kb_filename: str) -> str:
        """
        Load KB file content for dedup check.
        Returns empty string if file missing.
        """
        try:
            kb_path = KB_DIR / kb_filename
            if kb_path.exists():
                with open(kb_path, encoding="utf-8") as f:
                    return f.read()
        except Exception:
            pass
        return ""

    def _load_improvement_log(self) -> list[dict]:
        """
        Load existing improvement log.
        Returns empty list if no log exists yet.
        """
        try:
            if IMPROVEMENT_LOG.exists():
                with open(
                    IMPROVEMENT_LOG, encoding="utf-8"
                ) as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    # ------------------------------------------------------------------ #
    # TREND ANALYSIS
    # ------------------------------------------------------------------ #

    def _build_trend_data(
        self, reports: list[dict]
    ) -> list[dict]:
        """
        Build engagement trend data from reports.
        Sorted oldest to newest for trend display.
        """
        trend = []
        # Reverse so oldest first for trend display
        for i, report in enumerate(reversed(reports)):
            before   = report.get("findings_before", 0)
            after    = report.get("findings_after", 0)
            removed  = before - after
            rate     = (
                round(removed / before * 100)
                if before > 0 else 0
            )
            timestamp = report.get("timestamp", "")[:10]
            trend.append({
                "engagement": i + 1,
                "date":       timestamp,
                "findings":   before,
                "removed":    removed,
                "rate":       rate,
            })
        return trend

    def _print_trend_table(self, trend: list[dict]):
        """
        Print engagement trend table.
        Shows removal rate per engagement.
        Operator sees if tool is improving over time.
        """
        table = Table(
            title="Engagement Trend",
            show_header=True
        )
        table.add_column("#",         justify="right")
        table.add_column("Date",      style="dim")
        table.add_column("Findings",  justify="right")
        table.add_column("Removed",   justify="right")
        table.add_column("Rate",      justify="right")
        table.add_column("Trend")

        prev_rate = None
        for row in trend:
            rate = row["rate"]
            if prev_rate is None:
                trend_str = "─"
            elif rate < prev_rate:
                trend_str = "[green]↓ improving[/green]"
            elif rate > prev_rate:
                trend_str = "[red]↑ degrading[/red]"
            else:
                trend_str = "[yellow]→ stable[/yellow]"

            rate_str = (
                f"[green]{rate}%[/green]"
                if rate <= 10
                else f"[yellow]{rate}%[/yellow]"
                if rate <= 25
                else f"[red]{rate}%[/red]"
            )

            table.add_row(
                str(row["engagement"]),
                row["date"],
                str(row["findings"]),
                str(row["removed"]),
                rate_str,
                trend_str
            )
            prev_rate = rate

        console.print(table)
        console.print()

    # ------------------------------------------------------------------ #
    # PATTERN EXTRACTION
    # ------------------------------------------------------------------ #

    def _extract_patterns(
        self, reports: list[dict]
    ) -> dict:
        """
        Extract patterns from verification reports.
        Pure Python -- no LLM needed for data extraction.
        """
        patterns = {
            "removed_types":   {},  # finding_type -> count
            "flagged_types":   {},  # finding_type -> count
            "cve_stripped":    0,
            "total_removed":   0,
            "total_flagged":   0,
            "failed_payloads": {},  # payload title -> count
            "samples":         [],  # sample findings for Ollama
        }

        payloads = self._load_payloads()
        payload_titles = {
            p.get("id", ""): p.get("payload", "")[:50]
            for p in payloads
        }

        for report in reports:
            stats = report.get("stats", {})
            patterns["cve_stripped"]  += stats.get(
                "cve_stripped", 0
            )
            patterns["total_removed"] += stats.get(
                "removed", 0
            )
            patterns["total_flagged"] += stats.get(
                "flagged_uncertain", 0
            )

            for unverified in report.get(
                "unverified_findings", []
            ):
                finding = unverified.get("finding", {})
                ftype   = finding.get("finding_type", "unknown")
                reason  = unverified.get("reason", "unknown")
                title   = finding.get("title", "")

                if reason == "low_severity":
                    patterns["removed_types"][ftype] = (
                        patterns["removed_types"].get(ftype, 0)
                        + 1
                    )
                elif reason == "duplicate":
                    patterns["flagged_types"][ftype] = (
                        patterns["flagged_types"].get(ftype, 0)
                        + 1
                    )

                # Track payload failures by matching [P-XXX] ID in title
                # Finding titles format: "Prompt injection [P-001]"
                # Match on bracket ID not payload text
                ids_in_title = re.findall(
                    r'\[([A-Z0-9\-]+)\]', title
                )
                for pid in ids_in_title:
                    if pid in payload_titles:
                        patterns["failed_payloads"][pid] = (
                            patterns["failed_payloads"]
                            .get(pid, 0) + 1
                        )

                # Collect samples for Ollama
                if len(patterns["samples"]) < 5:
                    patterns["samples"].append({
                        "type":   ftype,
                        "reason": reason,
                        "title":  title[:100],
                    })

        return patterns

    # ------------------------------------------------------------------ #
    # SUGGESTION GENERATION
    # ------------------------------------------------------------------ #

    def _priority_label(self, count: int) -> str:
        """Map occurrence count to priority label."""
        if count >= CRITICAL_THRESHOLD:
            return "CRITICAL"
        elif count >= HIGH_THRESHOLD:
            return "HIGH"
        else:
            return "MEDIUM"

    def _priority_color(self, priority: str) -> str:
        """Map priority to Rich color."""
        return {
            "CRITICAL": "bold red",
            "HIGH":     "red",
            "MEDIUM":   "yellow",
        }.get(priority, "white")

    def _already_in_kb(
        self, suggested_text: str, kb_filename: str
    ) -> bool:
        """
        Check if suggested text already exists in KB file.
        Simple similarity check -- prevents duplicate suggestions.
        """
        existing = self._load_kb_content(kb_filename)
        if not existing:
            return False

        # Check if any 200-char window in existing is similar
        chunk_size = 200
        for i in range(0, len(existing), chunk_size // 2):
            chunk = existing[i:i + chunk_size]
            r = SequenceMatcher(
                None,
                suggested_text.lower()[:200],
                chunk.lower()
            ).ratio()
            if r > KB_DEDUP_THRESHOLD:
                return True

        return False

    def _generate_kb_suggestion(
        self, finding_type: str, count: int
    ) -> Optional[str]:
        """
        Ask Ollama to generate copy-paste ready KB text
        for a finding type that consistently fails verification.
        Returns None if Ollama unavailable.
        """
        try:
            result: LLMResponse = query_llm(
                prompt=(
                    f"You are improving an AI security testing tool.\n\n"
                    f"Finding type '{finding_type}' has been removed "
                    f"by the verifier {count} times across recent "
                    f"engagements due to low confidence scores.\n\n"
                    f"Generate a focused 150-word knowledge base entry "
                    f"in markdown format that would help the LLM attack "
                    f"module better identify and score '{finding_type}' "
                    f"vulnerabilities more accurately.\n\n"
                    f"Include: what the vulnerability looks like in "
                    f"responses, specific indicators of success, "
                    f"and common false positive patterns to avoid.\n\n"
                    f"Output only the markdown text. No preamble."
                ),
                system_prompt=(
                    "You are a precise AI security researcher. "
                    "Generate concise, actionable KB content. "
                    "Output markdown only."
                ),
                expect_json=False
            )

            if result and result.content:
                content = result.content
                if isinstance(content, str) and len(content) > 50:
                    return content

        except Exception:
            pass

        return None

    def _build_suggestions(
        self, patterns: dict, n_engagements: int
    ) -> list[dict]:
        """
        Build ranked suggestion list from patterns.
        CRITICAL > HIGH > MEDIUM ordering.
        Each suggestion has copy-paste ready text.
        Deduped against existing KB content.
        """
        suggestions = []

        # Suggestion type 1 -- Payload retirement
        retire_list = [
            (pid, count)
            for pid, count in patterns["failed_payloads"].items()
            if count >= PAYLOAD_FAIL_THRESHOLD
        ]
        if retire_list:
            retire_list.sort(key=lambda x: x[1], reverse=True)
            count    = max(c for _, c in retire_list)
            priority = self._priority_label(count)
            suggestions.append({
                "type":     "payload_retirement",
                "priority": priority,
                "title":    "Payload retirement recommended",
                "detail": (
                    f"{len(retire_list)} payload(s) blocked "
                    f"in {PAYLOAD_FAIL_THRESHOLD}+ engagements"
                ),
                "payload_ids": [pid for pid, _ in retire_list],
                "counts": {
                    pid: count for pid, count in retire_list
                },
                "action": (
                    "Retire these payload IDs from "
                    "data/payloads/static_injections.json:\n"
                    + "\n".join(
                        f"  {pid}: blocked {c}/{n_engagements} times"
                        for pid, c in retire_list
                    )
                ),
                "copy_paste": None,
                "status": "approved",
            })

        # Suggestion type 2 -- KB gaps from removed findings
        for ftype, count in sorted(
            patterns["removed_types"].items(),
            key=lambda x: x[1],
            reverse=True
        ):
            priority = self._priority_label(count)

            # Map finding type to KB file
            kb_file = self._finding_type_to_kb(ftype)
            if not kb_file:
                continue

            # Generate copy-paste ready text
            kb_text = self._generate_kb_suggestion(ftype, count)

            # Skip if already in KB
            if kb_text and self._already_in_kb(kb_text, kb_file):
                console.print(
                    f"[dim]  Skipping {ftype} -- "
                    f"already in {kb_file}[/dim]"
                )
                continue

            suggestions.append({
                "type":      "kb_gap",
                "priority":  priority,
                "title":     f"KB gap: {ftype}",
                "detail": (
                    f"Removed {count} times across "
                    f"{n_engagements} engagements"
                ),
                "kb_file":   kb_file,
                "action": (
                    f"Add the following to "
                    f"data/llm_attack_kb/{kb_file}"
                ),
                "copy_paste": kb_text,
                "status":    "approved",
            })

        # Suggestion type 3 -- Severity threshold adjustment
        for ftype, count in sorted(
            patterns["flagged_types"].items(),
            key=lambda x: x[1],
            reverse=True
        ):
            priority = self._priority_label(count)
            suggestions.append({
                "type":     "threshold_adjustment",
                "priority": priority,
                "title":    f"Severity threshold: {ftype}",
                "detail": (
                    f"Flagged uncertain {count} times. "
                    f"Consider adjusting scoring for this category."
                ),
                "action": (
                    f"In modules/llm_attack.py _map_severity():\n"
                    f"  Consider raising base score for '{ftype}'\n"
                    f"  Current default: 5.0\n"
                    f"  Suggested: 6.5 based on false positive rate"
                ),
                "copy_paste": None,
                "status":    "approved",
            })

        # Sort by priority: CRITICAL first, then HIGH, MEDIUM
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        suggestions.sort(
            key=lambda s: priority_order.get(s["priority"], 3)
        )

        return suggestions

    def _finding_type_to_kb(
        self, finding_type: str
    ) -> Optional[str]:
        """Map finding type to most relevant KB file."""
        mapping = {
            "prompt_injection":     "prompt_injection_taxonomy.md",
            "jailbreak":            "jailbreak_patterns.md",
            "trust_escalation":     "prompt_injection_taxonomy.md",
            "context_manipulation": "prompt_injection_taxonomy.md",
            "data_exfiltration":    "owasp_llm_top10_2025.md",
            "crescendo_attack":     "jailbreak_patterns.md",
        }
        return mapping.get(finding_type)

    # ------------------------------------------------------------------ #
    # OPERATOR REVIEW
    # ------------------------------------------------------------------ #

    def _show_suggestion(
        self,
        suggestion: dict,
        index:      int,
        total:      int
    ) -> bool:
        """
        Show one suggestion and ask operator to approve.
        Returns True if approved, False if rejected.
        """
        priority = suggestion["priority"]
        color    = self._priority_color(priority)

        console.print(
            Panel(
                f"[{color}]{priority}[/{color}] -- "
                f"{suggestion['title']}\n\n"
                f"[bold]Detail:[/bold] {suggestion['detail']}\n\n"
                f"[bold]Action:[/bold]\n{suggestion['action']}"
                + (
                    f"\n\n[bold]Copy-paste text:[/bold]\n"
                    f"{'─'*40}\n"
                    f"{suggestion['copy_paste']}\n"
                    f"{'─'*40}"
                    if suggestion.get("copy_paste")
                    else ""
                ),
                title=(
                    f"[bold]Suggestion [{index}/{total}][/bold]"
                ),
                border_style=color
            )
        )

        response = input(
            "Approve this suggestion? [Y/N]: "
        ).strip().upper()

        return response == "Y"

    # ------------------------------------------------------------------ #
    # LOG MANAGEMENT
    # ------------------------------------------------------------------ #

    def _save_improvement_log(self, entries: list[dict]):
        """
        Save approved suggestions to improvement log.
        Appends to existing log -- never overwrites history.
        Never raises -- non-critical if save fails.
        """
        try:
            existing = self._load_improvement_log()
            existing.extend(entries)
            with open(
                IMPROVEMENT_LOG, "w", encoding="utf-8"
            ) as f:
                json.dump(existing, f, indent=2)
            console.print(
                f"[green]  Logged {len(entries)} approved "
                f"suggestion(s) to {IMPROVEMENT_LOG}[/green]"
            )
        except Exception as e:
            console.print(
                f"[yellow]  Log save failed: {e}[/yellow]"
            )

    # ------------------------------------------------------------------ #
    # MAIN RUN
    # ------------------------------------------------------------------ #

    def run(self):
        """
        Run the improvement engine.
        Reads reports, shows trend, presents suggestions,
        logs approved suggestions. Never auto-modifies files.
        """
        console.print(
            f"\n[bold cyan]"
            f"{'='*52}\n"
            f"  R3D IMPROVEMENT ENGINE\n"
            f"{'='*52}"
            f"[/bold cyan]\n"
        )

        # Load reports
        console.print(
            "[cyan]  Loading engagement reports...[/cyan]"
        )
        reports = self._load_verification_reports()

        if not reports:
            console.print(
                "[yellow]  No engagement reports found.\n"
                "  Run at least one full engagement first:\n"
                "  python main.py --target example.com"
                "[/yellow]"
            )
            return

        n = len(reports)
        console.print(
            f"[green]  Found {n} engagement report(s)[/green]"
        )

        # Minimum engagement threshold
        if n < MIN_ENGAGEMENTS:
            console.print(
                f"\n[yellow]  Only {n} engagement(s) found.\n"
                f"  Minimum {MIN_ENGAGEMENTS} required for "
                f"meaningful pattern analysis.\n"
                f"  Run {MIN_ENGAGEMENTS - n} more engagement(s) "
                f"then try again.[/yellow]"
            )
            # Still show trend even with limited data
            if n > 0:
                trend = self._build_trend_data(reports)
                self._print_trend_table(trend)
            return

        # Build and show trend
        console.print(
            "\n[bold]Engagement Trend:[/bold]"
        )
        trend = self._build_trend_data(reports)
        self._print_trend_table(trend)

        # Extract patterns
        console.print(
            "[cyan]  Extracting patterns...[/cyan]"
        )
        patterns = self._extract_patterns(reports)

        if (
            not patterns["removed_types"] and
            not patterns["flagged_types"] and
            not patterns["failed_payloads"]
        ):
            console.print(
                "[green]  No improvement patterns found.\n"
                "  All findings passing verification cleanly.\n"
                "  Tool is performing well.[/green]"
            )
            return

        # Generate suggestions
        console.print(
            "[cyan]  Generating suggestions...[/cyan]"
        )
        suggestions = self._build_suggestions(patterns, n)

        if not suggestions:
            console.print(
                "[green]  No actionable suggestions "
                "generated.[/green]"
            )
            return

        # Count by priority
        critical = sum(
            1 for s in suggestions
            if s["priority"] == "CRITICAL"
        )
        high     = sum(
            1 for s in suggestions
            if s["priority"] == "HIGH"
        )
        medium   = sum(
            1 for s in suggestions
            if s["priority"] == "MEDIUM"
        )

        console.print(
            f"\n[bold]{len(suggestions)} suggestion(s) ready "
            f"({critical} CRITICAL, {high} HIGH, "
            f"{medium} MEDIUM)[/bold]\n"
            f"{'─'*52}"
        )

        # Operator review -- one at a time
        approved_entries = []

        for i, suggestion in enumerate(suggestions, 1):
            approved = self._show_suggestion(
                suggestion, i, len(suggestions)
            )

            if approved:
                entry = {
                    **suggestion,
                    "status":      "approved",
                    "approved_at": datetime.now().isoformat(),
                }
                approved_entries.append(entry)
                self.approved.append(suggestion)
                console.print(
                    "[green]  Approved -- logged[/green]\n"
                )
            else:
                suggestion["status"] = "rejected"
                self.rejected.append(suggestion)
                console.print(
                    "[dim]  Rejected -- skipped[/dim]\n"
                )

        # Save approved to log
        if approved_entries:
            self._save_improvement_log(approved_entries)

        # Final summary
        console.print(
            f"\n[bold green]"
            f"{'='*52}\n"
            f"  IMPROVEMENT SESSION COMPLETE\n"
            f"  Approved: {len(self.approved)}\n"
            f"  Rejected: {len(self.rejected)}\n"
            f"  Log:      {IMPROVEMENT_LOG}\n"
            f"{'='*52}"
            f"[/bold green]\n"
        )

        if self.approved:
            console.print(
                "[dim]  Next steps:\n"
                "  1. Open improvement_log.json\n"
                "  2. Apply each approved suggestion manually\n"
                "  3. Update status to 'applied' in the log\n"
                "  4. Run another engagement to measure impact"
                "[/dim]"
            )


# ------------------------------------------------------------------ #
# TEST
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    console.print(
        "[bold green]R3D Improvement Engine -- "
        "Module Load Test[/bold green]\n"
    )

    engine = ImprovementEngine()

    # Test with no reports -- should show helpful message
    console.print("Test 1: No reports scenario")
    console.print(
        f"Reports dir: {REPORTS_DIR}"
    )
    console.print(
        f"Reports found: "
        f"{len(engine._load_verification_reports())}"
    )

    # Test trend builder with mock data
    console.print("\nTest 2: Trend table with mock data")
    mock_reports = [
        {"findings_before": 12, "findings_after": 9,
         "timestamp": "2026-03-21T10:00:00", "stats": {},
         "unverified_findings": []},
        {"findings_before": 15, "findings_after": 13,
         "timestamp": "2026-03-22T10:00:00", "stats": {},
         "unverified_findings": []},
        {"findings_before": 18, "findings_after": 17,
         "timestamp": "2026-03-23T10:00:00", "stats": {},
         "unverified_findings": []},
    ]
    trend = engine._build_trend_data(mock_reports)
    engine._print_trend_table(trend)

    console.print(
        "[green]Module loaded successfully.[/green]"
    )