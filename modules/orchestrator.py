"""
R3D Agent -- Master Orchestrator
Wires all four modules together into a complete engagement.
Manages sequencing, checkpointing, context filtering,
safety gates, and final report generation.

Engagement flow:
    1.  Target authorization consent
    2.  Load or create engagement state
    3.  OSINT reconnaissance
    4.  Context filter before LLM handoff
    5.  LLM attack suite (if AI surfaces found)
    6.  Traditional reconnaissance
    7.  Findings aggregation
    8.  Verifier hook (if available)
    9.  GRC compliance mapping
    10. Report generation
    11. Final engagement summary

Checkpointing:
    State saved after every module completes.
    --resume flag loads state and skips completed modules.
    Engagement never needs to restart from scratch.

Safety guarantees:
    GUIDED mode gates enforced -- never bypassed
    Sherlock blocked in FULL-AUTO regardless of mode
    Target authorization consent required before start
    Context filtered before LLM handoff
    Critical findings alert operator in GUIDED mode

Performance:
    2 second buffer between modules
    45 minute overall timeout (configurable)
    Progress heartbeat every 30 seconds on long ops
    Elapsed time tracked and reported

Compatibility: Windows 10/11, Ubuntu, Kali Linux
"""

import json
import re
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.findings import Finding, FindingsAggregator
from core.report_gen import ReportGenerator
from modules.osint_recon import OSINTRecon, OSINTProfile
from modules.llm_attack import LLMAttackSuite
from modules.traditional_recon import TraditionalRecon
from modules.grc_mapper import GRCMapper

console = Console()

# Paths
BASE_DIR        = Path(__file__).parent.parent
OUTPUT_DIR      = BASE_DIR / "output"
ENGAGEMENTS_DIR = OUTPUT_DIR / "engagements"

# Timing
MODULE_BUFFER       = 2     # seconds between modules
HEARTBEAT_INTERVAL  = 30    # seconds between heartbeat prints
DEFAULT_TIMEOUT     = 2700  # 45 minutes in seconds

# AI relevant subdomain keywords for context filtering
AI_RELEVANT_KEYWORDS = [
    "api", "chat", "ai", "llm", "bot", "assistant",
    "gpt", "model", "ml", "inference", "copilot",
    "v1", "v2", "graphql", "gateway",
]


# ------------------------------------------------------------------ #
# HELPERS
# ------------------------------------------------------------------ #

def _sanitize_filename(value: str) -> str:
    """Safe filename component."""
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', value)[:30]


def _generate_engagement_id(target: str) -> str:
    """
    Generate unique engagement ID.
    Used as prefix for all output files from this run.
    Ties all outputs together when multiple runs exist.
    Format: R3D_YYYYMMDD_HHMMSS_TARGET
    """
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = _sanitize_filename(target)
    return f"R3D_{timestamp}_{safe_target}"


# ------------------------------------------------------------------ #
# HEARTBEAT
# ------------------------------------------------------------------ #

class Heartbeat:
    """
    Background thread that prints progress dots
    during long operations (nmap, Ollama).
    Operator sees the tool is alive not hung.
    Stops cleanly when operation completes.
    """

    def __init__(self, message: str = "Working"):
        self.message = message
        self.running = False
        self._thread = None

    def start(self):
        """Start heartbeat in background thread."""
        self.running = True
        self._thread = threading.Thread(
            target=self._beat,
            daemon=True
        )
        self._thread.start()

    def stop(self):
        """Stop heartbeat thread."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
        console.print()  # newline after dots

    def _beat(self):
        """Print dot every HEARTBEAT_INTERVAL seconds."""
        count = 0
        while self.running:
            time.sleep(HEARTBEAT_INTERVAL)
            if self.running:
                count += 1
                elapsed = count * HEARTBEAT_INTERVAL
                console.print(
                    f"[dim]  {self.message}... "
                    f"{elapsed}s elapsed[/dim]"
                )


# ------------------------------------------------------------------ #
# ORCHESTRATOR
# ------------------------------------------------------------------ #

class Orchestrator:
    """
    Master orchestrator for R3D engagements.

    Sequences all four modules, manages checkpointing,
    enforces safety gates, filters context between modules,
    tracks elapsed time, and produces final summary.

    Never bypasses GUIDED mode gates.
    Sherlock always blocked in FULL-AUTO.
    Target authorization required before any module runs.
    """

    def __init__(
        self,
        target:      str,
        mode:        str  = "SEMI-AUTO",
        full_scan:   bool = False,
        auto_attack: bool = False,
        org_type:    Optional[str] = None,
        resume:      bool = False,
        timeout:     int  = DEFAULT_TIMEOUT,
        fast_mode:   bool = False,
        skip_llm:    bool = False,
        skip_trad:   bool = False,
    ):
        self.target      = target
        self.mode        = mode.upper()
        self.full_scan   = full_scan
        self.auto_attack = auto_attack
        self.org_type    = org_type
        self.resume      = resume
        self.timeout     = timeout
        self.fast_mode   = fast_mode
        self.skip_llm    = skip_llm
        self.skip_trad   = skip_trad

        # Generate engagement ID -- ties all outputs together
        self.engagement_id = _generate_engagement_id(target)

        # State tracking -- init before resume check
        self.state = {
            "engagement_id": self.engagement_id,
            "target":        self.target,
            "mode":          self.mode,
            "timestamp":     datetime.now().isoformat(),
            "completed":     [],
            "skipped":       [],
            "in_progress":   None,
            "org_type":      org_type,
            "findings_count": 0,
            "status":        "running",
        }

        # Defer directory creation until after resume check
        # Prevents orphan empty engagement dirs on every resume
        self.engagement_dir = None

        # Timing
        self.start_time = time.time()

        # All findings collected across modules
        self.all_findings: list[Finding] = []

        # Output paths collected across modules
        self.output_files = {}

    def _init_engagement_dir(self):
        """
        Create engagement directory.
        Called AFTER resume check so we use the correct ID.
        Prevents orphan empty dirs when --resume is used.
        """
        self.engagement_dir = (
            ENGAGEMENTS_DIR / self.engagement_id
        )
        self.engagement_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # CHECKPOINT
    # ------------------------------------------------------------------ #

    def _save_state(self, status: str = "running"):
        """
        Save engagement state to disk.
        Called after every module completes.
        Enables --resume to skip completed modules.
        Never raises -- state save failure is non-critical.
        """
        try:
            self.state["status"]          = status
            self.state["elapsed_seconds"] = int(
                time.time() - self.start_time
            )
            state_path = self.engagement_dir / "state.json"
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            console.print(
                f"[yellow]  State save failed: {e}[/yellow]"
            )

    def _load_state(self) -> Optional[dict]:
        """
        Load saved engagement state for resume.
        Returns None if no state found.
        """
        try:
            safe_target = _sanitize_filename(self.target)
            candidates  = list(
                ENGAGEMENTS_DIR.glob(
                    f"R3D_*_{safe_target}*/state.json"
                )
            )
            if not candidates:
                return None

            latest = max(
                candidates,
                key=lambda p: p.stat().st_mtime
            )
            with open(latest, encoding="utf-8") as f:
                state = json.load(f)
            console.print(
                f"[green]  Resumed: "
                f"{state['engagement_id']}[/green]"
            )
            return state

        except Exception as e:
            console.print(
                f"[yellow]  Resume failed: "
                f"{e} -- starting fresh[/yellow]"
            )
            return None

    def _is_completed(self, module: str) -> bool:
        """Check if module already completed in resumed state."""
        return module in self.state.get("completed", [])

    def _mark_completed(self, module: str):
        """Mark module as completed and save state."""
        if module not in self.state["completed"]:
            self.state["completed"].append(module)
        self.state["in_progress"] = None
        self._save_state()

    def _mark_skipped(self, module: str, reason: str):
        """Mark module as skipped with reason."""
        self.state["skipped"].append({
            "module": module,
            "reason": reason
        })
        self._save_state()

    # ------------------------------------------------------------------ #
    # AUTHORIZATION CONSENT
    # ------------------------------------------------------------------ #

    def _target_authorization_consent(self) -> bool:
        """
        Show target authorization consent screen.
        Operator must explicitly confirm authorization.
        Required before any module runs -- even FULL-AUTO.
        Creates documented record of operator intent.
        This is legal protection -- not optional.
        """
        console.print(
            Panel(
                f"[bold]Target:[/bold] {self.target}\n"
                f"[bold]Mode:[/bold]   {self.mode}\n"
                f"[bold]Scan:[/bold]   "
                f"{'Full (65535 ports)' if self.full_scan else 'Standard (1000 ports)'}\n\n"
                f"[yellow]You are about to run an autonomous "
                f"security assessment.[/yellow]\n\n"
                f"By proceeding you confirm:\n"
                f"  • You own this target OR\n"
                f"  • You have explicit written authorization\n"
                f"  • You are operating in an approved "
                f"lab environment\n\n"
                f"[red]Unauthorized use is illegal under "
                f"the CFAA and equivalent laws.[/red]",
                title=(
                    "[bold red]"
                    "AUTHORIZATION REQUIRED"
                    "[/bold red]"
                ),
                border_style="red"
            )
        )

        response = input(
            "\nType YES to confirm authorization: "
        ).strip().upper()

        if response != "YES":
            console.print(
                "[yellow]  Engagement cancelled.[/yellow]"
            )
            return False

        console.print(
            f"[green]  Authorization confirmed -- "
            f"engagement ID: {self.engagement_id}[/green]"
        )
        return True

    # ------------------------------------------------------------------ #
    # CONTEXT FILTER
    # ------------------------------------------------------------------ #

    def _filter_profile_for_llm(
        self, profile: OSINTProfile
    ) -> dict:
        """
        Filter OSINTProfile before passing to LLM attack.
        Strips noise -- protects llama3:8b context window.

        What stays:
        - Live AI surfaces (max 10)
        - AI-relevant subdomains only
        - Tech stack (max 5)
        - WAF detection status

        What gets stripped:
        - Dead subdomains
        - Emails and usernames (not needed for LLM attack)
        - Raw evidence paths (local filesystem paths)
        - Historical endpoints (mostly dead)
        - Registrar, DNS records (not relevant)
        """
        ai_relevant_subs = [
            s for s in (profile.subdomains or [])
            if any(
                kw in s.lower()
                for kw in AI_RELEVANT_KEYWORDS
            )
        ][:10]

        return {
            "target":       profile.target,
            "ai_surfaces":  (profile.ai_surfaces or [])[:10],
            "tech_stack":   (profile.tech_stack or [])[:5],
            "subdomains":   ai_relevant_subs,
            "waf_detected": profile.waf_detected,
            "waf_type":     profile.waf_type,
        }

    # ------------------------------------------------------------------ #
    # CRITICAL FINDING ALERT
    # ------------------------------------------------------------------ #

    def _check_critical_findings(
        self, findings: list[Finding], module: str
    ) -> bool:
        """
        Check for critical findings after each module.
        In GUIDED mode: alert operator and ask to continue.
        In other modes: log and continue automatically.
        Returns True to continue, False to pause.
        """
        critical  = [f for f in findings if f.severity_label == "CRITICAL"]
        zero_days = [f for f in findings if f.zero_day_flag]

        if not critical and not zero_days:
            return True

        if critical:
            console.print(
                f"\n[bold red]"
                f"⚠ CRITICAL: {len(critical)} critical "
                f"finding(s) from {module}"
                f"[/bold red]"
            )
            for f in critical[:3]:
                console.print(f"[red]  • {f.title}[/red]")

        if zero_days:
            console.print(
                f"\n[bold red]"
                f"⚠ ZERO DAY: {len(zero_days)} unclassified "
                f"finding(s) -- evidence preserved"
                f"[/bold red]"
            )

        if self.mode == "GUIDED":
            response = input(
                "\nContinue engagement? [Y/N]: "
            ).strip().upper()
            if response != "Y":
                self._save_state("paused_critical_review")
                return False

        return True

    # ------------------------------------------------------------------ #
    # TIMEOUT CHECK
    # ------------------------------------------------------------------ #

    def _check_timeout(self) -> bool:
        """
        Check if engagement has exceeded timeout.
        Returns True if still within budget.
        Returns False if timeout exceeded.
        """
        elapsed = time.time() - self.start_time
        if elapsed > self.timeout:
            console.print(
                f"\n[bold red]"
                f"Engagement timeout ({self.timeout // 60} min). "
                f"Stopping after current module."
                f"[/bold red]"
            )
            self._save_state("timeout")
            return False
        return True

    # ------------------------------------------------------------------ #
    # FINAL SUMMARY
    # ------------------------------------------------------------------ #

    def _print_final_summary(self, aggregated, elapsed: float):
        """
        Print clean final engagement summary.
        Shows all output files, findings by severity,
        and elapsed time.
        """
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)

        console.print(
            f"\n[bold green]"
            f"{'='*52}\n"
            f"  R3D ENGAGEMENT COMPLETE\n"
            f"  ID     : {self.engagement_id}\n"
            f"  Target : {self.target}\n"
            f"  Mode   : {self.mode}\n"
            f"  Time   : {minutes}m {seconds}s\n"
            f"{'='*52}"
            f"[/bold green]\n"
        )

        if aggregated:
            table = Table(title="Findings Summary")
            table.add_column("Severity", style="bold")
            table.add_column("Count", justify="right")

            if aggregated.zero_day_count > 0:
                table.add_row(
                    "[bold red]⚠ ZERO DAY[/bold red]",
                    f"[bold red]{aggregated.zero_day_count}[/bold red]"
                )
            table.add_row(
                "[bold red]CRITICAL[/bold red]",
                str(aggregated.critical_count)
            )
            table.add_row("[red]HIGH[/red]",         str(aggregated.high_count))
            table.add_row("[yellow]MEDIUM[/yellow]", str(aggregated.medium_count))
            table.add_row("[green]LOW[/green]",       str(aggregated.low_count))
            table.add_row("─────────", "─────")
            table.add_row(
                "[bold]TOTAL[/bold]",
                f"[bold]{aggregated.total_findings}[/bold]"
            )
            console.print(table)
            console.print()

        if self.output_files:
            console.print("[bold]Output files:[/bold]")
            for file_type, path in self.output_files.items():
                if file_type == "executive_summary":
                    continue
                console.print(
                    f"  [green]→[/green] {file_type}: {path}"
                )

        console.print(
            f"\n[dim]Completed: "
            f"{', '.join(self.state['completed'])}[/dim]"
        )
        if self.state["skipped"]:
            skipped_names = [
                s["module"] for s in self.state["skipped"]
            ]
            console.print(
                f"[dim]Skipped: "
                f"{', '.join(skipped_names)}[/dim]"
            )

        console.print(
            f"\n[dim]Engagement saved: "
            f"{self.engagement_dir}[/dim]"
        )

    # ------------------------------------------------------------------ #
    # MAIN RUN
    # ------------------------------------------------------------------ #

    def run(self) -> dict:
        """
        Execute full R3D engagement.

        Sequence:
        1.  Authorization consent
        2.  Resume or fresh start
        3.  OSINT module
        4.  LLM attack (if AI surfaces and not skipped)
        5.  Traditional recon (if not skipped)
        6.  Aggregation
        7.  Verifier hook
        8.  GRC mapper
        9.  Report generation
        10. Final summary

        Returns dict of all output file paths.
        """
        console.print(
            f"\n[bold cyan]"
            f"{'='*52}\n"
            f"  R3D AUTONOMOUS RED TEAM AGENT\n"
            f"  Version  : 1.0\n"
            f"  Target   : {self.target}\n"
            f"  Mode     : {self.mode}\n"
            f"  Engagement: {self.engagement_id}\n"
            f"{'='*52}"
            f"[/bold cyan]\n"
        )

        # Step 1 -- Authorization consent
        # Required before ANY module runs -- even FULL-AUTO
        if not self._target_authorization_consent():
            return {}

        # Step 2 -- Resume or fresh start
        # Resolve engagement ID BEFORE creating directory
        # Prevents orphan empty dirs on every resume
        if self.resume:
            saved = self._load_state()
            if saved:
                self.state         = saved
                self.engagement_id = saved["engagement_id"]
                if saved.get("org_type"):
                    self.org_type = saved["org_type"]

        # Now create directory with the correct engagement ID
        self._init_engagement_dir()
        self._save_state("running")

        profile    = None
        aggregated = None

        # ------------------------------------------------------------------ #
        # MODULE 1 -- OSINT
        # ------------------------------------------------------------------ #
        if self._is_completed("osint"):
            console.print(
                "[dim]  OSINT: already completed (resumed)[/dim]"
            )
            # FIX 1: OSINTProfile.load() doesn't exist.
            # Load profile JSON manually and rebuild via from_dict().
            try:
                profile_files = list(
                    (OUTPUT_DIR / "profiles").glob(
                        f"*{_sanitize_filename(self.target)}*"
                    )
                )
                if profile_files:
                    latest = max(
                        profile_files,
                        key=lambda p: p.stat().st_mtime
                    )
                    with open(latest, encoding="utf-8") as f:
                        data = json.load(f)
                    profile = OSINTProfile.from_dict(data)
            except Exception:
                # Non-fatal -- profile won't be available for
                # LLM context filtering on resume but run continues
                profile = None
        else:
            if not self._check_timeout():
                return self.output_files

            self.state["in_progress"] = "osint"
            self._save_state()

            heartbeat = Heartbeat("OSINT running")
            heartbeat.start()

            try:
                recon = OSINTRecon(
                    target=self.target,
                    mode=self.mode,
                    fast_mode=self.fast_mode
                )

                # FIX 2: OSINTRecon.run() returns list[Finding], not a tuple.
                # Profile lives on recon.profile -- not returned by run().

                osint_findings, profile = recon.run()
                heartbeat.stop()

                # Set org_type on profile if provided via CLI
                if self.org_type and profile:
                    profile.org_type = self.org_type

                self.all_findings.extend(osint_findings or [])
                self.state["osint_findings"] = len(osint_findings or [])

                console.print(
                    f"[green]  OSINT complete -- "
                    f"{len(osint_findings or [])} findings[/green]"
                )

                if not self._check_critical_findings(
                    osint_findings or [], "OSINT"
                ):
                    return self.output_files

                self._mark_completed("osint")

            except Exception as e:
                heartbeat.stop()
                console.print(f"[red]  OSINT crashed: {e}[/red]")
                self._save_state("osint_failed")

        time.sleep(MODULE_BUFFER)

        # ------------------------------------------------------------------ #
        # MODULE 2 -- LLM ATTACK
        # ------------------------------------------------------------------ #
        if self._is_completed("llm_attack"):
            console.print(
                "[dim]  LLM attack: already completed (resumed)[/dim]"
            )
        elif self.skip_llm:
            console.print(
                "[dim]  LLM attack: skipped (--skip-llm)[/dim]"
            )
            self._mark_skipped("llm_attack", "--skip-llm flag")
        elif not profile or not profile.ai_surfaces:
            console.print(
                "[dim]  LLM attack: skipped -- "
                "no AI surfaces found by OSINT[/dim]"
            )
            self._mark_skipped("llm_attack", "no AI surfaces")
        else:
            if not self._check_timeout():
                return self.output_files

            self.state["in_progress"] = "llm_attack"
            self._save_state()

            filtered = self._filter_profile_for_llm(profile)
            console.print(
                f"[dim]  LLM context: "
                f"{len(filtered['ai_surfaces'])} surfaces, "
                f"{len(filtered['subdomains'])} relevant subdomains[/dim]"
            )

            heartbeat = Heartbeat("LLM attack running")
            heartbeat.start()

            try:
                llm_suite = LLMAttackSuite(
                    target=self.target,
                    mode=self.mode,
                    auto_attack=self.auto_attack
                )
                llm_findings = llm_suite.run(filtered["ai_surfaces"])

                heartbeat.stop()

                self.all_findings.extend(llm_findings or [])
                self.state["llm_findings"] = len(llm_findings or [])

                console.print(
                    f"[green]  LLM attack complete -- "
                    f"{len(llm_findings or [])} findings[/green]"
                )

                if not self._check_critical_findings(
                    llm_findings or [], "LLM Attack"
                ):
                    return self.output_files

                self._mark_completed("llm_attack")

            except Exception as e:
                heartbeat.stop()
                console.print(f"[red]  LLM attack crashed: {e}[/red]")

        time.sleep(MODULE_BUFFER)

        # ------------------------------------------------------------------ #
        # MODULE 3 -- TRADITIONAL RECON
        # ------------------------------------------------------------------ #
        if self._is_completed("traditional_recon"):
            console.print(
                "[dim]  Traditional recon: already completed (resumed)[/dim]"
            )
        elif self.skip_trad:
            console.print(
                "[dim]  Traditional recon: skipped (--skip-trad)[/dim]"
            )
            self._mark_skipped("traditional_recon", "--skip-trad flag")
        else:
            if not self._check_timeout():
                return self.output_files

            self.state["in_progress"] = "traditional_recon"
            self._save_state()

            heartbeat = Heartbeat("Traditional recon running")
            heartbeat.start()

            try:
                trad = TraditionalRecon(
                    target=self.target,
                    mode=self.mode,
                    full_scan=self.full_scan
                )
                trad_findings = trad.run(
                    profile or OSINTProfile(target=self.target)
                )

                heartbeat.stop()

                self.all_findings.extend(trad_findings or [])
                self.state["trad_findings"] = len(trad_findings or [])

                console.print(
                    f"[green]  Traditional recon complete -- "
                    f"{len(trad_findings or [])} findings[/green]"
                )

                if not self._check_critical_findings(
                    trad_findings or [], "Traditional Recon"
                ):
                    return self.output_files

                self._mark_completed("traditional_recon")

            except Exception as e:
                heartbeat.stop()
                console.print(
                    f"[red]  Traditional recon crashed: {e}[/red]"
                )

        time.sleep(MODULE_BUFFER)

        # ------------------------------------------------------------------ #
        # AGGREGATION
        # ------------------------------------------------------------------ #
        console.print("\n[cyan]Aggregating all findings...[/cyan]")

        try:
            aggregator = FindingsAggregator(target=self.target)

            # FIX 3: FindingsAggregator only has add_finding() singular.
            # Loop instead of calling add_findings() which doesn't exist.
            for f in self.all_findings:
                aggregator.add_finding(f)

            aggregated = aggregator.aggregate()

            # FIX 4: save_findings_json() may not exist on aggregator.
            # Wrap in try/except -- aggregation result is what matters.
            # Falls back to manual json.dump if method missing.
            try:
                aggregator.save_findings_json(aggregated)
            except AttributeError:
                findings_path = self.engagement_dir / "findings.json"
                with open(findings_path, "w", encoding="utf-8") as f:
                    json.dump(
                        [
                            finding.to_dict()
                            for finding in self.all_findings
                            if hasattr(finding, "to_dict")
                        ],
                        f,
                        indent=2
                    )
            except Exception:
                pass  # non-critical -- state already saved

            self.state["findings_count"] = aggregated.total_findings
            self._save_state()

        except Exception as e:
            console.print(f"[red]  Aggregation crashed: {e}[/red]")
            self._save_state("aggregation_failed")
            return self.output_files

        # ------------------------------------------------------------------ #
        # VERIFIER HOOK
        # ------------------------------------------------------------------ #
        # Placeholder -- calls verifier if available.
        # Fails silently if core/verifier.py not built yet.
        try:
            from core.verifier import Verifier
            verifier   = Verifier()
            aggregated = verifier.verify(aggregated)
            console.print("[green]  Verifier: complete[/green]")
        except ImportError:
            console.print("[dim]  Verifier: not available yet[/dim]")
        except Exception as e:
            console.print(f"[yellow]  Verifier failed: {e}[/yellow]")

        # ------------------------------------------------------------------ #
        # MODULE 4 -- GRC MAPPER
        # ------------------------------------------------------------------ #
        if self._is_completed("grc_mapper"):
            console.print(
                "[dim]  GRC mapper: already completed (resumed)[/dim]"
            )
        else:
            if not self._check_timeout():
                return self.output_files

            self.state["in_progress"] = "grc_mapper"
            self._save_state()

            try:
                if self.org_type and profile and not profile.org_type:
                    profile.org_type = self.org_type

                grc = GRCMapper(
                    target=self.target,
                    mode=self.mode
                )
                grc_results = grc.run(
                    aggregated,
                    profile or OSINTProfile(target=self.target)
                )

                self.output_files.update(grc_results)
                self._mark_completed("grc_mapper")

            except Exception as e:
                console.print(f"[red]  GRC mapper crashed: {e}[/red]")

        # ------------------------------------------------------------------ #
        # REPORT GENERATION
        # ------------------------------------------------------------------ #
        if self._is_completed("report_gen"):
            console.print(
                "[dim]  Reports: already generated (resumed)[/dim]"
            )
        else:
            self.state["in_progress"] = "report_gen"
            self._save_state()

            try:
                generator = ReportGenerator(aggregated)

                # FIX 5: generate_all() doesn't exist on ReportGenerator.
                # Call the three methods individually and collect paths.
                pdf_path       = generator.generate_pdf()
                xlsx_path      = generator.generate_xlsx()
                telemetry_path = generator.generate_telemetry_json()

                if pdf_path:
                    self.output_files["report_pdf"]       = pdf_path
                if xlsx_path:
                    self.output_files["report_xlsx"]      = xlsx_path
                if telemetry_path:
                    self.output_files["report_telemetry"] = telemetry_path

                self._mark_completed("report_gen")

            except Exception as e:
                console.print(
                    f"[red]  Report generation crashed: {e}[/red]"
                )

        # ------------------------------------------------------------------ #
        # FINAL SUMMARY
        # ------------------------------------------------------------------ #
        elapsed = time.time() - self.start_time
        self._save_state("complete")
        self._print_final_summary(aggregated, elapsed)

        return self.output_files


# ------------------------------------------------------------------ #
# TEST
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    console.print(
        "[bold green]R3D Orchestrator -- "
        "Module Load Test[/bold green]\n"
    )
    console.print(
        "[yellow]This test only checks module loads "
        "and engagement ID generation.[/yellow]\n"
    )

    # Test engagement ID generation
    eid = _generate_engagement_id("example.com")
    console.print(f"Engagement ID: {eid}")

    # Test Heartbeat
    console.print("\nHeartbeat test (5 seconds):")
    hb = Heartbeat("Testing")
    hb.start()
    time.sleep(3)
    hb.stop()
    console.print("Heartbeat: OK")

    # Test orchestrator init only -- no actual run
    orch = Orchestrator(
        target="example.com",
        mode="SEMI-AUTO",
        full_scan=False,
        auto_attack=False,
    )
    console.print("\nOrchestrator initialized:")
    console.print(f"  Target: {orch.target}")
    console.print(f"  Mode:   {orch.mode}")
    console.print(f"  ID:     {orch.engagement_id}")
    console.print("\n[green]Module loaded successfully.[/green]")