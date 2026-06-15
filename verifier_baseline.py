"""
R3D Agent -- Verifier Module (BASELINE with Metrics)
=====================================================
PURPOSE:
    Original single-pass verifier with a statistical observation layer added.
    Zero verification logic changed -- only watching and recording.
    This is the control group. Run this first, then run verifier_agentic.py
    against the same targets, compare the output JSONs.

WHY THIS EXISTS:
    The agentic verifier claims improvement:
        - Fewer LLM calls (~70-80% reduction)
        - Lower hallucination rate (32% -> 4%)
        - Better F1 score
    None of those claims mean anything without a baseline to compare against.

HOW TO USE (exact terminal commands at bottom of file):
    Step 1: Copy this into core/ renamed as verifier.py
    Step 2: Run R3D against your TryHackMe/HackTheBox target
    Step 3: Collect the _BASELINE_metrics.json from output/reports/
    Step 4: Do this for 3 different targets
    Step 5: Swap in verifier_agentic.py, repeat same targets
    Step 6: Run compare_metrics.py to see the delta

MIKAYLA'S DFIR-METRIC SCORING INTEGRATED HERE:
    Her Reliability Score (RS) formula:
        correct answer  -> +1
        wrong answer    -> -2  (hallucination penalty is 2x the reward)
        skip/unknown    -> 0
        RS = sum(all scores) / k   where k = number of labeled findings

    Why -2 for wrong matters in security:
        A hallucinated CVE that slips through means a real vulnerability
        stays open. The penalty must be heavier than the reward.
        Negative RS = verifier is net-harmful (hallucinates more than it catches).

    Her Confidence Index (CI) maps to our per-finding confidence tracking --
    we record which findings are borderline so you can cross-reference
    with her benchmark's CI scores later.

    Her Task Success Rate (TSR) = our correct_decision_rate in the output.

BUILDING YOUR LABELED TEST SET:
    After each engagement, open output/TIMESTAMP_findings.json
    Go through every finding with source_module = "llm_attack"
    For each one ask: "Is this finding real and accurately described?"
    Build a dict: {"Finding title exactly as shown": True or False}
    True  = real finding, accurate CVE, correct severity
    False = hallucinated, wrong CVE, inflated severity, too vague
    Pass that dict to verify() as ground_truth_map=your_dict
    Start with 10-15 findings per engagement, grow to 50-100 total
"""

import json
import time
import requests
from difflib import SequenceMatcher
from datetime import datetime
from pathlib import Path
from typing import Optional
from rich.console import Console

from core.findings import Finding, FindingsAggregator, AggregatedFindings
from core.llm_client import query_llm, LLMResponse

console = Console()

# ------------------------------------------------------------------ #
# PATHS
# ------------------------------------------------------------------ #
BASE_DIR    = Path(__file__).parent.parent
OUTPUT_DIR  = BASE_DIR / "output"
LOGS_DIR    = OUTPUT_DIR / "attack_logs"
REPORTS_DIR = OUTPUT_DIR / "reports"

# ------------------------------------------------------------------ #
# THRESHOLDS -- DO NOT CHANGE FOR BASELINE
# Changing these would make the baseline no longer represent the original.
# ------------------------------------------------------------------ #
SEVERITY_REMOVE_THRESHOLD  = 3.0   # below this -> finding removed
SEVERITY_FLAG_THRESHOLD    = 5.0   # below this -> finding flagged uncertain
DEDUP_SIMILARITY_THRESHOLD = 0.85  # difflib ratio for duplicate detection

# ------------------------------------------------------------------ #
# NVD API
# ------------------------------------------------------------------ #
NVD_CVE_URL         = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
NVD_REQUEST_TIMEOUT = 10


# ================================================================== #
# PYDANTIC COMPATIBILITY
# Finding is immutable -- always use _copy_finding(), never mutate directly.
# Handles both Pydantic v1 (.copy/.dict) and v2 (.model_copy/.model_dump).
# ================================================================== #

def _copy_finding(finding: Finding, updates: dict) -> Finding:
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
    if hasattr(finding, "model_dump"):
        return finding.model_dump()
    elif hasattr(finding, "dict"):
        return finding.dict()
    else:
        return {k: v for k, v in finding.__dict__.items() if not k.startswith("_")}


# ================================================================== #
# BASELINE METRICS
# Pure observation layer. Records what the original verifier does.
# Does not influence any verification decision.
# ================================================================== #

class BaselineMetrics:
    """
    Statistical recorder for the original single-pass verifier.

    METRICS TRACKED:
        LLM usage:
            llm_calls       -- total Ollama calls made this engagement
            llm_call_rate   -- LLM calls as % of LLM findings processed
                               (KEY comparison metric vs agentic version)

        Runtime:
            total_runtime_s         -- wall clock time entire engagement
            avg_finding_time_s      -- average time spent per LLM finding
            (no pass1/pass2 split because original has no passes)

        Per-finding records:
            disposition     -- what happened: pass/flag/remove/duplicate
            llm_called      -- did THIS specific finding trigger an LLM call
            processing_time -- seconds spent on this finding
            checks_failed   -- exactly which check caused the disposition
                               e.g. ["cve_not_in_nvd", "severity_2.5_below_3.0"]

        Ground truth metrics (requires labeled test set):
            reliability_score_RS  -- Mikayla's DFIR-Metric RS formula
                                     +1 correct, -2 wrong, 0 skip, avg by k
                                     Negative RS = net harmful verifier
            false_negatives       -- hallucinations that slipped through as passed
                                     This is the dangerous one in security
            false_positives       -- real findings incorrectly removed
            hallucination_rate    -- false_negatives as % of labeled findings
            precision             -- of everything passed, how many were real
            recall                -- of all real findings, how many were caught
            f1_score              -- harmonic mean of precision/recall
                                     Single best number for baseline vs agentic comparison
            correct_decision_rate -- Mikayla's TSR equivalent
    """

    def __init__(self):
        self.engagement_start = time.time()
        self.llm_calls        = 0
        self.finding_records  = []
        self.total_runtime    = 0.0

    def record_finding(
        self,
        finding:         Finding,
        disposition:     str,
        llm_called:      bool,
        processing_time: float,
        checks_failed:   list,
        ground_truth:    Optional[bool] = None
    ):
        """
        Record a single finding's outcome.
        Called once per LLM finding after all checks complete.

        ground_truth: True = real finding, False = hallucinated/wrong
                      None = not labeled yet (live engagement without test set)
        """
        if llm_called:
            self.llm_calls += 1

        record = {
            "finding_title":     finding.title,
            "finding_type":      finding.finding_type,
            "severity_score":    finding.severity_score,
            "has_cve":           bool(finding.cve_id),
            "disposition":       disposition,
            "llm_called":        llm_called,
            "processing_time_s": round(processing_time, 4),
            "checks_failed":     checks_failed,
            "ground_truth":      ground_truth,
            # Whether the verifier made the correct call:
            # passed a real finding -> True
            # removed a fake finding -> True
            # passed a fake finding -> False (hallucination slipped through)
            # removed a real finding -> False (missed real vulnerability)
            "correct_decision":  self._score_decision(disposition, ground_truth),
            "timestamp":         datetime.now().isoformat(),
        }
        self.finding_records.append(record)

    def _score_decision(
        self, disposition: str, ground_truth: Optional[bool]
    ) -> Optional[bool]:
        """Score the verifier's decision. None if no ground truth provided."""
        if ground_truth is None:
            return None
        if disposition in ("pass", "flag"):
            return ground_truth is True
        if disposition in ("remove", "duplicate"):
            return ground_truth is False
        return None

    def _reliability_score(self, labeled: list) -> Optional[float]:
        """
        Mikayla's DFIR-Metric Reliability Score (RS).

        RS = sum(score_i) / k
            +1 for each correct decision
            -2 for each wrong decision  <-- 2x penalty for hallucinations
             0 for unlabeled findings

        k = number of labeled findings (not total questions like in her paper,
        but the principle is the same -- penalize wrong harder than reward right)

        Negative RS means the verifier is causing net harm.
        This is the strictest metric and the most meaningful for security.
        """
        if not labeled:
            return None

        total_score = sum(
            1 if r["correct_decision"] is True
            else -2 if r["correct_decision"] is False
            else 0
            for r in labeled
        )
        return round(total_score / len(labeled), 4)

    def summary(self) -> dict:
        """Compute all statistics. Call after engagement completes."""
        self.total_runtime = time.time() - self.engagement_start
        total              = len(self.finding_records)

        if total == 0:
            return {
                "version": "baseline_single_pass",
                "error": (
                    "No LLM findings processed. "
                    "Target had no AI surfaces so LLM attack module did not fire. "
                    "Use a TryHackMe/HackTheBox machine with an LLM endpoint."
                )
            }

        passed     = [r for r in self.finding_records if r["disposition"] == "pass"]
        flagged    = [r for r in self.finding_records if r["disposition"] == "flag"]
        removed    = [r for r in self.finding_records if r["disposition"] == "remove"]
        duplicates = [r for r in self.finding_records if r["disposition"] == "duplicate"]
        labeled    = [r for r in self.finding_records if r["ground_truth"] is not None]

        # False negatives = hallucinations that passed (the dangerous case)
        false_negatives = [
            r for r in labeled
            if r["disposition"] in ("pass", "flag") and r["ground_truth"] is False
        ]
        # False positives = real findings that were removed
        false_positives = [
            r for r in labeled
            if r["disposition"] in ("remove", "duplicate") and r["ground_truth"] is True
        ]
        correct = [r for r in labeled if r["correct_decision"] is True]

        # Standard classification metrics
        tp = len([r for r in labeled if r["disposition"] in ("pass","flag") and r["ground_truth"] is True])
        fp = len(false_negatives)
        fn = len(false_positives)

        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall    = tp / (tp + fn) if (tp + fn) > 0 else None
        f1        = (
            2 * precision * recall / (precision + recall)
            if precision and recall else None
        )
        avg_time  = sum(r["processing_time_s"] for r in self.finding_records) / total
        rs        = self._reliability_score(labeled)
        cdr       = len(correct) / len(labeled) if labeled else None  # Mikayla's TSR equivalent

        return {
            "version":            "baseline_single_pass",
            "generated_at":       datetime.now().isoformat(),

            # Runtime -- no pass split because original has no passes
            "total_runtime_s":    round(self.total_runtime, 2),
            "avg_finding_time_s": round(avg_time, 4),

            # LLM usage -- KEY comparison metric
            # In original, LLM called on every finding for dedup
            # Agentic should show 70-80% reduction here
            "llm_calls":          self.llm_calls,
            "llm_call_rate":      (
                f"{self.llm_calls}/{total} "
                f"({100*self.llm_calls//total}%)"
            ),

            "findings_processed": total,
            "dispositions": {
                "passed":     len(passed),
                "flagged":    len(flagged),
                "removed":    len(removed),
                "duplicates": len(duplicates),
            },

            # Ground truth metrics -- populated when labeled test set provided
            "ground_truth_metrics": {
                "labeled_findings": len(labeled),
                "note": (
                    "Provide ground_truth_map to verify() to populate these. "
                    "Build it by manually reviewing _findings.json after engagement."
                ) if not labeled else f"{len(labeled)} findings labeled.",

                # Mikayla's RS -- most important metric
                # Negative = net harmful, 0 = random, positive = useful
                "reliability_score_RS": (
                    rs if rs is not None else "N/A -- no labeled set provided"
                ),

                # Mikayla's TSR equivalent
                "correct_decision_rate": (
                    round(cdr, 4) if cdr is not None else "N/A"
                ),

                # Security-specific metrics
                "false_negatives":   len(false_negatives),
                "false_positives":   len(false_positives),
                "correct_decisions": len(correct),
                "hallucination_rate": (
                    f"{100*len(false_negatives)//len(labeled)}%"
                    if labeled else "N/A"
                ),

                # Standard ML metrics
                "precision": round(precision, 4) if precision else "N/A",
                "recall":    round(recall, 4)    if recall    else "N/A",

                # F1 -- single best comparison number between baseline and agentic
                "f1_score":  round(f1, 4)        if f1        else "N/A",
            },

            # Full per-finding records for cross-engagement analysis
            # and for Mikayla's CI (consistency across runs) calculation
            "finding_records": self.finding_records,
        }

    def save(self, target: str) -> Path:
        """
        Save metrics to timestamped JSON in output/reports/.
        Nothing is ever overwritten -- each engagement adds a new file.
        Filename format: TIMESTAMP_TARGET_BASELINE_metrics.json
        """
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        ts   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = REPORTS_DIR / f"{ts}_{target}_BASELINE_metrics.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.summary(), f, indent=2)
        console.print(f"[cyan]  Baseline metrics saved: {path}[/cyan]")
        return path


# ================================================================== #
# VERIFIER -- original logic, metrics layer added
# ================================================================== #

class Verifier:
    """
    Original single-pass verifier. Metrics recorded, logic unchanged.

    ORIGINAL PIPELINE (unchanged):
        For each LLM finding:
        1. CVE validation  -> NVD API lookup, strip if not found
        2. Severity check  -> remove if < 3.0, flag if < 5.0
        3. Evidence check  -> annotate if file missing
        4. Dedup           -> Ollama yes/no similarity (LLM called here)

    WHAT CHANGED:
        - Timing added per finding
        - checks_failed list populated per step
        - llm_called tracked per finding
        - BaselineMetrics.record_finding() called after each finding
        - ground_truth_map optional param for labeled test set scoring
    """

    def __init__(self):
        self.nvd_available    = True
        self.ollama_available = True
        self.metrics          = BaselineMetrics()
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

    def _validate_cve(self, finding: Finding) -> tuple:
        """
        NVD API lookup by CVE ID.
        Fail open: if NVD unreachable, finding survives.
        Only strips CVE when NVD actively confirms it does not exist.
        Returns (finding, checks_failed_list).
        """
        if not finding.cve_id or not self.nvd_available:
            return finding, []

        cve_id, checks_failed = finding.cve_id.strip(), []

        try:
            resp = requests.get(
                NVD_CVE_URL.format(cve_id=cve_id),
                timeout=NVD_REQUEST_TIMEOUT,
                headers={"User-Agent": "R3D-Verifier/1.0"}
            )
            if resp.status_code == 200:
                if resp.json().get("totalResults", 0) > 0:
                    console.print(f"[dim]    CVE confirmed: {cve_id}[/dim]")
                    return finding, []
                checks_failed.append("cve_not_in_nvd")
                return self._strip_cve(finding, "not found in NVD"), checks_failed
            elif resp.status_code == 404:
                checks_failed.append("cve_404_from_nvd")
                return self._strip_cve(finding, "404 from NVD"), checks_failed
            return finding, []

        except requests.Timeout:
            console.print("[yellow]  NVD timeout -- CVE validation skipped[/yellow]")
            self.nvd_available = False
            return finding, []
        except requests.ConnectionError:
            console.print("[yellow]  NVD unreachable -- CVE validation skipped[/yellow]")
            self.nvd_available = False
            return finding, []
        except Exception:
            return finding, []

    def _strip_cve(self, finding: Finding, reason: str) -> Finding:
        """Strip unconfirmed CVE and downgrade severity."""
        console.print(f"[yellow]    CVE stripped: {finding.cve_id} ({reason})[/yellow]")
        self.stats["cve_stripped"] += 1
        return _copy_finding(finding, {
            "cve_id":         None,
            "cvss_score":     None,
            "severity_score": max(finding.severity_score - 1.5, SEVERITY_FLAG_THRESHOLD),
            "description": (
                f"{finding.description}\n"
                f"[VERIFIER: CVE {finding.cve_id} not confirmed by NVD -- stripped]"
            )
        })

    # ------------------------------------------------------------------ #
    # SEVERITY CHECK
    # ------------------------------------------------------------------ #

    def _check_severity(self, finding: Finding) -> tuple:
        """
        Threshold check on severity score.
        Returns (finding_or_None, disposition_str, checks_failed_list).
        """
        score, checks_failed = finding.severity_score, []

        if score < SEVERITY_REMOVE_THRESHOLD:
            checks_failed.append(
                f"severity_{score}_below_remove_threshold_{SEVERITY_REMOVE_THRESHOLD}"
            )
            return None, "removed_low_severity", checks_failed

        if score < SEVERITY_FLAG_THRESHOLD:
            checks_failed.append(
                f"severity_{score}_below_flag_threshold_{SEVERITY_FLAG_THRESHOLD}"
            )
            return _copy_finding(finding, {
                "description": (
                    f"{finding.description}\n"
                    f"[VERIFIER: Low confidence ({score:.1f}) -- flagged uncertain]"
                )
            }), "flagged_uncertain", checks_failed

        return finding, "passed", []

    # ------------------------------------------------------------------ #
    # EVIDENCE CHECK
    # ------------------------------------------------------------------ #

    def _check_evidence(self, finding: Finding) -> tuple:
        """
        Confirm evidence file exists on disk.
        Never removes -- only annotates if missing.
        Returns (finding, checks_failed_list).
        """
        if not finding.raw_evidence_path:
            return finding, []
        checks_failed = []
        try:
            if not Path(finding.raw_evidence_path).exists():
                checks_failed.append("evidence_file_missing_from_disk")
                return _copy_finding(finding, {
                    "description": (
                        f"{finding.description}\n"
                        f"[VERIFIER: Evidence file not found -- manual review recommended]"
                    )
                }), checks_failed
        except Exception:
            pass
        return finding, []

    # ------------------------------------------------------------------ #
    # SEMANTIC DEDUP
    # THIS IS WHERE THE LLM IS CALLED IN THE ORIGINAL VERIFIER.
    # The agentic version removes LLM from dedup entirely and
    # reserves it for Pass 2 reasoning on low-confidence findings only.
    # ------------------------------------------------------------------ #

    def _is_duplicate(self, finding: Finding, verified: list) -> tuple:
        """
        Duplicate check: Ollama first, difflib fallback.
        LLM called here on every finding -- this is what drives the high
        LLM call rate in the baseline.
        Returns (is_duplicate, llm_was_called).
        """
        if not verified:
            return False, False

        same_type = [f for f in verified if f.finding_type == finding.finding_type]
        if not same_type:
            return False, False

        llm_called = False
        for existing in same_type:
            if self.ollama_available:
                try:
                    llm_called = True
                    if self._ollama_similarity(finding.title, existing.title):
                        return True, llm_called
                except Exception:
                    self.ollama_available = False
                    llm_called = False

            # difflib fallback
            t_ratio = SequenceMatcher(None, finding.title.lower(), existing.title.lower()).ratio()
            d_ratio = SequenceMatcher(
                None,
                finding.description[:200].lower(),
                existing.description[:200].lower()
            ).ratio()
            if t_ratio > DEDUP_SIMILARITY_THRESHOLD and d_ratio > DEDUP_SIMILARITY_THRESHOLD:
                return True, llm_called

        return False, llm_called

    def _ollama_similarity(self, title_a: str, title_b: str) -> bool:
        """
        Yes/No LLM dedup question.
        This is what the agentic version replaces with CoT reasoning.
        """
        result: LLMResponse = query_llm(
            prompt=(
                f"Are these two security findings describing the same vulnerability?\n\n"
                f"Finding A: {title_a}\n"
                f"Finding B: {title_b}\n\n"
                f"Respond in JSON only:\n"
                f"{{\"duplicate\": true/false, \"reasoning\": \"one sentence\"}}"
            ),
            system_prompt="You are a precise security analyst. Respond only in valid JSON.",
            expect_json=True
        )
        if result and result.content:
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
    # MAIN VERIFY LOOP
    # ------------------------------------------------------------------ #

    def verify(
        self,
        aggregated:       AggregatedFindings,
        ground_truth_map: Optional[dict] = None
    ) -> AggregatedFindings:
        """
        Original single-pass verification with metrics observation added.

        ground_truth_map: {"Finding title exactly as shown": True/False}
            True  = real, accurate finding
            False = hallucinated or inaccurate
            Build this by manually reviewing _findings.json after each engagement.
            Leave as None for live engagements -- metrics will still record
            LLM calls, runtime, and dispositions, just not accuracy stats.
        """
        console.print(
            f"\n[cyan]  Verifier (BASELINE): reviewing "
            f"{aggregated.total_findings} findings...[/cyan]"
        )

        verified_findings:   list[Finding] = []
        deterministic_count: int           = 0

        for finding in aggregated.findings:

            # OSINT and traditional recon findings pass straight through.
            # Python is the authority for those -- no hallucination risk.
            if finding.source_module != "llm_attack":
                verified_findings.append(finding)
                deterministic_count += 1
                continue

            # -- Process LLM finding --
            self.stats["total_reviewed"] += 1
            finding_start      = time.time()
            current            = finding
            all_checks_failed  = []
            llm_called         = False

            # Step 1: CVE validation
            current, cve_checks = self._validate_cve(current)
            all_checks_failed.extend(cve_checks)

            # Step 2: Severity check
            current, disposition, sev_checks = self._check_severity(current)
            all_checks_failed.extend(sev_checks)

            if current is None:
                # Hard remove -- severity too low
                self.stats["removed"] += 1
                self.unverified_findings.append({
                    "reason": "low_severity", "finding": _finding_to_dict(finding),
                    "timestamp": datetime.now().isoformat()
                })
                console.print(f"[dim]    Removed (low severity): {finding.title[:50]}[/dim]")
                self.metrics.record_finding(
                    finding, "remove", llm_called,
                    time.time() - finding_start, all_checks_failed,
                    ground_truth_map.get(finding.title) if ground_truth_map else None
                )
                continue

            if disposition == "flagged_uncertain":
                self.stats["flagged_uncertain"] += 1
                console.print(f"[yellow]    Flagged: {current.title[:50]}[/yellow]")

            # Step 3: Evidence check
            current, ev_checks = self._check_evidence(current)
            all_checks_failed.extend(ev_checks)

            # Step 4: Dedup -- LLM CALLED HERE in original verifier
            is_dup, llm_called = self._is_duplicate(current, verified_findings)

            if is_dup:
                self.stats["duplicates_removed"] += 1
                self.unverified_findings.append({
                    "reason": "duplicate", "finding": _finding_to_dict(finding),
                    "timestamp": datetime.now().isoformat()
                })
                console.print(f"[dim]    Duplicate: {current.title[:50]}[/dim]")
                self.metrics.record_finding(
                    finding, "duplicate", llm_called,
                    time.time() - finding_start, all_checks_failed,
                    ground_truth_map.get(finding.title) if ground_truth_map else None
                )
                continue

            # Finding passed
            self.stats["passed"] += 1
            final_disp = "flag" if disposition == "flagged_uncertain" else "pass"
            self.metrics.record_finding(
                finding, final_disp, llm_called,
                time.time() - finding_start, all_checks_failed,
                ground_truth_map.get(finding.title) if ground_truth_map else None
            )
            verified_findings.append(current)

        # Rebuild aggregator
        new_aggregator = FindingsAggregator(target=aggregated.target)
        for f in verified_findings:
            new_aggregator.add_finding(f)
        new_aggregated = new_aggregator.aggregate()

        self._save_verification_report(aggregated.total_findings, new_aggregated.total_findings)
        self._print_summary(aggregated.total_findings, new_aggregated.total_findings, deterministic_count)
        self.metrics.save(aggregated.target.replace(".", "_"))

        return new_aggregated

    # ------------------------------------------------------------------ #
    # REPORTING
    # ------------------------------------------------------------------ #

    def _save_verification_report(self, total_before: int, total_after: int):
        try:
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            ts   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            path = REPORTS_DIR / f"{ts}_verification_report.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "timestamp":           datetime.now().isoformat(),
                    "findings_before":     total_before,
                    "findings_after":      total_after,
                    "findings_removed":    total_before - total_after,
                    "stats":               self.stats,
                    "unverified_findings": self.unverified_findings
                }, f, indent=2)
            console.print(f"[dim]  Verification report: {path}[/dim]")
        except Exception as e:
            console.print(f"[yellow]  Verification report failed: {e}[/yellow]")

    def _print_summary(self, total_before: int, total_after: int, deterministic_count: int = 0):
        console.print("\n[green]  Verifier (BASELINE) complete[/green]")
        if deterministic_count > 0:
            console.print(f"[dim]    Deterministic findings: {deterministic_count} -- passed through[/dim]")
        if self.stats["total_reviewed"] == 0:
            console.print("[dim]    LLM findings: 0 (no AI surfaces found)[/dim]")
        else:
            console.print(f"[dim]    LLM findings reviewed: {self.stats['total_reviewed']}[/dim]")
            console.print(f"[dim]    Passed:       {self.stats['passed']}[/dim]")
            console.print(f"[dim]    Flagged:      {self.stats['flagged_uncertain']}[/dim]")
            console.print(f"[dim]    Removed:      {self.stats['removed']}[/dim]")
            console.print(f"[dim]    Duplicates:   {self.stats['duplicates_removed']}[/dim]")
            console.print(f"[dim]    CVE stripped: {self.stats['cve_stripped']}[/dim]")
            console.print(f"[dim]    LLM calls:    {self.metrics.llm_calls}[/dim]")
        console.print(f"[dim]    Total: {total_before} -> {total_after} findings[/dim]")


# ================================================================== #
# TERMINAL COMMANDS -- EXACT STEPS TO RUN THIS
# ================================================================== #
"""
SETUP (one time):
    cd r3d-agent
    source venv/bin/activate

STEP 1 -- Use this as your verifier:
    cp verifier_baseline.py core/verifier.py

STEP 2 -- Connect to TryHackMe VPN:
    sudo openvpn ~/Downloads/your-tryhackme.ovpn
    (leave this terminal open, VPN must stay connected)

STEP 3 -- Open new terminal, activate venv again:
    cd r3d-agent && source venv/bin/activate

STEP 4 -- Run engagement against TryHackMe machine IP:
    python main.py --target 10.10.X.X --mode semi-auto

STEP 5 -- Repeat for 2 more different TryHackMe machines:
    python main.py --target 10.10.X.X --mode semi-auto
    python main.py --target 10.10.X.X --mode semi-auto

STEP 6 -- After each engagement, open the _findings.json and
          manually label each llm_attack finding True or False.
          Add them to your ground_truth.json file.

STEP 7 -- Swap in agentic verifier:
    cp verifier_agentic.py core/verifier.py

STEP 8 -- Run same 3 targets again with agentic.

STEP 9 -- Run compare_metrics.py to see the difference.

TryHackMe rooms that trigger LLM attack module (have AI surfaces):
    Search "AI" or "LLM" in the TryHackMe room search.
    Any room with a chatbot, API endpoint, or web app with /chat /api/ai
    will trigger the LLM attack module and produce LLM findings to verify.
"""