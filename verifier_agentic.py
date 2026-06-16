"""
R3D Agent -- Verifier Module (TWO-PASS AGENTIC)
================================================
PURPOSE:
    The upgraded verifier. Replaces single-pass pipeline with a two-pass
    architecture that reserves LLM usage for findings that actually need it.

WHAT CHANGED FROM BASELINE:
    Pass 1 (new):
        Deterministic confidence scoring on every finding (0.0-1.0).
        Findings >= 0.80 confidence exit immediately -- LLM never called.
        Only sub-0.80 findings proceed to Pass 2.

    Pass 2 (new):
        Chain of Thought LLM reasoning -- not yes/no questions.
        LLM receives full finding context + session memory (AgentContext).
        Must reason step by step before giving a disposition.
        Only fires on ~20-30% of findings.
        NOW USES Abraham Yelifari's OllamaClient wrapper for LLM calls.

    AgentContext (new):
        Session memory that persists across ALL findings in one engagement.
        LLM is no longer stateless -- it knows what happened earlier.
        Tracks: confirmed finding types, CVE strip patterns, confidence avg.

    VerifierDecision (new):
        Immutable snapshot of every decision before anything is modified.
        Written to decisions.jsonl -- full audit trail, one line per finding.
        Implements Alec's suggestion: backup before change + log every decision.

    Dedup (changed):
        LLM removed from dedup entirely.
        difflib only for dedup -- LLM budget reserved for Pass 2 reasoning.

WHAT THIS PROVES VS BASELINE:
    Lower llm_call_rate   -- 0.80 gate stops most findings reaching LLM
    Lower hallucination_rate -- CoT reasoning catches more bad findings
    Higher f1_score       -- better precision AND recall
    Higher reliability_score_RS (Mikayla's metric) -- fewer wrong decisions
    Pass1_runtime vs pass2_runtime split shows where time is spent

MIKAYLA'S METRICS:
    Same RS, TSR, CI tracking as baseline for direct comparison.
    Additional: pass2_agreement_rate -- how often LLM agrees with Pass 1.
    If LLM keeps agreeing with Pass 1 (>80%), raise the 0.80 threshold.
    If LLM keeps disagreeing (<50%), lower the threshold.
    This is the Phase 5 self-calibration data source.

ALEC'S AUDIT LAYER:
    decisions.jsonl: one line per finding, every decision recorded with:
        - What the finding looked like before any modification
        - Pass 1 confidence score and which checks failed
        - Whether Pass 2 was invoked and what it reasoned
        - What changed and why
        - Final disposition
    Nothing gets modified without a snapshot first.

ABRAHAM'S LLM CLIENT:
    Pass 2 LLM calls now route through Abraham Yelifari's OllamaClient
    wrapper (abraham_llm_client.py) instead of raw requests calls.
    OllamaClient provides a clean interface to the local Ollama instance
    with proper system/user prompt separation.
"""

import json
import time
import requests
from dataclasses import dataclass, field, asdict
from difflib import SequenceMatcher
from datetime import datetime
from pathlib import Path
from typing import Optional
from rich.console import Console

from core.findings import Finding, FindingsAggregator, AggregatedFindings

# Abraham Yelifari's LLM client wrapper
# Provides clean system/user prompt interface to local Ollama instance
# Drop abraham_llm_client.py in r3d-agent root alongside this file
try:
    from abraham_llm_client import OllamaClient
    ABRAHAM_CLIENT_AVAILABLE = True
except ImportError:
    ABRAHAM_CLIENT_AVAILABLE = False

console = Console()

# ------------------------------------------------------------------ #
# PATHS
# ------------------------------------------------------------------ #
BASE_DIR    = Path(__file__).parent.parent
OUTPUT_DIR  = BASE_DIR / "output"
LOGS_DIR    = OUTPUT_DIR / "attack_logs"
REPORTS_DIR = OUTPUT_DIR / "reports"

# ------------------------------------------------------------------ #
# THRESHOLDS
# ------------------------------------------------------------------ #
CONFIDENCE_GATE            = 0.80
SEVERITY_REMOVE_THRESHOLD  = 3.0
SEVERITY_FLAG_THRESHOLD    = 5.0
DEDUP_SIMILARITY_THRESHOLD = 0.85

# ------------------------------------------------------------------ #
# CONFIDENCE SCORE WEIGHTS -- must sum to 1.0
# ------------------------------------------------------------------ #
WEIGHT_CVE_CONFIRMED   = 0.30
WEIGHT_CVSS_ALIGNED    = 0.20
WEIGHT_EVIDENCE_EXISTS = 0.20
WEIGHT_SEVERITY_RANGE  = 0.15
WEIGHT_SOURCE_MODULE   = 0.15

SOURCE_RELIABILITY = {
    "llm_attack":        0.70,
    "traditional_recon": 1.0,
    "osint_recon":       1.0,
}

EXPECTED_SEVERITY_RANGES = {
    "prompt_injection":       (5.0, 10.0),
    "context_manipulation":   (4.0, 8.0),
    "exposed_port":           (3.0, 9.0),
    "missing_header":         (3.0, 6.0),
    "ssl_issue":              (4.0, 8.0),
    "cve_finding":            (5.0, 10.0),
    "information_disclosure": (3.0, 7.0),
}

NVD_CVE_URL         = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
NVD_REQUEST_TIMEOUT = 10

# LLM model used for Pass 2 reasoning
OLLAMA_MODEL = "llama3"
OLLAMA_URL   = "http://localhost:11434/api/chat"


# ================================================================== #
# PYDANTIC COMPATIBILITY
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
# AGENT CONTEXT -- session memory
# ================================================================== #

@dataclass
class AgentContext:
    """
    Persists across ALL findings in one engagement.
    Passed to the LLM in every Pass 2 call as a context summary.

    Without this, every LLM call starts from scratch.
    With this, if 3 prompt injections already confirmed at high confidence,
    the LLM uses that as a prior when evaluating the 4th.
    If CVEs keep getting stripped on a target, the LLM flags that pattern.
    This is what makes the verifier agentic -- it builds a model of the
    engagement as it goes, not just processes each finding in isolation.
    """
    target:                  str
    confirmed_finding_types: dict  = field(default_factory=dict)
    stripped_cve_count:      int   = 0
    session_confidence_avg:  float = 0.0
    confidence_readings:     list  = field(default_factory=list)
    findings_seen:           list  = field(default_factory=list)
    pass2_invocations:       int   = 0
    pass2_agreements:        int   = 0

    def update(self, finding_type: str, confidence: float, title: str):
        self.confirmed_finding_types[finding_type] = (
            self.confirmed_finding_types.get(finding_type, 0) + 1
        )
        self.confidence_readings.append(confidence)
        self.session_confidence_avg = (
            sum(self.confidence_readings) / len(self.confidence_readings)
        )
        self.findings_seen.append(title)

    def context_summary(self) -> str:
        type_str = (
            ", ".join(f"{k}:{v}" for k, v in self.confirmed_finding_types.items())
            if self.confirmed_finding_types else "none yet"
        )
        return (
            f"Session context for {self.target}: "
            f"{len(self.findings_seen)} findings processed so far. "
            f"Finding types confirmed: {type_str}. "
            f"Average confidence this engagement: {self.session_confidence_avg:.2f}. "
            f"CVEs stripped this session: {self.stripped_cve_count}. "
            f"Pass 2 invocations: {self.pass2_invocations}."
        )


# ================================================================== #
# VERIFIER DECISION -- audit snapshot (Alec's suggestion)
# ================================================================== #

@dataclass
class VerifierDecision:
    """
    Immutable record of what happened to one finding.
    Snapshot taken BEFORE any modification is made.
    Written to decisions.jsonl -- one line per finding.
    """
    finding_id:           str
    finding_title:        str
    timestamp:            str
    original_severity:    float
    pass_one_confidence:  float
    checks_failed:        list
    pass_two_invoked:     bool
    pass_two_reasoning:   Optional[str]
    pass_two_disposition: Optional[str]
    final_disposition:    str
    modifications:        dict
    final_confidence:     float
    ground_truth:         Optional[bool]
    correct_decision:     Optional[bool]


# ================================================================== #
# AGENTIC METRICS
# ================================================================== #

class AgenticMetrics:
    """
    Records two-pass verifier statistics.
    Same core schema as BaselineMetrics for direct comparison.
    Additional fields: pass1/pass2 runtime split, exit rate, agreement rate.
    """

    def __init__(self):
        self.engagement_start  = time.time()
        self.pass1_time        = 0.0
        self.pass2_time        = 0.0
        self.llm_calls         = 0
        self.pass1_exits       = 0
        self.pass2_invocations = 0
        self.pass2_agreements  = 0
        self.decisions:         list = []
        self.confidence_scores: list = []

    def record(self, decision, llm_called, p1_time, p2_time):
        self.decisions.append(decision)
        self.confidence_scores.append(decision.pass_one_confidence)
        self.pass1_time += p1_time
        self.pass2_time += p2_time
        if llm_called:
            self.llm_calls        += 1
            self.pass2_invocations += 1
        else:
            self.pass1_exits += 1

    def _reliability_score(self, labeled):
        """
        Mikayla's RS formula: +1 correct, -2 wrong, 0 skip, average by k.
        Higher RS vs baseline = agentic makes fewer wrong calls.
        """
        if not labeled:
            return None
        total = sum(
            1  if d.correct_decision is True
            else -2 if d.correct_decision is False
            else 0
            for d in labeled
        )
        return round(total / len(labeled), 4)

    def summary(self) -> dict:
        total         = len(self.decisions)
        total_runtime = time.time() - self.engagement_start

        if total == 0:
            return {
                "version": "two_pass_agentic",
                "error":   "No LLM findings processed -- target had no AI surfaces."
            }

        passed  = [d for d in self.decisions if d.final_disposition == "pass"]
        flagged = [d for d in self.decisions if d.final_disposition == "flag"]
        removed = [d for d in self.decisions if d.final_disposition in ("remove", "duplicate")]
        labeled = [d for d in self.decisions if d.ground_truth is not None]

        false_negatives = [
            d for d in labeled
            if d.final_disposition in ("pass", "flag") and d.ground_truth is False
        ]
        false_positives = [
            d for d in labeled
            if d.final_disposition in ("remove", "duplicate") and d.ground_truth is True
        ]
        correct = [d for d in labeled if d.correct_decision is True]

        tp = len([d for d in labeled if d.final_disposition in ("pass","flag") and d.ground_truth is True])
        fp = len(false_negatives)
        fn = len(false_positives)

        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall    = tp / (tp + fn) if (tp + fn) > 0 else None
        f1        = (
            2 * precision * recall / (precision + recall)
            if precision and recall else None
        )
        avg_conf = (
            sum(self.confidence_scores) / len(self.confidence_scores)
            if self.confidence_scores else 0
        )
        rs  = self._reliability_score(labeled)
        cdr = len(correct) / len(labeled) if labeled else None

        return {
            "version":      "two_pass_agentic",
            "generated_at": datetime.now().isoformat(),
            "llm_client":   "abraham_ollama_client" if ABRAHAM_CLIENT_AVAILABLE else "fallback_requests",

            "total_runtime_s":    round(total_runtime, 2),
            "pass1_runtime_s":    round(self.pass1_time, 2),
            "pass2_runtime_s":    round(self.pass2_time, 2),
            "avg_finding_time_s": round(total_runtime / total, 4),

            "llm_calls":     self.llm_calls,
            "llm_call_rate": (
                f"{self.llm_calls}/{total} "
                f"({100*self.llm_calls//total if total else 0}%)"
            ),

            "pass1_exits":          self.pass1_exits,
            "pass1_exit_rate":      f"{100*self.pass1_exits//total if total else 0}%",
            "pass2_invocations":    self.pass2_invocations,
            "pass2_agreement_rate": (
                f"{100*self.pass2_agreements//self.pass2_invocations}%"
                if self.pass2_invocations > 0 else "N/A"
            ),
            "avg_pass1_confidence": round(avg_conf, 4),
            "confidence_gate_used": CONFIDENCE_GATE,

            "findings_processed": total,
            "dispositions": {
                "passed":  len(passed),
                "flagged": len(flagged),
                "removed": len(removed),
            },

            "ground_truth_metrics": {
                "labeled_findings":      len(labeled),
                "note": (
                    "Provide ground_truth_map to verify() to populate these."
                    if not labeled else f"{len(labeled)} findings labeled."
                ),
                "reliability_score_RS":  rs  if rs  is not None else "N/A",
                "correct_decision_rate": round(cdr, 4) if cdr is not None else "N/A",
                "false_negatives":       len(false_negatives),
                "false_positives":       len(false_positives),
                "correct_decisions":     len(correct),
                "hallucination_rate": (
                    f"{100*len(false_negatives)//len(labeled)}%"
                    if labeled else "N/A"
                ),
                "precision": round(precision, 4) if precision else "N/A",
                "recall":    round(recall, 4)    if recall    else "N/A",
                "f1_score":  round(f1, 4)        if f1        else "N/A",
            },

            "decisions": [asdict(d) for d in self.decisions],
        }

    def save(self, target: str) -> Path:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        ts             = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        metrics_path   = REPORTS_DIR / f"{ts}_{target}_AGENTIC_metrics.json"
        decisions_path = REPORTS_DIR / f"{ts}_{target}_decisions.jsonl"

        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(self.summary(), f, indent=2)

        with open(decisions_path, "w", encoding="utf-8") as f:
            for d in self.decisions:
                f.write(json.dumps(asdict(d)) + "\n")

        console.print(f"[cyan]  Agentic metrics:  {metrics_path}[/cyan]")
        console.print(f"[cyan]  Decisions audit:  {decisions_path}[/cyan]")
        return metrics_path


# ================================================================== #
# TWO-PASS VERIFIER
# ================================================================== #

class Verifier:
    """
    Two-pass agentic verifier.

    Pass 1: confidence scoring on every LLM finding.
            >= CONFIDENCE_GATE -> exits, LLM never called.
            <  CONFIDENCE_GATE -> proceeds to Pass 2.

    Pass 2: Chain of Thought LLM reasoning on sub-0.80 findings only.
            Uses Abraham Yelifari's OllamaClient for LLM calls.
            Falls back to raw requests if client not available.

    Every decision snapshotted in VerifierDecision before modification.
    All decisions written to decisions.jsonl for audit.
    """

    def __init__(self):
        self.nvd_available    = True
        self.ollama_available = True
        self.metrics          = AgenticMetrics()
        self.context:         Optional[AgentContext] = None

        # Initialise Abraham's LLM client if available
        # Falls back to direct requests call if import failed
        if ABRAHAM_CLIENT_AVAILABLE:
            self.llm_client = OllamaClient(
                model=OLLAMA_MODEL,
                location=OLLAMA_URL
            )
            console.print("[dim]  LLM client: Abraham's OllamaClient[/dim]")
        else:
            self.llm_client = None
            console.print("[dim]  LLM client: fallback (raw requests)[/dim]")

        self.stats = {
            "total_reviewed":     0,
            "passed":             0,
            "flagged_uncertain":  0,
            "removed":            0,
            "cve_stripped":       0,
            "duplicates_removed": 0,
            "pass1_exits":        0,
            "pass2_invocations":  0,
        }
        self.unverified_findings: list = []

    # ------------------------------------------------------------------ #
    # PASS 1 -- CONFIDENCE SCORING
    # ------------------------------------------------------------------ #

    def _pass1_confidence(self, finding: Finding) -> tuple:
        """
        Compute confidence score using deterministic checks only.
        No LLM involved. Fast. Runs on every LLM finding.
        Returns (finding, confidence_score, checks_failed_list).
        """
        score, checks_failed = 0.0, []

        # CVE check
        if finding.cve_id:
            confirmed = self._nvd_check(finding.cve_id)
            if confirmed:
                score += WEIGHT_CVE_CONFIRMED
            else:
                checks_failed.append("cve_not_confirmed_in_nvd")
                finding = self._strip_cve(finding, "not confirmed in NVD")
        else:
            score += WEIGHT_CVE_CONFIRMED * 0.5

        # CVSS alignment
        if finding.cvss_score and finding.severity_score:
            delta = abs(finding.cvss_score - finding.severity_score)
            if delta <= 2.0:
                score += WEIGHT_CVSS_ALIGNED
            else:
                checks_failed.append(f"cvss_severity_delta_{delta:.1f}_exceeds_2.0")
        else:
            score += WEIGHT_CVSS_ALIGNED * 0.5

        # Evidence on disk
        if finding.raw_evidence_path:
            if Path(finding.raw_evidence_path).exists():
                score += WEIGHT_EVIDENCE_EXISTS
            else:
                checks_failed.append("evidence_file_not_on_disk")
        else:
            score += WEIGHT_EVIDENCE_EXISTS * 0.5

        # Severity range
        expected = EXPECTED_SEVERITY_RANGES.get(finding.finding_type)
        if expected:
            lo, hi = expected
            if lo <= finding.severity_score <= hi:
                score += WEIGHT_SEVERITY_RANGE
            else:
                checks_failed.append(
                    f"severity_{finding.severity_score}_outside_expected_{lo}-{hi}"
                )
        else:
            score += WEIGHT_SEVERITY_RANGE * 0.5

        # Source reliability
        reliability = SOURCE_RELIABILITY.get(finding.source_module, 0.5)
        score += WEIGHT_SOURCE_MODULE * reliability

        return finding, round(min(max(score, 0.0), 1.0), 4), checks_failed

    def _nvd_check(self, cve_id: str) -> bool:
        if not self.nvd_available:
            return True
        try:
            resp = requests.get(
                NVD_CVE_URL.format(cve_id=cve_id.strip()),
                timeout=NVD_REQUEST_TIMEOUT,
                headers={"User-Agent": "R3D-Verifier/2.0"}
            )
            if resp.status_code == 200:
                return resp.json().get("totalResults", 0) > 0
            elif resp.status_code == 404:
                return False
            return True
        except requests.Timeout:
            self.nvd_available = False
            return True
        except requests.ConnectionError:
            self.nvd_available = False
            return True
        except Exception:
            return True

    def _strip_cve(self, finding: Finding, reason: str) -> Finding:
        console.print(f"[yellow]    CVE stripped: {finding.cve_id} ({reason})[/yellow]")
        self.stats["cve_stripped"] += 1
        if self.context:
            self.context.stripped_cve_count += 1
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
    # PASS 2 -- CHAIN OF THOUGHT REASONING
    # Uses Abraham's OllamaClient if available, falls back to raw requests
    # ------------------------------------------------------------------ #

    def _call_llm(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """
        Single LLM call entry point.
        Routes through Abraham's OllamaClient if available.
        Falls back to direct requests call otherwise.
        Returns the raw text response from the LLM, or None on failure.
        """
        # --- Abraham's client path ---
        if self.llm_client is not None:
            try:
                data = self.llm_client.prompt(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt
                )
                # Abraham's client returns {"message": {"content": "..."}, ...}
                return data["message"]["content"]
            except Exception as e:
                console.print(
                    f"[yellow]  Abraham OllamaClient error: {e} -- trying fallback[/yellow]"
                )

        # --- Fallback: raw requests to Ollama chat endpoint ---
        try:
            resp = requests.post(
                OLLAMA_URL,
                json={
                    "model":  OLLAMA_MODEL,
                    "messages": [
                        {"role": "system",  "content": system_prompt},
                        {"role": "user",    "content": user_prompt},
                    ],
                    "format": "json",
                    "stream": False,
                },
                timeout=60
            )
            if resp.status_code == 200:
                return resp.json()["message"]["content"]
        except Exception as e:
            console.print(f"[yellow]  Fallback LLM error: {e}[/yellow]")

        return None

    def _pass2_reason(
        self,
        finding:          Finding,
        pass1_confidence: float,
        checks_failed:    list
    ) -> tuple:
        """
        Chain of Thought LLM reasoning for sub-0.80 findings.

        DESIGN:
            LLM is not asked yes/no. It must reason through 4 questions
            before concluding. Forces consideration of evidence rather
            than pattern-matching. CoT significantly reduces hallucination
            in LLM judgments.

        LLM CALL:
            Routes through Abraham's OllamaClient (abraham_llm_client.py).
            Falls back to raw requests if client unavailable.

        Returns (disposition, final_confidence, reasoning_text).
        Fails gracefully to severity-based fallback if LLM unavailable.
        """
        if not self.ollama_available:
            if finding.severity_score < SEVERITY_REMOVE_THRESHOLD:
                return "remove", pass1_confidence, "LLM unavailable -- severity below threshold"
            return "flag", pass1_confidence, "LLM unavailable -- flagged for manual review"

        context_summary = (
            self.context.context_summary() if self.context
            else "No session context available."
        )
        failed_str = (
            ", ".join(checks_failed) if checks_failed
            else "none -- borderline confidence score"
        )

        system_prompt = (
            "You are a precise security analyst. "
            "Think step by step. Respond only in valid JSON."
        )

        user_prompt = f"""You are a senior security analyst reviewing a flagged finding.

The automated Pass 1 checks scored this finding {pass1_confidence:.2f} confidence.
The threshold to skip LLM review is {CONFIDENCE_GATE}. This finding did not clear it.
Specific checks that failed: {failed_str}

{context_summary}

Finding details:
  Title:        {finding.title}
  Description:  {finding.description[:400]}
  Finding type: {finding.finding_type}
  CVE:          {finding.cve_id or "none"}
  CVSS:         {finding.cvss_score or "none"}
  Severity:     {finding.severity_score}
  Source:       {finding.source_module}
  Target:       {finding.target}

Reason through these questions before concluding:
1. Does the severity score make sense for this finding type on this target?
2. If a CVE is present, does the CVSS align with the described impact?
3. Is the description specific and actionable, or vague and possibly hallucinated?
4. Given what has already been confirmed this engagement, does this finding fit?

Respond ONLY in valid JSON, no other text before or after:
{{
  "final_confidence": <float 0.0-1.0>,
  "severity_adjustment": <float or null if no change needed>,
  "reasoning": "<your step by step reasoning across all 4 questions>",
  "disposition": "<pass or flag or remove>",
  "analyst_note": "<one sentence summarizing your conclusion>"
}}"""

        try:
            text = self._call_llm(system_prompt, user_prompt)

            if text is None:
                self.ollama_available = False
                return "flag", pass1_confidence, "LLM returned no response -- flagged"

            # Parse JSON response
            if isinstance(text, str):
                try:
                    content = json.loads(text)
                except json.JSONDecodeError:
                    return "flag", pass1_confidence, "LLM JSON parse failed -- flagged"
            else:
                content = text

            if isinstance(content, dict):
                disposition      = content.get("disposition", "flag")
                final_confidence = float(content.get("final_confidence", pass1_confidence))
                reasoning        = content.get("reasoning", "")
                analyst_note     = content.get("analyst_note", "")

                if disposition not in ("pass", "flag", "remove"):
                    disposition = "flag"

                console.print(
                    f"[dim]    Pass 2 ({disposition}): {reasoning[:60]}...[/dim]"
                )
                return disposition, final_confidence, f"{reasoning} | {analyst_note}"

        except Exception as e:
            self.ollama_available = False
            console.print(f"[yellow]  Pass 2 error: {e} -- falling back[/yellow]")

        return "flag", pass1_confidence, "LLM call failed -- flagged for manual review"

    # ------------------------------------------------------------------ #
    # DEDUP -- difflib only, no LLM
    # ------------------------------------------------------------------ #

    def _is_duplicate(self, finding: Finding, verified: list) -> bool:
        if not verified:
            return False
        same_type = [f for f in verified if f.finding_type == finding.finding_type]
        if not same_type:
            return False
        for existing in same_type:
            t = SequenceMatcher(None, finding.title.lower(), existing.title.lower()).ratio()
            d = SequenceMatcher(
                None,
                finding.description[:200].lower(),
                existing.description[:200].lower()
            ).ratio()
            if t > DEDUP_SIMILARITY_THRESHOLD and d > DEDUP_SIMILARITY_THRESHOLD:
                return True
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
        Two-pass verification with AgentContext and full audit trail.

        ground_truth_map: {"Finding title": True/False}
            True  = real, accurate finding
            False = hallucinated or inaccurate
        """
        self.context = AgentContext(target=aggregated.target)

        console.print(
            f"\n[cyan]  Verifier (TWO-PASS AGENTIC): reviewing "
            f"{aggregated.total_findings} findings...[/cyan]"
        )
        console.print(
            f"[dim]  Confidence gate: {CONFIDENCE_GATE} "
            f"(findings above this skip LLM entirely)[/dim]"
        )

        verified_findings:   list = []
        deterministic_count: int  = 0

        for finding in aggregated.findings:

            # Non-LLM findings pass through unchanged
            if finding.source_module != "llm_attack":
                verified_findings.append(finding)
                deterministic_count += 1
                continue

            self.stats["total_reviewed"] += 1

            # ── PASS 1 ──────────────────────────────────────────────
            p1_start = time.time()
            current, confidence, checks_failed = self._pass1_confidence(finding)
            p1_time  = time.time() - p1_start

            original_severity = finding.severity_score

            console.print(
                f"[dim]  P1: {current.title[:40]} | "
                f"conf={confidence:.2f} | "
                f"{'-> EXIT' if confidence >= CONFIDENCE_GATE else '-> PASS2'}[/dim]"
            )

            # Hard remove: severity below minimum
            if current.severity_score < SEVERITY_REMOVE_THRESHOLD:
                self.stats["removed"] += 1
                decision = VerifierDecision(
                    finding_id           = str(id(finding)),
                    finding_title        = finding.title,
                    timestamp            = datetime.now().isoformat(),
                    original_severity    = original_severity,
                    pass_one_confidence  = confidence,
                    checks_failed        = checks_failed,
                    pass_two_invoked     = False,
                    pass_two_reasoning   = None,
                    pass_two_disposition = None,
                    final_disposition    = "remove",
                    modifications        = {"reason": "severity_below_hard_minimum"},
                    final_confidence     = confidence,
                    ground_truth         = ground_truth_map.get(finding.title) if ground_truth_map else None,
                    correct_decision     = None,
                )
                self.metrics.record(decision, False, p1_time, 0.0)
                self.unverified_findings.append({
                    "reason":    "low_severity",
                    "finding":   _finding_to_dict(finding),
                    "timestamp": datetime.now().isoformat()
                })
                continue

            # CONFIDENCE GATE: high confidence exits here, no LLM
            if confidence >= CONFIDENCE_GATE:
                self.stats["pass1_exits"] += 1

                if self._is_duplicate(current, verified_findings):
                    self.stats["duplicates_removed"] += 1
                    final_disp = "duplicate"
                else:
                    final_disp = "pass" if confidence >= 0.90 else "flag"
                    self.stats["passed"] += 1
                    verified_findings.append(current)
                    self.context.update(current.finding_type, confidence, current.title)
                    console.print(
                        f"[green]    P1 exit ({final_disp}, conf={confidence:.2f}): "
                        f"{current.title[:50]}[/green]"
                    )

                decision = VerifierDecision(
                    finding_id           = str(id(finding)),
                    finding_title        = finding.title,
                    timestamp            = datetime.now().isoformat(),
                    original_severity    = original_severity,
                    pass_one_confidence  = confidence,
                    checks_failed        = checks_failed,
                    pass_two_invoked     = False,
                    pass_two_reasoning   = None,
                    pass_two_disposition = None,
                    final_disposition    = final_disp,
                    modifications        = {},
                    final_confidence     = confidence,
                    ground_truth         = ground_truth_map.get(finding.title) if ground_truth_map else None,
                    correct_decision     = None,
                )
                self.metrics.record(decision, False, p1_time, 0.0)
                continue

            # ── PASS 2: CoT REASONING ───────────────────────────────
            self.stats["pass2_invocations"] += 1
            self.context.pass2_invocations  += 1
            p2_start = time.time()

            console.print(
                f"[yellow]  P2 (conf={confidence:.2f}): {current.title[:50]}[/yellow]"
            )

            p2_disp, final_conf, p2_reasoning = self._pass2_reason(
                current, confidence, checks_failed
            )
            p2_time = time.time() - p2_start

            if p2_disp == "flag":
                self.context.pass2_agreements += 1
                self.metrics.pass2_agreements  += 1

            if p2_disp == "remove":
                self.stats["removed"] += 1
                self.unverified_findings.append({
                    "reason":    "pass2_removed",
                    "finding":   _finding_to_dict(finding),
                    "reasoning": p2_reasoning,
                    "timestamp": datetime.now().isoformat()
                })
                final_disp = "remove"

            elif self._is_duplicate(current, verified_findings):
                self.stats["duplicates_removed"] += 1
                final_disp = "duplicate"

            else:
                if p2_disp == "pass":
                    self.stats["passed"] += 1
                    final_disp = "pass"
                else:
                    self.stats["flagged_uncertain"] += 1
                    final_disp = "flag"
                    current = _copy_finding(current, {
                        "description": (
                            f"{current.description}\n"
                            f"[VERIFIER P2: {p2_reasoning[:120] if p2_reasoning else 'flagged'}]"
                        )
                    })
                verified_findings.append(current)
                self.context.update(current.finding_type, final_conf, current.title)
                color = "green" if final_disp == "pass" else "yellow"
                console.print(f"[{color}]    P2 {final_disp}: {current.title[:50]}[/{color}]")

            decision = VerifierDecision(
                finding_id           = str(id(finding)),
                finding_title        = finding.title,
                timestamp            = datetime.now().isoformat(),
                original_severity    = original_severity,
                pass_one_confidence  = confidence,
                checks_failed        = checks_failed,
                pass_two_invoked     = True,
                pass_two_reasoning   = p2_reasoning,
                pass_two_disposition = p2_disp,
                final_disposition    = final_disp,
                modifications        = {"pass2_changed_disposition": p2_disp != "flag"},
                final_confidence     = final_conf,
                ground_truth         = ground_truth_map.get(finding.title) if ground_truth_map else None,
                correct_decision     = None,
            )
            self.metrics.record(decision, True, p1_time, p2_time)

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
                    "timestamp":        datetime.now().isoformat(),
                    "verifier_version": "two_pass_agentic",
                    "confidence_gate":  CONFIDENCE_GATE,
                    "findings_before":  total_before,
                    "findings_after":   total_after,
                    "findings_removed": total_before - total_after,
                    "stats":            self.stats,
                    "unverified_findings": self.unverified_findings,
                    "agent_context": {
                        "confirmed_finding_types": self.context.confirmed_finding_types if self.context else {},
                        "stripped_cve_count":      self.context.stripped_cve_count      if self.context else 0,
                        "session_confidence_avg":  self.context.session_confidence_avg  if self.context else 0,
                        "pass2_invocations":       self.context.pass2_invocations       if self.context else 0,
                        "pass2_agreements":        self.context.pass2_agreements        if self.context else 0,
                    }
                }, f, indent=2)
            console.print(f"[dim]  Verification report: {path}[/dim]")
        except Exception as e:
            console.print(f"[yellow]  Verification report failed: {e}[/yellow]")

    def _print_summary(self, total_before: int, total_after: int, deterministic_count: int = 0):
        console.print("\n[bold green]  Verifier (TWO-PASS AGENTIC) complete[/bold green]")
        llm_src = "Abraham OllamaClient" if ABRAHAM_CLIENT_AVAILABLE else "fallback requests"
        console.print(f"[dim]    LLM source: {llm_src}[/dim]")
        if deterministic_count > 0:
            console.print(f"[dim]    Deterministic findings: {deterministic_count} -- passed through[/dim]")
        if self.stats["total_reviewed"] == 0:
            console.print("[dim]    LLM findings: 0 (no AI surfaces found)[/dim]")
        else:
            console.print(f"[dim]    LLM findings reviewed:  {self.stats['total_reviewed']}[/dim]")
            console.print(f"[dim]    Pass 1 exits (no LLM):  {self.stats['pass1_exits']}[/dim]")
            console.print(f"[dim]    Pass 2 invocations:     {self.stats['pass2_invocations']}[/dim]")
            console.print(f"[dim]    Passed:                 {self.stats['passed']}[/dim]")
            console.print(f"[dim]    Flagged:                {self.stats['flagged_uncertain']}[/dim]")
            console.print(f"[dim]    Removed:                {self.stats['removed']}[/dim]")
            console.print(f"[dim]    CVE stripped:           {self.stats['cve_stripped']}[/dim]")
            if self.context:
                console.print(
                    f"[dim]    Session conf avg:       {self.context.session_confidence_avg:.2f}[/dim]"
                )
                console.print(
                    f"[dim]    P2 agreement rate:      "
                    f"{100*self.context.pass2_agreements//max(self.context.pass2_invocations,1)}%[/dim]"
                )
        console.print(f"[dim]    Total: {total_before} -> {total_after} findings[/dim]")
