"""
R3D Verifier -- Metrics Comparison Script
==========================================
PURPOSE:
    Reads all BASELINE and AGENTIC metrics JSONs from output/reports/
    and produces side-by-side comparison graphs showing improvement.

HOW TO RUN:
    python compare_metrics.py

    Run this AFTER you have completed baseline and agentic engagements.
    It automatically finds all _BASELINE_metrics.json and
    _AGENTIC_metrics.json files in output/reports/ and aggregates them.

WHAT IT PRODUCES:
    1. Bar chart      -- LLM call rate: baseline vs agentic per engagement
    2. Bar chart      -- Hallucination rate: baseline vs agentic
    3. Bar chart      -- F1 score: baseline vs agentic
    4. Bar chart      -- Reliability Score (Mikayla's RS): baseline vs agentic
    5. Line graph     -- Confidence scores across findings (agentic only)
    6. Stacked bar    -- Pass 1 exits vs Pass 2 invocations (agentic only)
    7. Runtime split  -- Pass 1 vs Pass 2 time per engagement (agentic only)
    8. Summary table  -- All key metrics side by side averaged across engagements

    All charts saved to output/reports/comparison_charts/
    Summary printed to terminal.

REQUIRES:
    pip install matplotlib numpy
"""

import json
import sys
from pathlib import Path
from datetime import datetime

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
except ImportError:
    print("ERROR: matplotlib not installed.")
    print("Run: pip install matplotlib numpy")
    sys.exit(1)

# ------------------------------------------------------------------ #
# PATHS
# ------------------------------------------------------------------ #
BASE_DIR    = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "output" / "reports"
CHARTS_DIR  = REPORTS_DIR / "comparison_charts"

# ------------------------------------------------------------------ #
# COLORS
# ------------------------------------------------------------------ #
COLOR_BASELINE = "#E74C3C"   # red -- original verifier
COLOR_AGENTIC  = "#2ECC71"   # green -- improved agentic verifier
COLOR_PASS1    = "#3498DB"   # blue -- pass 1 deterministic
COLOR_PASS2    = "#F39C12"   # orange -- pass 2 LLM reasoning
BG_COLOR       = "#1A1A2E"   # dark background matching R3D terminal aesthetic
TEXT_COLOR     = "#FFFFFF"
GRID_COLOR     = "#2D2D44"


# ================================================================== #
# DATA LOADING
# ================================================================== #

def load_metrics_files() -> tuple:
    """
    Scan output/reports/ for all BASELINE and AGENTIC metrics JSONs.
    Returns (baseline_list, agentic_list) where each item is a parsed dict.
    """
    if not REPORTS_DIR.exists():
        print(f"ERROR: {REPORTS_DIR} does not exist.")
        print("Run at least one engagement first.")
        sys.exit(1)

    baseline_files = sorted(REPORTS_DIR.glob("*_BASELINE_metrics.json"))
    agentic_files  = sorted(REPORTS_DIR.glob("*_AGENTIC_metrics.json"))

    if not baseline_files and not agentic_files:
        print("ERROR: No metrics files found in output/reports/")
        print("Run engagements with baseline and agentic verifiers first.")
        sys.exit(1)

    baseline_data, agentic_data = [], []

    for f in baseline_files:
        try:
            data = json.loads(f.read_text())
            if "error" not in data:
                data["_filename"] = f.name
                baseline_data.append(data)
                print(f"  Loaded baseline: {f.name}")
        except Exception as e:
            print(f"  WARNING: Could not load {f.name}: {e}")

    for f in agentic_files:
        try:
            data = json.loads(f.read_text())
            if "error" not in data:
                data["_filename"] = f.name
                agentic_data.append(data)
                print(f"  Loaded agentic:  {f.name}")
        except Exception as e:
            print(f"  WARNING: Could not load {f.name}: {e}")

    print(f"\n  Found: {len(baseline_data)} baseline, {len(agentic_data)} agentic engagement(s)\n")
    return baseline_data, agentic_data


def extract_llm_call_rate(data: dict) -> float:
    """Extract LLM call rate as float 0-100 from metrics dict."""
    rate_str = data.get("llm_call_rate", "0/0 (0%)")
    try:
        # Format: "3/10 (30%)"
        pct = rate_str.split("(")[1].replace("%)", "").strip()
        return float(pct)
    except Exception:
        return 0.0

def extract_hallucination_rate(data: dict) -> float:
    """Extract hallucination rate as float 0-100."""
    gt = data.get("ground_truth_metrics", {})
    rate_str = gt.get("hallucination_rate", "N/A")
    if rate_str == "N/A":
        return None
    try:
        return float(rate_str.replace("%", ""))
    except Exception:
        return None

def extract_f1(data: dict) -> float:
    """Extract F1 score as float 0-1."""
    gt = data.get("ground_truth_metrics", {})
    f1 = gt.get("f1_score", "N/A")
    if f1 == "N/A":
        return None
    try:
        return float(f1)
    except Exception:
        return None

def extract_rs(data: dict) -> float:
    """Extract Reliability Score (Mikayla's metric)."""
    gt = data.get("ground_truth_metrics", {})
    rs = gt.get("reliability_score_RS", "N/A")
    if rs == "N/A":
        return None
    try:
        return float(rs)
    except Exception:
        return None

def extract_pass1_exit_rate(data: dict) -> float:
    """Extract Pass 1 exit rate (agentic only)."""
    rate_str = data.get("pass1_exit_rate", "N/A")
    if rate_str == "N/A":
        return None
    try:
        return float(rate_str.replace("%", ""))
    except Exception:
        return None

def safe_avg(values: list) -> float:
    """Average a list, ignoring None values."""
    clean = [v for v in values if v is not None]
    return sum(clean) / len(clean) if clean else 0.0


# ================================================================== #
# CHART SETUP
# ================================================================== #

def setup_style():
    """Apply dark theme matching R3D terminal aesthetic."""
    plt.rcParams.update({
        "figure.facecolor":  BG_COLOR,
        "axes.facecolor":    BG_COLOR,
        "axes.edgecolor":    GRID_COLOR,
        "axes.labelcolor":   TEXT_COLOR,
        "axes.titlecolor":   TEXT_COLOR,
        "xtick.color":       TEXT_COLOR,
        "ytick.color":       TEXT_COLOR,
        "text.color":        TEXT_COLOR,
        "grid.color":        GRID_COLOR,
        "grid.alpha":        0.3,
        "font.family":       "monospace",
        "figure.dpi":        120,
    })

def add_value_labels(ax, bars, fmt="{:.1f}%", color=TEXT_COLOR):
    """Add value labels on top of bars."""
    for bar in bars:
        height = bar.get_height()
        if height is not None and height != 0:
            ax.annotate(
                fmt.format(height),
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 4),
                textcoords="offset points",
                ha="center", va="bottom",
                fontsize=9, color=color
            )


# ================================================================== #
# INDIVIDUAL CHARTS
# ================================================================== #

def chart_llm_call_rate(baseline_data: list, agentic_data: list, charts_dir: Path):
    """
    Bar chart: LLM call rate per engagement, baseline vs agentic.
    KEY metric -- agentic should show 70-80% fewer LLM calls.
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BG_COLOR)

    n_base   = len(baseline_data)
    n_agent  = len(agentic_data)
    n_engage = max(n_base, n_agent)

    if n_engage == 0:
        ax.text(0.5, 0.5, "No data available", transform=ax.transAxes,
                ha="center", va="center", color=TEXT_COLOR, fontsize=14)
    else:
        x        = np.arange(n_engage)
        width    = 0.35
        b_rates  = [extract_llm_call_rate(d) for d in baseline_data] + [0] * (n_engage - n_base)
        a_rates  = [extract_llm_call_rate(d) for d in agentic_data]  + [0] * (n_engage - n_agent)

        bars_b = ax.bar(x - width/2, b_rates, width, label="Baseline", color=COLOR_BASELINE, alpha=0.85)
        bars_a = ax.bar(x + width/2, a_rates, width, label="Agentic",  color=COLOR_AGENTIC,  alpha=0.85)

        add_value_labels(ax, bars_b)
        add_value_labels(ax, bars_a)

        # Avg lines
        avg_b = safe_avg(b_rates)
        avg_a = safe_avg(a_rates)
        ax.axhline(avg_b, color=COLOR_BASELINE, linestyle="--", alpha=0.5, linewidth=1.5, label=f"Baseline avg {avg_b:.1f}%")
        ax.axhline(avg_a, color=COLOR_AGENTIC,  linestyle="--", alpha=0.5, linewidth=1.5, label=f"Agentic avg {avg_a:.1f}%")

        ax.set_xticks(x)
        ax.set_xticklabels([f"Engagement {i+1}" for i in range(n_engage)])
        ax.set_ylabel("LLM Call Rate (%)")
        ax.set_ylim(0, 110)
        ax.grid(axis="y", alpha=0.3)

    ax.set_title("LLM Call Rate: Baseline vs Agentic\n(Lower is better -- agentic should show 70-80% reduction)", pad=15)
    ax.legend(loc="upper right")
    plt.tight_layout()
    path = charts_dir / "1_llm_call_rate.png"
    plt.savefig(path, facecolor=BG_COLOR)
    plt.close()
    print(f"  Saved: {path.name}")


def chart_hallucination_rate(baseline_data: list, agentic_data: list, charts_dir: Path):
    """
    Bar chart: hallucination rate baseline vs agentic.
    Requires labeled test set. Shows N/A if no ground truth provided.
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BG_COLOR)

    b_rates = [extract_hallucination_rate(d) for d in baseline_data]
    a_rates = [extract_hallucination_rate(d) for d in agentic_data]

    has_data = any(v is not None for v in b_rates + a_rates)

    if not has_data:
        ax.text(
            0.5, 0.5,
            "No labeled test set data yet.\n\nProvide ground_truth_map to verify()\nafter manually labeling findings.",
            transform=ax.transAxes, ha="center", va="center",
            color=TEXT_COLOR, fontsize=13, linespacing=2
        )
    else:
        n_engage = max(len(baseline_data), len(agentic_data))
        x        = np.arange(n_engage)
        width    = 0.35

        b_clean = [v if v is not None else 0 for v in b_rates] + [0] * (n_engage - len(b_rates))
        a_clean = [v if v is not None else 0 for v in a_rates] + [0] * (n_engage - len(a_rates))

        bars_b = ax.bar(x - width/2, b_clean, width, label="Baseline", color=COLOR_BASELINE, alpha=0.85)
        bars_a = ax.bar(x + width/2, a_clean, width, label="Agentic",  color=COLOR_AGENTIC,  alpha=0.85)

        add_value_labels(ax, bars_b)
        add_value_labels(ax, bars_a)

        avg_b = safe_avg(b_clean)
        avg_a = safe_avg(a_clean)
        ax.axhline(avg_b, color=COLOR_BASELINE, linestyle="--", alpha=0.5, linewidth=1.5, label=f"Baseline avg {avg_b:.1f}%")
        ax.axhline(avg_a, color=COLOR_AGENTIC,  linestyle="--", alpha=0.5, linewidth=1.5, label=f"Agentic avg {avg_a:.1f}%")

        ax.set_xticks(x)
        ax.set_xticklabels([f"Engagement {i+1}" for i in range(n_engage)])
        ax.set_ylabel("Hallucination Rate (%)")
        ax.set_ylim(0, 110)
        ax.grid(axis="y", alpha=0.3)
        ax.legend(loc="upper right")

    ax.set_title("Hallucination Rate: Baseline vs Agentic\n(Lower is better -- hallucinated findings that slipped through)", pad=15)
    plt.tight_layout()
    path = charts_dir / "2_hallucination_rate.png"
    plt.savefig(path, facecolor=BG_COLOR)
    plt.close()
    print(f"  Saved: {path.name}")


def chart_f1_score(baseline_data: list, agentic_data: list, charts_dir: Path):
    """
    Bar chart: F1 score baseline vs agentic.
    F1 is the single best summary number -- combines precision and recall.
    Higher F1 = better at catching bad findings AND keeping real ones.
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BG_COLOR)

    b_scores = [extract_f1(d) for d in baseline_data]
    a_scores = [extract_f1(d) for d in agentic_data]
    has_data = any(v is not None for v in b_scores + a_scores)

    if not has_data:
        ax.text(
            0.5, 0.5,
            "No labeled test set data yet.\n\nF1 score requires ground_truth_map.",
            transform=ax.transAxes, ha="center", va="center",
            color=TEXT_COLOR, fontsize=13, linespacing=2
        )
    else:
        n_engage = max(len(baseline_data), len(agentic_data))
        x        = np.arange(n_engage)
        width    = 0.35

        b_clean = [v if v is not None else 0 for v in b_scores] + [0] * (n_engage - len(b_scores))
        a_clean = [v if v is not None else 0 for v in a_scores] + [0] * (n_engage - len(a_scores))

        bars_b = ax.bar(x - width/2, b_clean, width, label="Baseline", color=COLOR_BASELINE, alpha=0.85)
        bars_a = ax.bar(x + width/2, a_clean, width, label="Agentic",  color=COLOR_AGENTIC,  alpha=0.85)

        add_value_labels(ax, bars_b, fmt="{:.3f}")
        add_value_labels(ax, bars_a, fmt="{:.3f}")

        avg_b = safe_avg(b_clean)
        avg_a = safe_avg(a_clean)
        ax.axhline(avg_b, color=COLOR_BASELINE, linestyle="--", alpha=0.5, linewidth=1.5, label=f"Baseline avg {avg_b:.3f}")
        ax.axhline(avg_a, color=COLOR_AGENTIC,  linestyle="--", alpha=0.5, linewidth=1.5, label=f"Agentic avg {avg_a:.3f}")

        ax.set_xticks(x)
        ax.set_xticklabels([f"Engagement {i+1}" for i in range(n_engage)])
        ax.set_ylabel("F1 Score (0.0 - 1.0)")
        ax.set_ylim(0, 1.15)
        ax.grid(axis="y", alpha=0.3)
        ax.legend(loc="lower right")

    ax.set_title("F1 Score: Baseline vs Agentic\n(Higher is better -- harmonic mean of precision and recall)", pad=15)
    plt.tight_layout()
    path = charts_dir / "3_f1_score.png"
    plt.savefig(path, facecolor=BG_COLOR)
    plt.close()
    print(f"  Saved: {path.name}")


def chart_reliability_score(baseline_data: list, agentic_data: list, charts_dir: Path):
    """
    Bar chart: Mikayla's Reliability Score (RS) baseline vs agentic.
    RS = (+1 correct, -2 wrong) / k
    Negative RS = net harmful verifier (hallucinates more than it catches).
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BG_COLOR)

    b_scores = [extract_rs(d) for d in baseline_data]
    a_scores = [extract_rs(d) for d in agentic_data]
    has_data = any(v is not None for v in b_scores + a_scores)

    if not has_data:
        ax.text(
            0.5, 0.5,
            "No labeled test set data yet.\n\nReliability Score requires ground_truth_map.\n\nRS formula: (+1 correct, -2 wrong) / k\nNegative RS = net harmful verifier.",
            transform=ax.transAxes, ha="center", va="center",
            color=TEXT_COLOR, fontsize=13, linespacing=2
        )
    else:
        n_engage = max(len(baseline_data), len(agentic_data))
        x        = np.arange(n_engage)
        width    = 0.35

        b_clean = [v if v is not None else 0 for v in b_scores] + [0] * (n_engage - len(b_scores))
        a_clean = [v if v is not None else 0 for v in a_scores] + [0] * (n_engage - len(a_scores))

        bars_b = ax.bar(x - width/2, b_clean, width, label="Baseline", color=COLOR_BASELINE, alpha=0.85)
        bars_a = ax.bar(x + width/2, a_clean, width, label="Agentic",  color=COLOR_AGENTIC,  alpha=0.85)

        add_value_labels(ax, bars_b, fmt="{:.3f}")
        add_value_labels(ax, bars_a, fmt="{:.3f}")

        # Zero line -- negative RS means net harmful
        ax.axhline(0, color=TEXT_COLOR, linestyle="-", alpha=0.5, linewidth=1)
        ax.text(n_engage - 0.5, 0.02, "← negative = net harmful", color="#E74C3C", fontsize=9, ha="right")

        ax.set_xticks(x)
        ax.set_xticklabels([f"Engagement {i+1}" for i in range(n_engage)])
        ax.set_ylabel("Reliability Score (RS)")
        ax.grid(axis="y", alpha=0.3)
        ax.legend(loc="lower right")

    ax.set_title("Reliability Score (Mikayla's DFIR-Metric): Baseline vs Agentic\n(Higher is better -- penalty: +1 correct, -2 wrong, avg by k)", pad=15)
    plt.tight_layout()
    path = charts_dir / "4_reliability_score_RS.png"
    plt.savefig(path, facecolor=BG_COLOR)
    plt.close()
    print(f"  Saved: {path.name}")


def chart_pass1_pass2_split(agentic_data: list, charts_dir: Path):
    """
    Stacked bar: Pass 1 exits vs Pass 2 invocations per engagement.
    Shows what % of findings never needed the LLM at all.
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BG_COLOR)

    if not agentic_data:
        ax.text(0.5, 0.5, "No agentic engagement data yet.",
                transform=ax.transAxes, ha="center", va="center",
                color=TEXT_COLOR, fontsize=14)
    else:
        exits       = [d.get("pass1_exits", 0)        for d in agentic_data]
        invocations = [d.get("pass2_invocations", 0)  for d in agentic_data]
        x           = np.arange(len(agentic_data))

        bars1 = ax.bar(x, exits,       label="Pass 1 exits (no LLM)", color=COLOR_PASS1,  alpha=0.85)
        bars2 = ax.bar(x, invocations, label="Pass 2 invocations (LLM used)",
                       bottom=exits, color=COLOR_PASS2, alpha=0.85)

        # Label each segment
        for i, (e, inv) in enumerate(zip(exits, invocations)):
            total = e + inv
            if total > 0:
                ax.text(i, e/2,       f"{e}\n({100*e//total}%)",   ha="center", va="center", fontsize=10, color=TEXT_COLOR)
                ax.text(i, e + inv/2, f"{inv}\n({100*inv//total}%)", ha="center", va="center", fontsize=10, color=TEXT_COLOR)

        ax.set_xticks(x)
        ax.set_xticklabels([f"Engagement {i+1}" for i in range(len(agentic_data))])
        ax.set_ylabel("Finding Count")
        ax.grid(axis="y", alpha=0.3)
        ax.legend(loc="upper right")

    ax.set_title("Pass 1 Exits vs Pass 2 Invocations (Agentic)\n(Blue = cleared 0.80 gate, LLM never called | Orange = sent to LLM reasoning)", pad=15)
    plt.tight_layout()
    path = charts_dir / "5_pass1_pass2_split.png"
    plt.savefig(path, facecolor=BG_COLOR)
    plt.close()
    print(f"  Saved: {path.name}")


def chart_runtime_split(agentic_data: list, charts_dir: Path):
    """
    Grouped bar: Pass 1 runtime vs Pass 2 runtime per engagement.
    Shows that Pass 2 LLM reasoning is the expensive part,
    and that the 0.80 gate limits how much of that you pay.
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BG_COLOR)

    if not agentic_data:
        ax.text(0.5, 0.5, "No agentic engagement data yet.",
                transform=ax.transAxes, ha="center", va="center",
                color=TEXT_COLOR, fontsize=14)
    else:
        p1_times = [d.get("pass1_runtime_s", 0) for d in agentic_data]
        p2_times = [d.get("pass2_runtime_s", 0) for d in agentic_data]
        x        = np.arange(len(agentic_data))
        width    = 0.35

        bars1 = ax.bar(x - width/2, p1_times, width, label="Pass 1 runtime (deterministic)", color=COLOR_PASS1, alpha=0.85)
        bars2 = ax.bar(x + width/2, p2_times, width, label="Pass 2 runtime (LLM reasoning)", color=COLOR_PASS2, alpha=0.85)

        add_value_labels(ax, bars1, fmt="{:.2f}s")
        add_value_labels(ax, bars2, fmt="{:.2f}s")

        ax.set_xticks(x)
        ax.set_xticklabels([f"Engagement {i+1}" for i in range(len(agentic_data))])
        ax.set_ylabel("Runtime (seconds)")
        ax.grid(axis="y", alpha=0.3)
        ax.legend(loc="upper right")

    ax.set_title("Pass 1 vs Pass 2 Runtime per Engagement (Agentic)\n(Pass 2 is the expensive LLM part -- gate limits how often it runs)", pad=15)
    plt.tight_layout()
    path = charts_dir / "6_runtime_split.png"
    plt.savefig(path, facecolor=BG_COLOR)
    plt.close()
    print(f"  Saved: {path.name}")


def chart_confidence_distribution(agentic_data: list, charts_dir: Path):
    """
    Line graph: average Pass 1 confidence score across engagements.
    Shows whether the verifier is consistently confident or erratic.
    Also plots the 0.80 gate line for reference.
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BG_COLOR)

    if not agentic_data:
        ax.text(0.5, 0.5, "No agentic engagement data yet.",
                transform=ax.transAxes, ha="center", va="center",
                color=TEXT_COLOR, fontsize=14)
    else:
        confidences = [d.get("avg_pass1_confidence", 0) for d in agentic_data]
        x           = list(range(1, len(agentic_data) + 1))

        ax.plot(x, confidences, color=COLOR_AGENTIC, linewidth=2.5,
                marker="o", markersize=8, label="Avg Pass 1 confidence")

        # Shade above/below the gate
        ax.axhline(0.80, color="#F39C12", linestyle="--", linewidth=1.5,
                   label="Confidence gate (0.80)")
        ax.fill_between(x, confidences, 0.80,
                        where=[c >= 0.80 for c in confidences],
                        alpha=0.15, color=COLOR_AGENTIC, label="Above gate (no LLM needed)")
        ax.fill_between(x, confidences, 0.80,
                        where=[c < 0.80 for c in confidences],
                        alpha=0.15, color=COLOR_BASELINE, label="Below gate (LLM invoked)")

        # Label each point
        for xi, ci in zip(x, confidences):
            ax.annotate(f"{ci:.2f}", (xi, ci), textcoords="offset points",
                        xytext=(0, 10), ha="center", fontsize=10, color=TEXT_COLOR)

        ax.set_xticks(x)
        ax.set_xticklabels([f"Engagement {i}" for i in x])
        ax.set_ylabel("Average Pass 1 Confidence Score")
        ax.set_ylim(0, 1.1)
        ax.grid(axis="y", alpha=0.3)
        ax.legend(loc="lower right")

    ax.set_title("Average Pass 1 Confidence Score Across Engagements\n(Above 0.80 gate = findings exited without LLM)", pad=15)
    plt.tight_layout()
    path = charts_dir / "7_confidence_trend.png"
    plt.savefig(path, facecolor=BG_COLOR)
    plt.close()
    print(f"  Saved: {path.name}")


# ================================================================== #
# SUMMARY TABLE
# ================================================================== #

def print_summary_table(baseline_data: list, agentic_data: list):
    """
    Print a clean comparison table to terminal.
    Shows averages across all engagements for each version.
    """
    print("\n" + "=" * 65)
    print("  R3D VERIFIER -- METRICS COMPARISON SUMMARY")
    print("=" * 65)
    print(f"  Baseline engagements:  {len(baseline_data)}")
    print(f"  Agentic engagements:   {len(agentic_data)}")
    print("-" * 65)
    print(f"  {'Metric':<35} {'Baseline':>12} {'Agentic':>12}")
    print("-" * 65)

    # LLM call rate
    b_llm = safe_avg([extract_llm_call_rate(d) for d in baseline_data])
    a_llm = safe_avg([extract_llm_call_rate(d) for d in agentic_data])
    delta = b_llm - a_llm
    print(f"  {'LLM Call Rate':<35} {b_llm:>11.1f}% {a_llm:>11.1f}%  ↓{delta:.1f}%")

    # Hallucination rate
    b_hal = safe_avg([v for v in [extract_hallucination_rate(d) for d in baseline_data] if v is not None])
    a_hal = safe_avg([v for v in [extract_hallucination_rate(d) for d in agentic_data]  if v is not None])
    if b_hal or a_hal:
        delta = b_hal - a_hal
        print(f"  {'Hallucination Rate':<35} {b_hal:>11.1f}% {a_hal:>11.1f}%  ↓{delta:.1f}%")
    else:
        print(f"  {'Hallucination Rate':<35} {'N/A':>12} {'N/A':>12}  (need labeled set)")

    # F1 score
    b_f1 = safe_avg([v for v in [extract_f1(d) for d in baseline_data] if v is not None])
    a_f1 = safe_avg([v for v in [extract_f1(d) for d in agentic_data]  if v is not None])
    if b_f1 or a_f1:
        delta = a_f1 - b_f1
        print(f"  {'F1 Score':<35} {b_f1:>12.4f} {a_f1:>12.4f}  ↑{delta:.4f}")
    else:
        print(f"  {'F1 Score':<35} {'N/A':>12} {'N/A':>12}  (need labeled set)")

    # Reliability Score (Mikayla's RS)
    b_rs = safe_avg([v for v in [extract_rs(d) for d in baseline_data] if v is not None])
    a_rs = safe_avg([v for v in [extract_rs(d) for d in agentic_data]  if v is not None])
    if b_rs or a_rs:
        delta = a_rs - b_rs
        print(f"  {'Reliability Score RS (Mikayla)':<35} {b_rs:>12.4f} {a_rs:>12.4f}  ↑{delta:.4f}")
    else:
        print(f"  {'Reliability Score RS (Mikayla)':<35} {'N/A':>12} {'N/A':>12}  (need labeled set)")

    # Runtime
    b_rt = safe_avg([d.get("total_runtime_s", 0) for d in baseline_data])
    a_rt = safe_avg([d.get("total_runtime_s", 0) for d in agentic_data])
    if b_rt or a_rt:
        delta = b_rt - a_rt
        print(f"  {'Total Runtime (avg)':<35} {b_rt:>10.1f}s {a_rt:>10.1f}s  ↓{delta:.1f}s")

    # Agentic-only stats
    if agentic_data:
        print("-" * 65)
        print("  AGENTIC-ONLY METRICS")
        print("-" * 65)
        avg_exit = safe_avg([extract_pass1_exit_rate(d) or 0 for d in agentic_data])
        avg_conf = safe_avg([d.get("avg_pass1_confidence", 0) for d in agentic_data])
        print(f"  {'Pass 1 Exit Rate (no LLM needed)':<35} {avg_exit:>11.1f}%")
        print(f"  {'Avg Pass 1 Confidence Score':<35} {avg_conf:>12.4f}")

        p2_agreements = []
        for d in agentic_data:
            rate_str = d.get("pass2_agreement_rate", "N/A")
            if rate_str != "N/A":
                try:
                    p2_agreements.append(float(rate_str.replace("%", "")))
                except Exception:
                    pass
        if p2_agreements:
            avg_agree = safe_avg(p2_agreements)
            note = "raise threshold" if avg_agree > 80 else "lower threshold" if avg_agree < 50 else "threshold ok"
            print(f"  {'Pass 2 Agreement Rate':<35} {avg_agree:>11.1f}%  ({note})")

    print("=" * 65)
    print(f"  Charts saved to: {CHARTS_DIR}")
    print("=" * 65 + "\n")


# ================================================================== #
# MAIN
# ================================================================== #

def main():
    print("\n" + "=" * 65)
    print("  R3D VERIFIER -- METRICS COMPARISON")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65 + "\n")

    # Setup
    setup_style()
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)

    # Load data
    print("Loading metrics files...")
    baseline_data, agentic_data = load_metrics_files()

    # Generate all charts
    print("Generating charts...")
    chart_llm_call_rate(baseline_data, agentic_data, CHARTS_DIR)
    chart_hallucination_rate(baseline_data, agentic_data, CHARTS_DIR)
    chart_f1_score(baseline_data, agentic_data, CHARTS_DIR)
    chart_reliability_score(baseline_data, agentic_data, CHARTS_DIR)
    chart_pass1_pass2_split(agentic_data, CHARTS_DIR)
    chart_runtime_split(agentic_data, CHARTS_DIR)
    chart_confidence_distribution(agentic_data, CHARTS_DIR)

    # Print summary table
    print_summary_table(baseline_data, agentic_data)


if __name__ == "__main__":
    main()
