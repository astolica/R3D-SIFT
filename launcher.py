"""
R3D Verifier Launcher
=====================
Simple menu to switch between verifier versions and run comparisons.
Run this instead of manually copying files around.

Usage:
    python launcher.py
"""

import shutil
import subprocess
import sys
from pathlib import Path

BASE_DIR        = Path(__file__).parent
CORE_VERIFIER   = BASE_DIR / "core" / "verifier.py"
BASELINE_SRC    = BASE_DIR / "verifier_baseline.py"
AGENTIC_SRC     = BASE_DIR / "verifier_agentic.py"
COMPARE_SCRIPT  = BASE_DIR / "compare_metrics.py"


def clear():
    print("\n" * 2)


def which_verifier_is_active() -> str:
    """Read first line of core/verifier.py to detect which version is active."""
    if not CORE_VERIFIER.exists():
        return "unknown"
    try:
        content = CORE_VERIFIER.read_text()
        if "BASELINE" in content[:500]:
            return "baseline"
        elif "TWO-PASS AGENTIC" in content[:500]:
            return "agentic"
        else:
            return "original"
    except Exception:
        return "unknown"


def check_files():
    """Warn if any required files are missing."""
    missing = []
    if not BASELINE_SRC.exists():
        missing.append("verifier_baseline.py  -- not found in r3d-agent/")
    if not AGENTIC_SRC.exists():
        missing.append("verifier_agentic.py   -- not found in r3d-agent/")
    if not COMPARE_SCRIPT.exists():
        missing.append("compare_metrics.py    -- not found in r3d-agent/")
    if not CORE_VERIFIER.parent.exists():
        missing.append("core/                 -- core folder not found, are you in r3d-agent/?")
    return missing


def switch_to_baseline():
    print("\n  Switching to BASELINE verifier...")
    try:
        # Backup current verifier first
        if CORE_VERIFIER.exists():
            shutil.copy(CORE_VERIFIER, BASE_DIR / "core" / "verifier_backup.py")
        shutil.copy(BASELINE_SRC, CORE_VERIFIER)
        print("  Done. core/verifier.py is now the BASELINE version.")
        print("  Run your engagement: python main.py --target <IP> --mode semi-auto")
    except Exception as e:
        print(f"  ERROR: {e}")


def switch_to_agentic():
    print("\n  Switching to AGENTIC verifier...")
    try:
        if CORE_VERIFIER.exists():
            shutil.copy(CORE_VERIFIER, BASE_DIR / "core" / "verifier_backup.py")
        shutil.copy(AGENTIC_SRC, CORE_VERIFIER)
        print("  Done. core/verifier.py is now the AGENTIC version.")
        print("  Run your engagement: python main.py --target <IP> --mode semi-auto")
    except Exception as e:
        print(f"  ERROR: {e}")


def restore_original():
    backup = BASE_DIR / "core" / "verifier_backup.py"
    if backup.exists():
        shutil.copy(backup, CORE_VERIFIER)
        print("  Restored previous verifier from backup.")
    else:
        print("  No backup found. Copy your original verifier.py manually into core/.")


def run_compare():
    if not COMPARE_SCRIPT.exists():
        print("  ERROR: compare_metrics.py not found.")
        return
    print("\n  Running comparison...\n")
    subprocess.run([sys.executable, str(COMPARE_SCRIPT)])


def count_metrics_files() -> tuple:
    reports = BASE_DIR / "output" / "reports"
    if not reports.exists():
        return 0, 0
    baseline = len(list(reports.glob("*_BASELINE_metrics.json")))
    agentic  = len(list(reports.glob("*_AGENTIC_metrics.json")))
    return baseline, agentic


def main():
    while True:
        clear()
        active          = which_verifier_is_active()
        b_count, a_count = count_metrics_files()
        missing         = check_files()

        print("=" * 55)
        print("  R3D VERIFIER LAUNCHER")
        print("=" * 55)
        print(f"  Active verifier:     {active.upper()}")
        print(f"  Baseline runs saved: {b_count}")
        print(f"  Agentic runs saved:  {a_count}")

        if missing:
            print("\n  WARNINGS:")
            for m in missing:
                print(f"    ! {m}")

        print("\n  What do you want to do?\n")
        print("  [1]  Switch to BASELINE verifier")
        print("  [2]  Switch to AGENTIC verifier")
        print("  [3]  Run metrics comparison + generate charts")
        print("  [4]  Restore previous verifier from backup")
        print("  [5]  Exit")
        print()

        choice = input("  Enter number: ").strip()

        if choice == "1":
            switch_to_baseline()
            input("\n  Press Enter to continue...")

        elif choice == "2":
            switch_to_agentic()
            input("\n  Press Enter to continue...")

        elif choice == "3":
            if b_count == 0 and a_count == 0:
                print("\n  No metrics files found yet.")
                print("  Run at least one engagement with baseline or agentic first.")
            else:
                run_compare()
            input("\n  Press Enter to continue...")

        elif choice == "4":
            restore_original()
            input("\n  Press Enter to continue...")

        elif choice == "5":
            print("\n  Exiting.\n")
            break

        else:
            print("  Invalid choice.")


if __name__ == "__main__":
    main()
