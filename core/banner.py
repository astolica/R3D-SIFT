"""
R3D Agent -- Banner Module
Startup display. Runs before everything else.
Shows the ASCII art, a 6-point system check, and the last 3 engagements.

If any check fails, it prints a fix hint inline — operator knows exactly
what to do before wasting 10 minutes waiting for a module to crash.
Never raises — checks fail gracefully so a missing optional dep
doesn't block a full run.

System checks:
    Python version  -- 3.10+ required
    Nmap            -- subprocess nmap --version
    Ollama          -- HTTP ping to localhost:11434
    LLM Model       -- checks whatever model is actually loaded (any model)
    CVE database    -- file existence + size (optional but recommended)
    Internet        -- socket connect to 8.8.8.8:53

Color coding:
    Green  -- all good
    Red    -- broken, fix hint shown next to it
    Yellow -- warning, won't block a run but worth knowing

Compatibility: Windows 10/11, Ubuntu, Kali Linux
"""

import sys
import socket
import subprocess
import requests
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

BASE_DIR        = Path(__file__).parent.parent
OUTPUT_DIR      = BASE_DIR / "output"
ENGAGEMENTS_DIR = OUTPUT_DIR / "engagements"
# Check .db first (new SQLite format), fall back to .json (legacy)
CVE_DB_PATH = (
    BASE_DIR / "data" / "cve_database.db"
    if (BASE_DIR / "data" / "cve_database.db").exists()
    else BASE_DIR / "data" / "cve_database.json"
)
R3D_VERSION     = "1.0"

ASCII_ART = r"""
    ██████╗ ██████╗ ██████╗
    ██╔══██╗╚════██╗██╔══██╗
    ██████╔╝ █████╔╝██║  ██║
    ██╔══██╗ ╚═══██╗██║  ██║
    ██║  ██║██████╔╝██████╔╝
    ╚═╝  ╚═╝╚═════╝ ╚═════╝
"""


def _check_python() -> tuple[bool, str, str]:
    """Check Python version >= 3.10. Returns (ok, label, fix)."""
    v = sys.version_info
    label = f"Python {v.major}.{v.minor}.{v.micro}"
    if v.major == 3 and v.minor >= 10:
        return True, label, ""
    return False, label, "Python 3.10+ required -- python.org/downloads"


def _check_nmap() -> tuple[bool, str, str]:
    """Check Nmap installed. Returns (ok, label, fix)."""
    try:
        r = subprocess.run(
            ["nmap", "--version"],
            capture_output=True, text=True, timeout=5,
            check=False  # returncode checked manually below
        )
        if r.returncode == 0:
            first = r.stdout.split("\n")[0]
            ver   = first.replace("Nmap version ", "").split(" ")[0]
            return True, f"Nmap {ver}", ""
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return False, "Nmap not found", "Install: nmap.org/download -- add to PATH"


def _check_ollama() -> tuple[bool, str, str]:
    """
    Ping Ollama's REST API to confirm the server is up.
    Returns (ok, label, fix_hint).
    """
    try:
        resp = requests.get(
            "http://localhost:11434/api/tags", timeout=3
        )
        if resp.status_code == 200:
            return True, "Ollama running", ""
    except Exception:
        pass
    return False, "Ollama not running", "Run: ollama serve"


def _check_model() -> tuple[bool, str, str]:
    """
    Confirm at least one model is loaded in Ollama.
    Model-agnostic — works with llama3, qwen, gemma, anything.
    Shows the first loaded model by name so the operator knows
    exactly what they're running with.
    Returns (ok, label, fix_hint).
    """
    try:
        resp = requests.get(
            "http://localhost:11434/api/tags", timeout=3
        )
        if resp.status_code == 200:
            data   = resp.json()
            models = [
                m.get("name", "")
                for m in data.get("models", [])
                if m.get("name", "")
            ]
            if models:
                # Show first loaded model as representative
                return True, f"{models[0]} loaded", ""
            return (
                False,
                "No models loaded",
                "Run: ollama pull <model> (e.g. ollama pull gemma3:4b)"
            )
    except Exception:
        pass
    return (
        False,
        "Model check failed",
        "Start Ollama first: ollama serve"
    )


def _check_cve_db() -> tuple[bool, str, str]:
    """Check CVE database exists. Returns (ok, label, fix)."""
    if CVE_DB_PATH.exists():
        size_mb = CVE_DB_PATH.stat().st_size // (1024 * 1024)
        return True, f"CVE database ({size_mb}MB)", ""
    return (
        False,
        "CVE database missing",
        "Run: python main.py --setup-cve-db (optional but recommended)"
    )


def _check_internet() -> tuple[bool, str, str]:
    """
    Quick internet reachability check via TCP to 8.8.8.8:53.
    If this fails, OSINT and NVD API calls will also fail —
    good to know up front rather than mid-engagement.
    Returns (ok, label, fix_hint).
    """
    try:
        socket.setdefaulttimeout(3)
        with socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        ) as s:
            s.connect(("8.8.8.8", 53))
        return True, "Internet accessible", ""
    except Exception:
        pass
    return (
        False,
        "No internet",
        "OSINT and CVE API checks will be limited"
    )


def _get_recent_engagements(n: int = 3) -> list[dict]:
    """
    Read last N engagement state files.
    Returns list of dicts with target, date, status.
    Never raises -- returns empty list on any failure.
    """
    engagements = []
    try:
        if not ENGAGEMENTS_DIR.exists():
            return []

        state_files = sorted(
            ENGAGEMENTS_DIR.glob("*/state.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )[:n]

        for state_file in state_files:
            try:
                import json
                with open(state_file, encoding="utf-8") as f:
                    state = json.load(f)
                engagements.append({
                    "id":     state.get("engagement_id", "unknown")[:30],
                    "target": state.get("target", "unknown"),
                    "status": state.get("status", "unknown"),
                    "date":   state.get("timestamp", "")[:10],
                })
            except Exception:
                continue

    except Exception:
        pass

    return engagements


def _get_commit_hash() -> str:
    """Get current git commit hash. Returns 'unknown' on failure."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
            cwd=str(BASE_DIR), check=False  # returncode checked manually below
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def show_banner(skip_checks: bool = False):
    """
    Show R3D banner with system checks and recent engagements.
    skip_checks=True for fast startup when checks not needed.
    Never raises -- all failures handled gracefully.
    """
    # ASCII art header
    console.print(
        f"[bold cyan]{ASCII_ART}[/bold cyan]"
    )

    commit = _get_commit_hash()
    console.print(
        f"[bold]R3D Autonomous Purple Team Agent[/bold]  "
        f"[dim]v{R3D_VERSION} ({commit})[/dim]\n"
        f"[dim]Author: HumdoesCyber -- "
        f"Authorized use only[/dim]\n"
    )

    if skip_checks:
        return

    # System checks
    checks = [
        ("Python",        _check_python),
        ("Nmap",          _check_nmap),
        ("Ollama",        _check_ollama),
        ("LLM Model",     _check_model),
        ("CVE Database",  _check_cve_db),
        ("Internet",      _check_internet),
    ]

    passed   = 0
    warnings = []

    table = Table(
        show_header=False,
        box=None,
        padding=(0, 1)
    )
    table.add_column("Icon",  width=3)
    table.add_column("Check", width=16)
    table.add_column("Status")

    for check_name, check_fn in checks:
        try:
            ok, label, fix = check_fn()
        except Exception:
            ok    = False
            label = f"{check_name} check failed"
            fix   = "Unknown error"

        if ok:
            passed += 1
            icon   = "[green]✅[/green]"
            status = f"[green]{label}[/green]"
        else:
            # CVE DB is warning not failure -- optional
            if "CVE" in check_name:
                icon   = "[yellow]⚠ [/yellow]"
                status = f"[yellow]{label}[/yellow]"
                if fix:
                    warnings.append(f"[yellow]  {fix}[/yellow]")
                passed += 1  # Don't count as failure
            else:
                icon   = "[red]❌[/red]"
                status = f"[red]{label}[/red]"
                if fix:
                    warnings.append(f"[red]  Fix: {fix}[/red]")

        table.add_row(icon, check_name, status)

    console.print(
        Panel(
            table,
            title="[bold]System Check[/bold]",
            border_style="cyan"
        )
    )

    # Show fix hints
    if warnings:
        console.print()
        for w in warnings:
            console.print(w)
        console.print()

    # Recent engagements
    engagements = _get_recent_engagements(3)
    if engagements:
        eng_table = Table(
            title="Recent Engagements",
            show_header=True
        )
        eng_table.add_column("Date",   style="dim")
        eng_table.add_column("Target", style="bold")
        eng_table.add_column("Status")

        for eng in engagements:
            status = eng["status"]
            if status == "complete":
                status_str = "[green]complete[/green]"
            elif status in ["timeout", "paused_critical_review"]:
                status_str = "[yellow]paused[/yellow]"
            elif "failed" in status:
                status_str = "[red]failed[/red]"
            else:
                status_str = f"[dim]{status}[/dim]"

            eng_table.add_row(
                eng["date"],
                eng["target"],
                status_str
            )

        console.print(eng_table)
        console.print()

    console.print(
        f"[dim]{'─'*52}[/dim]"
    )


# ------------------------------------------------------------------ #
# TEST
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    show_banner()