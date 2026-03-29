"""
R3D Agent -- Main Entry Point
CLI entry point for all R3D operations.
Handles argument parsing, validation, and routing.

Usage:
    python main.py --target example.com
    python main.py --target example.com --mode guided
    python main.py --target example.com --mode full-auto --auto-attack
    python main.py --test-connection
    python main.py --setup-cve-db
    python main.py --improve
    python main.py --update
    python main.py --cleanup --older-than 30

All flags:
    --target          Domain or IP to assess
    --mode            GUIDED / SEMI-AUTO / FULL-AUTO
    --full-scan       Scan all 65535 ports
    --auto-attack     LLM attacks without confirmation
    --org-type        personal/small_business/enterprise/
                      critical_infrastructure/all
    --resume          Resume interrupted engagement
    --skip-llm        Skip LLM attack module
    --skip-trad       Skip traditional recon module
    --timeout         Engagement timeout in seconds (default 2700)
    --improve         Run improvement engine
    --setup-cve-db    Download NVD CVE database
    --test-connection Verify all dependencies
    --update          Pull latest code and update deps
    --cleanup         Remove old engagement files
    --older-than      Days threshold for cleanup (default 30)
    --fast-mode       Reduce delays for testing

Validation:
    Target stripped of protocol and trailing slashes
    Mode validated against allowed values
    FULL-AUTO auto-enables --auto-attack with warning
    --cleanup requires confirmation before deleting

Compatibility: Windows 10/11, Ubuntu, Kali Linux
"""

import argparse
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib import response

from rich.console import Console

console = Console()

BASE_DIR        = Path(__file__).parent
OUTPUT_DIR      = BASE_DIR / "output"
ENGAGEMENTS_DIR = OUTPUT_DIR / "engagements"

VALID_MODES = ["GUIDED", "SEMI-AUTO", "FULL-AUTO"]
VALID_ORG_TYPES = [
    "personal", "small_business",
    "enterprise", "critical_infrastructure", "all"
]


# ------------------------------------------------------------------ #
# TARGET VALIDATION
# ------------------------------------------------------------------ #

def _validate_target(target: str) -> str:
    """
    Validate and clean target input.
    Strips protocol, trailing slashes, whitespace.
    Raises SystemExit with clear message on invalid input.
    """
    if not target:
        console.print(
            "[red]Error: --target cannot be empty.[/red]\n"
            "Example: python main.py --target example.com"
        )
        sys.exit(1)

    # Strip protocol if accidentally included
    target = target.strip()
    target = re.sub(r'^https?://', '', target)
    target = target.rstrip('/')

    # Basic domain/IP validation
    # Allow: letters, numbers, dots, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9.\-_]+$', target):
        console.print(
            f"[red]Error: Invalid target format: "
            f"{target!r}[/red]\n"
            "[dim]Valid formats:\n"
            "  example.com\n"
            "  subdomain.example.com\n"
            "  192.168.1.1[/dim]"
        )
        sys.exit(1)

    return target


# ------------------------------------------------------------------ #
# MODE VALIDATION
# ------------------------------------------------------------------ #

def _validate_mode(mode: str) -> str:
    """
    Validate operating mode.
    Returns uppercase mode or exits with clear error.
    """
    mode_upper = mode.upper().replace("-", "-")

    # Handle common typos
    mode_map = {
        "GUIDED":     "GUIDED",
        "SEMIAUTO":   "SEMI-AUTO",
        "SEMI_AUTO":  "SEMI-AUTO",
        "SEMI-AUTO":  "SEMI-AUTO",
        "FULLAUTO":   "FULL-AUTO",
        "FULL_AUTO":  "FULL-AUTO",
        "FULL-AUTO":  "FULL-AUTO",
    }

    if mode_upper in mode_map:
        return mode_map[mode_upper]

    console.print(
        f"[red]Error: Invalid mode: {mode!r}[/red]\n"
        "[dim]Valid modes:\n"
        "  guided      -- approve every action\n"
        "  semi-auto   -- passive auto, active manual\n"
        "  full-auto   -- everything automatic (lab only)[/dim]"
    )
    sys.exit(1)


# ------------------------------------------------------------------ #
# UTILITY COMMANDS
# ------------------------------------------------------------------ #

def cmd_test_connection():
    """
    Comprehensive dependency check.
    Tests all 6 dependencies with pass/fail and fix hints.
    This is the first thing a new user should run.
    """
    console.print(
        "\n[bold cyan]R3D -- System Check[/bold cyan]\n"
        f"[dim]{'─'*52}[/dim]"
    )

    results = []

    # 1. Python version
    v = sys.version_info
    ver_str = f"{v.major}.{v.minor}.{v.micro}"
    if v.major == 3 and v.minor >= 10:
        results.append((True, "Python", ver_str, ""))
    else:
        results.append((
            False, "Python", ver_str,
            "Python 3.10+ required -- python.org/downloads"
        ))

    # 2. Nmap
    try:
        r = subprocess.run(
            ["nmap", "--version"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            ver = r.stdout.split("\n")[0].replace(
                "Nmap version ", ""
            ).split(" ")[0]
            results.append((True, "Nmap", ver, ""))
        else:
            results.append((
                False, "Nmap", "error",
                "Install: nmap.org/download"
            ))
    except FileNotFoundError:
        results.append((
            False, "Nmap", "not found",
            "Install: nmap.org/download -- add to PATH"
        ))
    except Exception as e:
        results.append((False, "Nmap", str(e)[:30], ""))

    # 3. Ollama running
    try:
        import requests
        resp = requests.get(
            "http://localhost:11434/api/tags", timeout=3
        )
        if resp.status_code == 200:
            results.append((
                True, "Ollama", "running on :11434", ""
            ))
        else:
            results.append((
                False, "Ollama",
                f"HTTP {resp.status_code}",
                "Run: ollama serve"
            ))
    except Exception:
        results.append((
            False, "Ollama", "not running",
            "Run: ollama serve"
        ))

    # 4. llama3:8b model
    try:
        import requests
        resp = requests.get(
            "http://localhost:11434/api/tags", timeout=3
        )
        if resp.status_code == 200:
            models = [
                m.get("name", "")
                for m in resp.json().get("models", [])
            ]
            if any("llama3" in m for m in models):
                results.append((
                    True, "llama3:8b", "downloaded", ""
                ))
            else:
                results.append((
                    False, "llama3:8b", "not found",
                    "Run: ollama pull llama3:8b (4.7GB)"
                ))
        else:
            results.append((
                False, "llama3:8b", "ollama unavailable",
                "Start Ollama first"
            ))
    except Exception:
        results.append((
            False, "llama3:8b", "ollama unavailable",
            "Start Ollama: ollama serve"
        ))

    # 5. CVE database
    cve_path = BASE_DIR / "data" / "cve_database.json"

    if cve_path.exists():
        size_mb = cve_path.stat().st_size // (1024 * 1024)
        results.append((
            True, "CVE database",
            f"{size_mb}MB local", ""
        ))
    else:
        results.append((
            None, "CVE database", "not found",
            "Optional: python main.py --setup-cve-db"
        ))

    # 6. Internet access
    try:
        import socket
        socket.setdefaulttimeout(3)
        socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        ).connect(("8.8.8.8", 53))
        results.append((True, "Internet", "accessible", ""))
    except Exception:
        results.append((
            False, "Internet", "no connection",
            "OSINT and CVE API calls will fail"
        ))

    # Print results
    passed = 0
    total  = 0
    for ok, name, status, fix in results:
        total += 1
        if ok is True:
            passed += 1
            icon    = "[green]✅[/green]"
            console.print(
                f"  {icon} [bold]{name:<16}[/bold] "
                f"[green]{status}[/green]"
            )
        elif ok is None:
            # Warning -- optional
            passed += 1
            icon    = "[yellow]⚠ [/yellow]"
            console.print(
                f"  {icon} [bold]{name:<16}[/bold] "
                f"[yellow]{status}[/yellow]"
            )
            if fix:
                console.print(
                    f"     [dim]{fix}[/dim]"
                )
        else:
            icon = "[red]❌[/red]"
            console.print(
                f"  {icon} [bold]{name:<16}[/bold] "
                f"[red]{status}[/red]"
            )
            if fix:
                console.print(
                    f"     [dim]Fix: {fix}[/dim]"
                )

    console.print(f"[dim]{'─'*52}[/dim]")
    console.print(
        f"\n[bold]{passed}/{total} checks passed[/bold]"
    )

    if passed == total:
        console.print(
            "[green]R3D is ready. "
            "Run: python main.py --target example.com"
            "[/green]\n"
        )
    else:
        console.print(
            "[yellow]Fix the issues above before running "
            "a full engagement.[/yellow]\n"
        )


def cmd_setup_cve_db():
    """
    Download NVD CVE database locally.
    Calls CVEEngine setup method.
    """
    console.print(
        "\n[bold cyan]R3D -- CVE Database Setup[/bold cyan]\n"
    )
    console.print(
        "[yellow]This downloads the NVD CVE database locally.\n"
        "Takes 30-60 minutes. Only needed once.[/yellow]\n"
    )

    response = input(
        "Download CVE database now? [Y/N]: "
    ).strip().upper()

    if response != "Y":
        console.print("[dim]Cancelled.[/dim]")
        return

    try:
        from core.cve_engine import setup_cve_db
        setup_cve_db()
        console.print(
            "[green]CVE database downloaded successfully.[/green]"
        )
    except Exception as e:
        console.print(
            f"[red]CVE database setup failed: {e}[/red]"
        )
        
def cmd_update():
    """
    Update R3D to latest version.
    Checks git status before pulling to prevent data loss.
    """
    console.print(
        "\n[bold cyan]R3D -- Update[/bold cyan]\n"
    )

    # Check git status before pulling
    try:
        status_result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True,
            timeout=10, cwd=str(BASE_DIR)
        )
        if status_result.stdout.strip():
            console.print(
                "[yellow]Warning: You have local changes:[/yellow]"
            )
            console.print(
                f"[dim]{status_result.stdout.strip()}[/dim]\n"
            )
            response = input(
                "Proceed with update anyway? [Y/N]: "
            ).strip().upper()
            if response != "Y":
                console.print(
                    "[dim]Update cancelled.[/dim]"
                )
                return
    except Exception:
        pass

    # git pull
    try:
        console.print("[cyan]Pulling latest code...[/cyan]")
        pull = subprocess.run(
            ["git", "pull", "origin", "main"],
            capture_output=True, text=True,
            timeout=60, cwd=str(BASE_DIR)
        )
        console.print(pull.stdout.strip())
        if pull.returncode != 0:
            console.print(
                f"[red]git pull failed: {pull.stderr}[/red]"
            )
            return
    except Exception as e:
        console.print(f"[red]git pull error: {e}[/red]")
        return

    # pip install -r requirements.txt
    try:
        console.print(
            "[cyan]Updating dependencies...[/cyan]"
        )
        pip = subprocess.run(
            [
                sys.executable, "-m", "pip", "install",
                "-r", str(BASE_DIR / "requirements.txt"),
                "--break-system-packages", "-q"
            ],
            capture_output=True, text=True, timeout=120
        )
        if pip.returncode == 0:
            console.print(
                "[green]Dependencies updated.[/green]"
            )
        else:
            console.print(
                f"[yellow]pip warning: {pip.stderr[:200]}[/yellow]"
            )
    except Exception as e:
        console.print(f"[red]pip update error: {e}[/red]")
        return

    console.print(
        "\n[bold green]R3D updated successfully.[/bold green]\n"
    )


def cmd_cleanup(older_than_days: int = 30):
    """
    Remove old engagement files.
    Shows what will be deleted before asking confirmation.
    Never deletes without explicit Y confirmation.
    """
    console.print(
        f"\n[bold cyan]R3D -- Cleanup "
        f"(>{older_than_days} days)[/bold cyan]\n"
    )

    if not ENGAGEMENTS_DIR.exists():
        console.print(
            "[dim]No engagement directory found.[/dim]"
        )
        return

    cutoff = datetime.now() - timedelta(days=older_than_days)
    to_delete = []

    for eng_dir in ENGAGEMENTS_DIR.iterdir():
        if not eng_dir.is_dir():
            continue
        try:
            mtime = datetime.fromtimestamp(
                eng_dir.stat().st_mtime
            )
            if mtime < cutoff:
                to_delete.append((eng_dir, mtime))
        except Exception:
            continue

    if not to_delete:
        console.print(
            f"[green]No engagements older than "
            f"{older_than_days} days found.[/green]"
        )
        return

    console.print(
        f"[yellow]Found {len(to_delete)} engagement(s) "
        f"to delete:[/yellow]\n"
    )
    for eng_dir, mtime in to_delete:
        console.print(
            f"  [dim]{eng_dir.name} "
            f"({mtime.strftime('%Y-%m-%d')})[/dim]"
        )

    console.print()
    response = input(
        f"Delete {len(to_delete)} engagement(s)? [Y/N]: "
    ).strip().upper()

    if response != "Y":
        console.print("[dim]Cleanup cancelled.[/dim]")
        return

    deleted = 0
    for eng_dir, _ in to_delete:
        try:
            shutil.rmtree(eng_dir)
            deleted += 1
        except Exception as e:
            console.print(
                f"[yellow]  Failed to delete "
                f"{eng_dir.name}: {e}[/yellow]"
            )

    console.print(
        f"\n[green]Deleted {deleted} engagement(s).[/green]\n"
    )


def cmd_improve():
    """Run improvement engine."""
    try:
        from core.improvement_engine import ImprovementEngine
        engine = ImprovementEngine()
        engine.run()
    except Exception as e:
        console.print(
            f"[red]Improvement engine failed: {e}[/red]"
        )


# ------------------------------------------------------------------ #
# MAIN
# ------------------------------------------------------------------ #

def main():
    """
    Main entry point.
    Parses args, validates inputs, routes to correct command.
    """
    parser = argparse.ArgumentParser(
        prog="r3d",
        description="R3D Autonomous Red Team Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --target example.com\n"
            "  python main.py --target example.com --mode guided\n"
            "  python main.py --test-connection\n"
            "  python main.py --improve\n"
            "  python main.py --cleanup --older-than 30\n"
        )
    )

    # Target
    parser.add_argument(
        "--target",
        type=str,
        help="Target domain or IP address"
    )

    # Mode
    parser.add_argument(
        "--mode",
        type=str,
        default="SEMI-AUTO",
        help="Operating mode: guided/semi-auto/full-auto "
             "(default: semi-auto)"
    )

    # Scan options
    parser.add_argument(
        "--full-scan",
        action="store_true",
        help="Scan all 65535 ports (default: top 1000)"
    )
    parser.add_argument(
        "--auto-attack",
        action="store_true",
        help="LLM attacks without per-surface confirmation"
    )

    # GRC options
    parser.add_argument(
        "--org-type",
        type=str,
        choices=VALID_ORG_TYPES,
        help="Organization type for compliance mapping"
    )

    # Resume
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume interrupted engagement"
    )

    # Skip flags
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Skip LLM attack module"
    )
    parser.add_argument(
        "--skip-trad",
        action="store_true",
        help="Skip traditional recon module"
    )

    # Timeout
    parser.add_argument(
        "--timeout",
        type=int,
        default=2700,
        help="Engagement timeout in seconds (default: 2700 = 45min)"
    )

    # Fast mode
    parser.add_argument(
        "--fast-mode",
        action="store_true",
        help="Reduce delays for testing"
    )

    # Utility commands
    parser.add_argument(
        "--test-connection",
        action="store_true",
        help="Verify all dependencies"
    )
    parser.add_argument(
        "--setup-cve-db",
        action="store_true",
        help="Download NVD CVE database"
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Pull latest code and update dependencies"
    )
    parser.add_argument(
        "--improve",
        action="store_true",
        help="Run improvement engine"
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove old engagement files"
    )
    parser.add_argument(
        "--older-than",
        type=int,
        default=30,
        help="Days threshold for cleanup (default: 30)"
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------ #
    # UTILITY COMMAND ROUTING
    # No banner needed for utility commands -- fast execution
    # ------------------------------------------------------------------ #

    if args.test_connection:
        cmd_test_connection()
        return

    if args.setup_cve_db:
        cmd_setup_cve_db()
        return

    if args.update:
        cmd_update()
        return

    if args.cleanup:
        cmd_cleanup(args.older_than)
        return

    if args.improve:
        cmd_improve()
        return

    # ------------------------------------------------------------------ #
    # ENGAGEMENT -- requires --target
    # ------------------------------------------------------------------ #

    if not args.target:
        # No target and no utility flag -- show banner + hint
        try:
            from core.banner import show_banner
            show_banner()
        except Exception:
            pass

        console.print(
            "\n[bold yellow]No target specified.[/bold yellow]\n"
            "[dim]Usage: python main.py --target example.com\n"
            "       python main.py --test-connection\n"
            "       python main.py --help[/dim]\n"
        )
        return

    # Show banner for engagements
    try:
        from core.banner import show_banner
        show_banner()
    except Exception:
        pass

    # Validate target
    target = _validate_target(args.target)

    # Validate mode
    mode = _validate_mode(args.mode)

    # FULL-AUTO auto-enables auto-attack with warning
    auto_attack = args.auto_attack
    if mode == "FULL-AUTO" and not auto_attack:
        console.print(
            "[yellow]  Note: FULL-AUTO mode auto-enables "
            "--auto-attack.\n"
            "  LLM attacks will run without per-surface "
            "confirmation.[/yellow]\n"
        )
        auto_attack = True

    # Validate org-type if provided
    if args.org_type and args.org_type not in VALID_ORG_TYPES:
        console.print(
            f"[red]Invalid --org-type: {args.org_type!r}[/red]\n"
            f"[dim]Valid: {', '.join(VALID_ORG_TYPES)}[/dim]"
        )
        sys.exit(1)

    # Run engagement
    try:
        from modules.orchestrator import Orchestrator

        orch = Orchestrator(
            target=target,
            mode=mode,
            full_scan=args.full_scan,
            auto_attack=auto_attack,
            org_type=args.org_type,
            resume=args.resume,
            timeout=args.timeout,
            fast_mode=args.fast_mode,
            skip_llm=args.skip_llm,
            skip_trad=args.skip_trad,
        )

        results = orch.run()

        if not results:
            console.print(
                "[yellow]Engagement produced no output files."
                "[/yellow]"
            )

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Engagement interrupted by operator. "
            "Use --resume to continue.[/yellow]\n"
        )
    except Exception as e:
        console.print(
            f"\n[red]Engagement failed: {e}[/red]\n"
            "[dim]Use --resume to attempt recovery.[/dim]\n"
        )


if __name__ == "__main__":
    main()