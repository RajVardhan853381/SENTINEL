#!/usr/bin/env python
# src/sentinels/cli.py -- Sentinels interactive CLI
import sys, io, os

# Force UTF-8 output on Windows so special chars print safely
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import asyncio
import time
from datetime import datetime
from pathlib import Path

# Load .env before any sentinels imports so env vars are available
from dotenv import load_dotenv
load_dotenv()

# -- ANSI colour helpers -------------------------------------------------------
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[36m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
DIM    = "\033[2m"
MAGENTA = "\033[35m"

def _c(color: str, text: str) -> str:
    return f"{color}{text}{RESET}"

def banner() -> None:
    art = r"""
   ____             _   _            _
  / ___|  ___ _ __ | |_(_)_ __   ___| |___
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ / __|
   ___) |  __/ | | | |_| | | | |  __/ \__ \
  |____/ \___|_| |_|\__|_|_| |_|\___|_|___/
"""
    print(_c(CYAN, BOLD + art + RESET))
    print(_c(DIM, "  Enterprise-Grade Agentic Security Analyzer"))
    print(_c(DIM, "  Powered by Microsoft Agent Framework"))
    
    from sentinels.config import get_active_provider_info
    p_info = get_active_provider_info()
    print(_c(DIM, f"  LLM Provider : {p_info['display']} (Model: {p_info['model']} @ {p_info['endpoint']})"))
    print()

def divider() -> None:
    print(_c(DIM, "  " + "─" * 60))

def log(symbol: str, color: str, msg: str) -> None:
    ts = _c(DIM, datetime.now().strftime("%H:%M:%S"))
    print(f"  {ts}  {_c(color, symbol)}  {msg}")

def prompt_repo() -> tuple[str, str | None]:
    """Interactively prompt the user for a repo URL and optional output file."""
    divider()
    print()
    print(f"  {_c(BOLD, 'Repository URL')}")
    print(_c(DIM, "  Enter the Git repository URL you want to scan."))
    print(_c(DIM, "  Example: https://github.com/org/repo"))
    print()

    while True:
        repo_url = input(_c(CYAN, "  > Repo URL: ")).strip()
        if repo_url:
            break
        print(_c(RED, "  Please enter a valid URL."))

    print()
    print(f"  {_c(BOLD, 'Output File')} {_c(DIM, '(optional)')}")
    print(_c(DIM, "  Save the report as a Markdown file, or press Enter to print to terminal."))
    print(_c(DIM, "  Example: report.md"))
    print()
    output = input(_c(CYAN, "  > Output file (leave blank to print): ")).strip()
    output = output if output else None

    return repo_url, output

async def run_scan(repo_url: str) -> tuple[str, float]:
    """Runs the full Sentinels workflow and returns (report_text, elapsed_secs)."""
    from sentinels.workflow.orchestrator import sentinel_scan_workflow

    print()
    divider()
    print()
    log("►", CYAN, f"Target  : {_c(BOLD, repo_url)}")
    log("►", CYAN, "Phase 1 : Cloning & ingesting repository ...")
    print()

    start = time.monotonic()
    # @workflow returns a FunctionalWorkflowDefinition (has no .run()); .build()
    # produces the runnable FunctionalWorkflow.
    run_result = await sentinel_scan_workflow.build().run(repo_url)
    elapsed = time.monotonic() - start

    # .run() returns a WorkflowRunResult (an events container), not the
    # plain string the @workflow function returns -- pull it out.
    outputs = run_result.get_outputs()
    report = outputs[-1] if outputs else ""

    return report, elapsed

def save_report(report: str, output_path: str) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report, encoding="utf-8")
    return path

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Sentinels: AI-Powered Multi-Agent Security Audit Platform")
    parser.add_argument("repo_url", nargs="?", help="Git repository URL to scan")
    parser.add_argument("-o", "--output", help="Path to save the Markdown security report")
    parser.add_argument("--web", action="store_true", help="Launch the Sentinels Web Cockpit UI")
    parser.add_argument("--debug", action="store_true", help="Print full exception stack trace on failure")
    args = parser.parse_args()

    banner()

    if args.web:
        from sentinels.web.server import start
        start()
        return

    if args.repo_url:
        repo_url = args.repo_url.strip()
        output = args.output
    else:
        try:
            repo_url, output = prompt_repo()
        except (KeyboardInterrupt, EOFError):
            print()
            print(_c(RED, "\n  Cancelled."))
            sys.exit(0)

    print()
    divider()
    print()
    log("*", YELLOW, "Starting scan — this may take a few minutes ...\n")

    try:
        report, elapsed = asyncio.run(run_scan(repo_url))
    except KeyboardInterrupt:
        print()
        log("x", RED, "Scan cancelled by user.")
        sys.exit(1)
    except Exception as exc:
        print()
        log("x", RED, f"Scan failed: {_c(BOLD, str(exc))}")
        if args.debug:
            raise
        sys.exit(1)

    mins, secs = divmod(int(elapsed), 60)
    duration = f"{mins}m {secs}s" if mins else f"{secs}s"

    print()
    divider()
    print()
    log("v", GREEN, f"Scan complete in {_c(BOLD, duration)}")
    print()

    if output:
        saved = save_report(report, output)
        log("v", GREEN, f"Report saved to: {_c(BOLD, str(saved.resolve()))}")
        print()
    else:
        print(_c(DIM, "  " + "─" * 60))
        print()
        print(report)
        print()
        print(_c(DIM, "  " + "─" * 60))
        print()

    # If run non-interactively via arguments, exit cleanly
    if args.repo_url:
        return

    # Ask if they want to scan another repo
    try:
        again = input(_c(CYAN, "  > Scan another repository? (y/N): ")).strip().lower()
        if again == "y":
            main()
    except (KeyboardInterrupt, EOFError):
        pass

    print()
    print(_c(DIM, "  Goodbye."))
    print()

if __name__ == "__main__":
    main()

