# src/sentinels/mcp_server/tools/scanner.py
import json
import os
import re
import shutil
import subprocess
import sys

# Pre-compiled regex patterns for secret detection
COMPILED_SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"aws(?:.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]", re.IGNORECASE)),
    ("Generic API Key", re.compile(r"api[_-]?key(?:.{0,20})?['\"][0-9a-zA-Z]{32}['\"]", re.IGNORECASE)),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36}")),
]

def _resolve_semgrep_bin() -> str:
    """Finds the semgrep executable in PATH or the current Python virtual environment."""
    which_bin = shutil.which("semgrep")
    if which_bin:
        return which_bin
    venv_bin = os.path.dirname(sys.executable)
    candidate = os.path.join(venv_bin, "semgrep.exe" if os.name == "nt" else "semgrep")
    if os.path.isfile(candidate):
        return candidate
    return "semgrep"

def run_semgrep(local_path: str) -> list[dict]:
    """
    Runs a fast Semgrep scan on the target directory using default security rules.
    Args:
        local_path: The local path to the cloned repository (or a subdirectory).
    Returns:
        A list of raw semgrep findings (JSON objects).
    """
    semgrep_cmd = _resolve_semgrep_bin()

    try:
        # Run semgrep via subprocess. --json outputs machine-readable data.
        # We use the "auto" config which pulls standard security rules.
        result = subprocess.run(
            [semgrep_cmd, "scan", "--config", "auto", "--json", local_path],
            capture_output=True,
            text=True,
            check=False # Don't crash if semgrep finds issues or exits non-zero
        )
        
        data = json.loads(result.stdout)
        raw_findings = []

        # Parse the semgrep JSON into a lean list of dicts for the LLM
        for finding in data.get("results", []):
            raw_path = finding.get("path", "")
            # Convert absolute path from semgrep into relative path from local_path
            rel_file = raw_path
            if raw_path and os.path.isabs(raw_path):
                try:
                    rel_file = os.path.relpath(raw_path, local_path)
                except ValueError:
                    rel_file = raw_path

            raw_findings.append({
                "rule_id": finding.get("check_id", "Unknown"),
                "message": finding.get("extra", {}).get("message", "No message"),
                "severity": finding.get("extra", {}).get("severity", "UNKNOWN"),
                "file": rel_file,
                "line_start": finding.get("start", {}).get("line", 0),
                "line_end": finding.get("end", {}).get("line", 0)
            })

        return raw_findings

    except json.JSONDecodeError:
        # Semgrep has no native Windows binary (ships only for Linux/macOS/WSL);
        # on Windows the CLI process itself fails before printing JSON, which
        # lands here rather than in the FileNotFoundError branch below.
        if os.name == "nt":
            return [{"error": "Semgrep could not run: it has no native Windows binary. Run this scan from WSL, Docker, or Linux/macOS instead."}]
        return [{"error": "Failed to parse Semgrep output."}]
    except FileNotFoundError:
        return [{"error": "Semgrep is not installed on the system."}]

def run_secret_scan(local_path: str) -> list[dict]:
    """
    Scans files in the target directory for hardcoded secrets using regex patterns.
    Args:
        local_path: The local path to the cloned repository.
    Returns:
        A list of raw secret findings.
    """
    raw_findings = []
    
    for root, dirs, files in os.walk(local_path):
        # Ignore .git and common noisy directories
        if ".git" in dirs:
            dirs.remove(".git")
        if "node_modules" in dirs:
            dirs.remove("node_modules")
            
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, local_path)
            
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern_name, compiled_pattern in COMPILED_SECRET_PATTERNS:
                            if compiled_pattern.search(line):
                                raw_findings.append({
                                    "type": pattern_name,
                                    "file": rel_path,
                                    "line": line_num,
                                    "evidence": line.strip() # The exact line of code
                                })
            except (OSError, UnicodeDecodeError):
                continue # Skip unreadable files
                
    return raw_findings