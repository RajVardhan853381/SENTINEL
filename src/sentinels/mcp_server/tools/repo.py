# src/sentinels/mcp_server/tools/repo.py
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

# Define directories to ignore during file listing
IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
MAX_FILE_SIZE_BYTES = 1_000_000 # 1 MB limit to prevent reading massive files

def clone_repo(repo_url: str) -> str:
    """
    Clones a GitHub repository into a secure local sandbox.
    Args:
        repo_url: The URL of the GitHub repository (e.g., https://github.com/user/repo).
    Returns:
        The local path to the cloned repository.
    """
    clean_url = repo_url.strip().rstrip("/")
    # Security: Validate URL is strictly https to prevent local file access exploits
    if not clean_url.startswith("https://"):
        raise ValueError("Only HTTPS GitHub URLs are allowed.")

    # Create a unique temporary directory for this scan
    sandbox_dir = tempfile.mkdtemp(prefix="sentinel_scan_")
    repo_name = clean_url.split("/")[-1].replace(".git", "") or "repo"
    local_path = os.path.join(sandbox_dir, repo_name)

    git_env = os.environ.copy()
    git_env["GIT_TERMINAL_PROMPT"] = "0"

    try:
        # Clone with --depth 1 for speed and to avoid scanning git history, with 120s timeout
        subprocess.run(
            ["git", "clone", "--depth", "1", clean_url, local_path],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
            env=git_env
        )
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(sandbox_dir, ignore_errors=True)
        raise RuntimeError(f"Git clone timed out after 120s for {clean_url}") from exc
    except subprocess.CalledProcessError as exc:
        # Avoid leaving orphaned temp directory if clone fails
        shutil.rmtree(sandbox_dir, ignore_errors=True)
        err_msg = exc.stderr.strip() if exc.stderr else f"Exit code {exc.returncode}"
        raise RuntimeError(f"Git clone failed for {clean_url}: {err_msg}") from exc

    return local_path

def list_files(local_path: str) -> list[str]:
    """
    Lists all relevant source files in the cloned repository, ignoring common noise directories.
    Args:
        local_path: The local path returned by clone_repo.
    Returns:
        A list of relative file paths.
    """
    files = []
    for root, dirs, filenames in os.walk(local_path):
        # Remove ignored directories in-place to prevent os.walk from traversing them
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        
        for filename in filenames:
            full_path = os.path.join(root, filename)
            relative_path = os.path.relpath(full_path, local_path)
            files.append(relative_path)
            
    return files

def read_file(local_path: str, relative_file_path: str) -> str:
    """
    Reads the contents of a specific file in the repository.
    Args:
        local_path: The root path of the cloned repo.
        relative_file_path: The path to the file relative to the repo root.
    Returns:
        The string contents of the file.
    """
    # Handle either relative path or absolute path safely
    if os.path.isabs(relative_file_path):
        target_file = os.path.abspath(relative_file_path)
    else:
        target_file = os.path.abspath(os.path.join(local_path, relative_file_path))

    # Security: Symlink Resolution & Path Traversal Protection
    # Both paths are canonicalized with realpath to ensure symlinks inside the sandbox
    # cannot escape to host sensitive files.
    real_local = os.path.realpath(local_path)
    real_target = os.path.realpath(target_file)

    if not (real_target == real_local or real_target.startswith(real_local + os.sep)):
        return f"[Access denied: Path traversal detected for {relative_file_path}]"

    # Gracefully handle non-existent files or directories instead of crashing
    if not os.path.exists(real_target):
        return f"[File not found: {relative_file_path}]"

    if os.path.isdir(real_target):
        return f"[Path is a directory, not a file: {relative_file_path}]"
    
    # Prevent reading huge files that would blow up the LLM context window
    try:
        if os.path.getsize(real_target) > MAX_FILE_SIZE_BYTES:
            return f"[File skipped: Exceeds maximum size of {MAX_FILE_SIZE_BYTES} bytes]"

        with open(real_target, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except (OSError, UnicodeDecodeError) as exc:
        return f"[Error reading file {relative_file_path}: {exc}]"