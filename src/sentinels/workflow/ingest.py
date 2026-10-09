import os
import shutil
import stat
import sys
from collections import defaultdict
from agent_framework import step
from sentinels.schemas.manifest import RepoManifest, FileInfo, DirectoryCluster
from sentinels.mcp_server.tools.repo import clone_repo, list_files

# Map extensions to programming languages
LANGUAGE_MAP = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".jsx": "React", ".tsx": "React", ".tf": "Terraform",
    ".bicep": "Bicep", ".go": "Go", ".java": "Java",
    ".rb": "Ruby", ".php": "PHP", ".rs": "Rust",
    ".cs": "C#", ".cpp": "C++", ".c": "C",
    ".yaml": "YAML", ".yml": "YAML", ".json": "JSON",
    ".toml": "TOML", ".sh": "Shell"
}

# Critical entrypoints and config files given priority in windowed manifests
HIGH_PRIORITY_PATTERNS = {
    "package.json", "requirements.txt", "pyproject.toml", "pipfile",
    "go.mod", "cargo.toml", "dockerfile", "docker-compose.yml",
    "main.py", "app.py", "index.js", "server.js", "main.go",
    ".env.example", "main.tf", "variables.tf"
}

def _cluster_directory(rel_path: str) -> str:
    """Computes a 1-to-2 level logical directory cluster for a given file path."""
    parts = rel_path.replace("\\", "/").split("/")
    if len(parts) <= 1:
        return "."  # Root file
    if len(parts) == 2:
        return parts[0]
    return f"{parts[0]}/{parts[1]}"

@step
async def ingest_repo(repo_url: str) -> RepoManifest:
    """
    Deterministic step: Clones the repo and builds the RepoManifest.
    Clusters directories and windows file listings for large repositories
    to prevent LLM context exhaustion.
    """
    # 1. Deterministic clone and file collection
    local_path = clone_repo(repo_url)
    sandbox_dir = os.path.dirname(os.path.abspath(local_path))

    try:
        files_str = list_files(local_path)
        
        # 2. Enrich the file list with language detection & clustering
        files_info = []
        detected_languages = set()
        cluster_map = defaultdict(lambda: {"count": 0, "languages": set(), "samples": []})
        
        for rel_path in files_str:
            ext = os.path.splitext(rel_path)[1].lower()
            language = LANGUAGE_MAP.get(ext, "Unknown")
            
            if language != "Unknown":
                detected_languages.add(language)

            full_file_path = os.path.join(local_path, rel_path)
            try:
                size_bytes = os.path.getsize(full_file_path)
            except (OSError, FileNotFoundError):
                size_bytes = 0

            file_item = FileInfo(
                path=rel_path,
                size_bytes=size_bytes,
                language=language
            )
            files_info.append(file_item)

            # Cluster assignment
            cluster_name = _cluster_directory(rel_path)
            cluster_map[cluster_name]["count"] += 1
            if language != "Unknown":
                cluster_map[cluster_name]["languages"].add(language)
            if len(cluster_map[cluster_name]["samples"]) < 5:
                cluster_map[cluster_name]["samples"].append(os.path.basename(rel_path))

        # Build DirectoryCluster objects
        directory_clusters = [
            DirectoryCluster(
                directory=c_name,
                file_count=c_data["count"],
                languages=sorted(list(c_data["languages"])),
                sample_files=c_data["samples"]
            )
            for c_name, c_data in sorted(cluster_map.items(), key=lambda x: x[1]["count"], reverse=True)
        ]

        # 3. Detect framework indicators
        detected_frameworks = set()
        file_basenames = {os.path.basename(f.path).lower() for f in files_info}
        if "package.json" in file_basenames:
            detected_frameworks.add("Node.js")
        if "pyproject.toml" in file_basenames or "requirements.txt" in file_basenames:
            detected_frameworks.add("Python")
        if "cargo.toml" in file_basenames:
            detected_frameworks.add("Rust")
        if "go.mod" in file_basenames:
            detected_frameworks.add("Go")
        if any(f.path.endswith(".tf") for f in files_info):
            detected_frameworks.add("Terraform")
        if any(f.path.endswith(".bicep") for f in files_info):
            detected_frameworks.add("Bicep")

        # 4. Manifest Windowing for large monorepos (>250 files)
        is_windowed = len(files_info) > 250
        final_files = files_info
        if is_windowed:
            # Prioritize configs and entrypoints, plus top files from each cluster
            priority_files = []
            regular_files = []
            for f in files_info:
                bname = os.path.basename(f.path).lower()
                if bname in HIGH_PRIORITY_PATTERNS or any(p in bname for p in ["config", "settings", "schema"]):
                    priority_files.append(f)
                else:
                    regular_files.append(f)
            
            # Keep up to 150 representative files
            final_files = (priority_files + regular_files)[:150]

        # 5. Construct the structured manifest
        manifest = RepoManifest(
            repo_url=repo_url,
            local_path=local_path,
            sandbox_dir=sandbox_dir,
            total_files=len(files_info),
            languages=sorted(list(detected_languages)),
            frameworks=sorted(list(detected_frameworks)),
            files=final_files,
            is_windowed=is_windowed,
            directory_clusters=directory_clusters
        )
        
        return manifest
    except Exception:
        # Guarantee ephemeral sandbox is removed if ingestion encounters any error
        if sandbox_dir and os.path.exists(sandbox_dir) and os.path.basename(sandbox_dir).startswith("sentinel_scan_"):
            def _clean(func, path, exc_info):
                try:
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                except Exception:
                    pass
            if sys.version_info >= (3, 12):
                shutil.rmtree(sandbox_dir, onexc=_clean)
            else:
                shutil.rmtree(sandbox_dir, onerror=_clean)
        raise