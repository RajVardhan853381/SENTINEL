# src/sentinels/workflow/orchestrator.py
import json
import os
import shutil
import stat
from pathlib import Path
from agent_framework import workflow

from sentinels.workflow.ingest import ingest_repo
from sentinels.agents.manager import create_manager_agent
from sentinels.schemas.manifest import RepoManifest
from sentinels.schemas.parser import extract_findings_resilient
from sentinels.reporting import export_all_reports

def _force_remove_readonly(func, path, exc_info) -> None:
    # git clone leaves packfiles/.idx files read-only; on Windows shutil.rmtree
    # can't delete those without first clearing the attribute.
    os.chmod(path, stat.S_IWRITE)
    func(path)

@workflow
async def sentinel_scan_workflow(repo_url: str) -> str:
    """
    The main entry point for a Sentinel security scan.
    Ties together deterministic ingestion, directory windowing,
    agentic orchestration, and automated multi-format report generation.
    """
    manifest: RepoManifest | None = None
    try:    
        # 1. Deterministic Ingestion & Clustering
        manifest = await ingest_repo(repo_url)

        # 2. Instantiate the Manager Agent
        manager = create_manager_agent()

        # 3. Format the prompt for the Manager
        # If the repository is large and windowed, provide directory clusters
        # to protect the prompt context limit.
        if manifest.is_windowed:
            clusters_desc = "\n".join([
                f"- Directory `{c.directory}`: {c.file_count} files ({', '.join(c.languages)}) [samples: {', '.join(c.sample_files[:3])}]"
                for c in manifest.directory_clusters[:20]
            ])
            sample_files_desc = "\n".join([f"- {f.path} ({f.language})" for f in manifest.files[:80]])
            manifest_summary = f"""
[NOTE: Large repository detected with {manifest.total_files} files. File listing clustered for efficiency.]

Architectural Directory Clusters:
{clusters_desc}

Sample Critical Configuration & Entrypoint Files:
{sample_files_desc}
"""
        else:
            manifest_summary = manifest.model_dump_json(indent=2)

        prompt = f"""
A repository has been cloned and is ready for security auditing.

Repository URL: {manifest.repo_url}
Local Sandbox Path: {manifest.local_path}
Detected Languages: {', '.join(manifest.languages)}
Detected Frameworks: {', '.join(manifest.frameworks)}
Total Files: {manifest.total_files}

File & Directory Manifest:
{manifest_summary}

Please orchestrate the comprehensive security audit now:
1. Check dependencies for CVEs using `audit_dependencies_tool`.
2. Dispatch workers across application and infrastructure directories.
3. Verify findings, generate unified git diff patches, and synthesize the report.
"""

        # 4. Execute the Manager Agent
        result = await manager.run(prompt)
        raw_report = result.text

        # 5. Extract structured findings and generate multi-format deliverables
        findings = extract_findings_resilient(raw_report)
        report_files = export_all_reports(manifest, findings, raw_report, output_dir="reports")

        # 6. Append deliverables banner to the returned report
        deliverables_banner = f"""

---
### 🛡️ Generated Security Audit Deliverables:
- **Executive White-Theme PDF:** `{report_files.get('pdf', 'N/A')}`
- **Developer Markdown Report:** `{report_files.get('markdown', 'N/A')}`
- **OASIS SARIF 2.1.0 File:** `{report_files.get('sarif', 'N/A')}`
- **Verified Findings Extracted:** {len(findings)}
"""
        return raw_report + deliverables_banner

    finally:
        # Safely delete the ephemeral sandbox
        target_sandbox = None
        if manifest:
            if manifest.sandbox_dir:
                target_sandbox = Path(manifest.sandbox_dir)
            elif manifest.local_path:
                candidate = Path(manifest.local_path).parent
                if candidate.name.startswith("sentinel_scan_"):
                    target_sandbox = candidate

        if target_sandbox and target_sandbox.exists() and target_sandbox.name.startswith("sentinel_scan_"):
            import sys
            if sys.version_info >= (3, 12):
                shutil.rmtree(target_sandbox, onexc=_force_remove_readonly)
            else:
                shutil.rmtree(target_sandbox, onerror=_force_remove_readonly)