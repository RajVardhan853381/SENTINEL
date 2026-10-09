# src/sentinels/reporting/__init__.py
"""
Unified Multi-Format Reporting Pipeline for Sentinels.
Exports executive White-Theme PDF, Developer Markdown, and OASIS SARIF 2.1.0 JSON.
"""
import os
import re
from pathlib import Path
from typing import List, Dict

from sentinels.schemas.finding import Finding
from sentinels.schemas.manifest import RepoManifest
from sentinels.reporting.sarif_exporter import export_sarif_file
from sentinels.reporting.markdown_exporter import export_markdown_file
from sentinels.reporting.pdf_exporter import export_pdf_file

def _safe_slug(repo_url: str) -> str:
    """Extracts a filesystem-safe slug from a git repository URL."""
    clean = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    slug = re.sub(r"[^a-zA-Z0-9_\-]", "_", clean)
    return slug or "repository"

def export_all_reports(
    manifest: RepoManifest,
    findings: List[Finding],
    raw_manager_text: str = "",
    output_dir: str = "reports"
) -> Dict[str, str]:
    """
    Exports scan results across all three formats into the designated output directory.
    Returns:
        dict mapping 'pdf', 'markdown', and 'sarif' to their generated file paths.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    slug = _safe_slug(manifest.repo_url)
    base_prefix = str((out_path / slug).resolve())

    pdf_file = f"{base_prefix}_audit_report.pdf"
    md_file = f"{base_prefix}_audit_report.md"
    sarif_file = f"{base_prefix}_audit_report.sarif"

    res = {}
    try:
        res["pdf"] = export_pdf_file(manifest, findings, pdf_file, raw_manager_text=raw_manager_text)
    except Exception as e:
        res["pdf_error"] = str(e)

    try:
        res["markdown"] = export_markdown_file(manifest, findings, md_file, raw_manager_text)
    except Exception as e:
        res["markdown_error"] = str(e)

    try:
        res["sarif"] = export_sarif_file(manifest, findings, sarif_file)
    except Exception as e:
        res["sarif_error"] = str(e)

    return res
