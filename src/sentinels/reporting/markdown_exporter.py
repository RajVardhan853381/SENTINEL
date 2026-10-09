# src/sentinels/reporting/markdown_exporter.py
"""
Developer-Focused Markdown Security Report Exporter.
Generates a structured, prioritized report with findings, evidence,
OWASP mapping, and syntax-highlighted git diff patches.
"""
from datetime import datetime
from pathlib import Path
from typing import List
from sentinels.schemas.finding import Finding, Severity
from sentinels.schemas.manifest import RepoManifest

def generate_markdown_content(manifest: RepoManifest, findings: List[Finding], raw_manager_text: str = "") -> str:
    """Generates comprehensive markdown report content."""
    # Count severities
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    total_vulns = len(findings)
    risk_level = "CRITICAL" if counts.get("Critical", 0) > 0 else (
        "HIGH" if counts.get("High", 0) > 0 else (
            "MEDIUM" if counts.get("Medium", 0) > 0 else "LOW"
        )
    )
    if total_vulns == 0:
        risk_level = "CLEAN / SECURE"

    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md = f"""# Sentinels Security Audit Report
**Target Repository:** `{manifest.repo_url}`  
**Scan Timestamp:** {scan_date}  
**Languages Detected:** {', '.join(manifest.languages) if manifest.languages else 'Unspecified'}  
**Overall Risk Posture:** **{risk_level}**  

---

## 1. Executive Summary

Sentinels performed an automated, multi-agent security audit across application source code, 
infrastructure configurations, and third-party dependencies.

| Metric | Value |
|---|---|
| **Total Files Analyzed** | {manifest.total_files} |
| **Total Verified Findings** | **{total_vulns}** |
| **Critical Severity** | {counts.get('Critical', 0)} |
| **High Severity** | {counts.get('High', 0)} |
| **Medium Severity** | {counts.get('Medium', 0)} |
| **Low / Info Severity** | {counts.get('Low', 0) + counts.get('Info', 0)} |

---

## 2. Verified Security Findings
"""

    if not findings:
        md += """
> **No exploitable security vulnerabilities or critical misconfigurations were identified.**  
> All static analysis triggers and dependency manifests were inspected and verified benign.
"""
    else:
        for idx, f in enumerate(findings, 1):
            owasp_badge = f" | **OWASP:** `{f.owasp}`" if f.owasp else ""
            cve_badge = f" | **CVE:** `{f.cve}`" if f.cve else ""
            md += f"""
### {idx}. [{f.severity.value.upper()}] {f.title}
- **File:** `{f.file}:{f.line_start}-{f.line_end}`
- **CWE:** `{f.cwe}`{owasp_badge}{cve_badge}
- **Confidence:** `{f.confidence.value}`

**Description:**  
{f.description}

**Vulnerable Evidence:**  
```
{f.evidence}
```

**Remediation Guidance:**  
{f.remediation}
"""
            if f.patch:
                md += f"""
**One-Click Remediation Patch (Git Diff):**
```diff
{f.patch}
```
"""
            md += "\n---\n"

    # If the manager agent produced valuable additional high-level synthesis, append it
    if raw_manager_text and len(raw_manager_text.strip()) > 50 and not raw_manager_text.strip().startswith("["):
        md += f"""
## 3. Manager Agent Strategic Synthesis & Roadmap
{raw_manager_text.strip()}
"""
    else:
        md += """
## 3. Recommended Remediation Plan
1. **Immediate P0 Action:** Apply one-click git patches for all Critical and High vulnerabilities.
2. **Dependency Upgrades:** Upgrade outdated libraries flagged in the SCA scan.
3. **CI/CD Security Gate:** Integrate Sentinels SARIF output into GitHub Actions to fail PRs on new Critical findings.
"""

    return md

def export_markdown_file(manifest: RepoManifest, findings: List[Finding], output_path: str, raw_text: str = "") -> str:
    """Exports findings as a Markdown file and returns the file path."""
    content = generate_markdown_content(manifest, findings, raw_text)
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w", encoding="utf-8") as f:
        f.write(content)
    return str(dest.resolve())
