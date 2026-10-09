# src/sentinels/reporting/pdf_exporter.py
"""
Executive White-Theme PDF Report Exporter for Sentinels.
Generates an executive-grade PDF security audit report using ReportLab,
complete with KPI cards, structured finding tables, and one-click unified git diffs.
"""
import re
from datetime import datetime
from pathlib import Path
from typing import List
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable, Preformatted
)

from sentinels.schemas.finding import Finding, Severity
from sentinels.schemas.manifest import RepoManifest
from sentinels.reporting.theme import (
    WhiteThemeNumberedCanvas,
    get_white_theme_styles,
    create_status_chip,
    create_metric_card,
    COLOR_CANVAS,
    COLOR_PRIMARY_TEXT,
    COLOR_SECONDARY_TEXT,
    COLOR_ACCENT,
    COLOR_ACCENT_DARK,
    COLOR_ACCENT_LIGHT,
    COLOR_CARD_BG,
    COLOR_CARD_ALT,
    COLOR_BORDER,
    STATUS_COLORS
)

def _safe_xml(text: str | None) -> str:
    """Escapes special characters (<, >, &) so ReportLab XML paragraph parser never crashes."""
    if text is None:
        return ""
    return xml_escape(str(text))

def export_pdf_file(manifest: RepoManifest, findings: List[Finding], output_path: str, raw_manager_text: str = "") -> str:
    """Compiles findings into an executive-grade White Theme PDF report."""
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    styles = get_white_theme_styles()
    story = []

    # Count severities
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    total_findings = len(findings)
    crit_high = counts.get("Critical", 0) + counts.get("High", 0)
    med_low = counts.get("Medium", 0) + counts.get("Low", 0) + counts.get("Info", 0)
    risk_status = "CRITICAL" if counts.get("Critical", 0) > 0 else (
        "HIGH" if counts.get("High", 0) > 0 else (
            "MEDIUM" if counts.get("Medium", 0) > 0 else "CLEAN"
        )
    )

    # Check for unparsed findings warning if findings is 0 but text mentions vulnerabilities
    has_unparsed_warnings = False
    if not findings and raw_manager_text:
        keywords = ["cwe-", "cve-", "vulnerability", "sql injection", "hardcoded secret", "critical", "high severity"]
        lower_raw = raw_manager_text.lower()
        if any(k in lower_raw for k in keywords):
            has_unparsed_warnings = True
            risk_status = "WARNING"

    repo_slug = manifest.repo_url.rstrip("/").split("/")[-1].replace(".git", "")

    # Top Header Badge
    top_badge = Table([[
        Paragraph(
            "<b><font size='8' color='#4F46E5'>SENTINELS — AUTONOMOUS SECURITY AUDIT &amp; DUE DILIGENCE</font></b>",
            styles["TableCellText"]
        )
    ]], colWidths=[540], rowHeights=[20])
    top_badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_ACCENT_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.75, COLOR_BORDER),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(top_badge)
    story.append(Spacer(1, 12))

    # Cover Title & Subtitle
    story.append(Paragraph(f"Security Audit: {_safe_xml(repo_slug)}", styles["CoverTitle"]))
    story.append(Paragraph("Verified Multi-Agent Vulnerability Assessment &amp; Remediation Plan", styles["CoverSubtitle"]))

    # Executive Metadata Box
    scan_time = datetime.now().strftime("%B %d, %Y - %H:%M UTC")
    langs_str = ", ".join(manifest.languages) if manifest.languages else "Unspecified"
    meta_data = [
        [
            Paragraph(f"<b>Target Repository:</b> {_safe_xml(manifest.repo_url)}", styles["CoverMeta"]),
            Paragraph(f"<b>Scan Date:</b> {scan_time}", styles["CoverMeta"])
        ],
        [
            Paragraph(f"<b>Languages:</b> {_safe_xml(langs_str)}", styles["CoverMeta"]),
            Paragraph(f"<b>Files Scanned:</b> {manifest.total_files}", styles["CoverMeta"])
        ],
        [
            Paragraph(f"<b>Overall Risk:</b> <b>{risk_status}</b>", styles["CoverMeta"]),
            Paragraph("<b>Scanner Engine:</b> Sentinels AI Multi-Agent v0.2.0", styles["CoverMeta"])
        ],
    ]
    t_meta = Table(meta_data, colWidths=[310, 230])
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_CARD_BG),
        ("BOX", (0, 0), (-1, -1), 0.75, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 14))

    # 4 Executive KPI Cards
    c1 = create_metric_card("Total Findings", str(total_findings), "Verified Vulnerabilities", styles, COLOR_ACCENT)
    c2 = create_metric_card("Critical & High", str(crit_high), "Immediate Action Needed", styles, colors.HexColor("#DC2626"))
    c3 = create_metric_card("Medium & Low", str(med_low), "Hardening & Best Practice", styles, colors.HexColor("#D97706"))
    c4 = create_metric_card("Files Analyzed", str(manifest.total_files), f"{len(manifest.languages)} Tech Stacks", styles, colors.HexColor("#16A34A"))

    t_kpis = Table([[c1, c2, c3, c4]], colWidths=[135, 135, 135, 135])
    t_kpis.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(t_kpis)
    story.append(Spacer(1, 14))

    # Section 1: Executive Findings Table
    story.append(Paragraph("1. Verified Security Findings Summary", styles["AuditH1"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_ACCENT, spaceBefore=2, spaceAfter=8))

    if not findings:
        if has_unparsed_warnings:
            p_msg = Paragraph(
                "<b>AUDIT WARNING:</b> Automated extraction found 0 structured JSON findings, but the auditor synthesis "
                "contains potential vulnerability discussions. Please consult the full Developer Markdown report for details.",
                styles["AuditBody"]
            )
            bg_color = STATUS_COLORS["MEDIUM"]["bg"]
            border_color = STATUS_COLORS["MEDIUM"]["border"]
        else:
            p_msg = Paragraph(
                "<b>CLEAN REPOSITORY AUDIT:</b> No exploitable security vulnerabilities or critical misconfigurations were detected. "
                "All inspected packages, infrastructure scripts, and application source modules conform to baseline security policies.",
                styles["AuditBody"]
            )
            bg_color = STATUS_COLORS["PASS"]["bg"]
            border_color = STATUS_COLORS["PASS"]["border"]

        t_clean = Table([[p_msg]], colWidths=[540])
        t_clean.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_color),
            ("BOX", (0, 0), (-1, -1), 0.75, border_color),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ]))
        story.append(t_clean)
    else:
        table_rows = [
            [
                Paragraph("<b>Sev</b>", styles["TableHeadText"]),
                Paragraph("<b>Finding Title</b>", styles["TableHeadText"]),
                Paragraph("<b>File Location</b>", styles["TableHeadText"]),
                Paragraph("<b>Classification</b>", styles["TableHeadText"])
            ]
        ]
        for f in findings:
            chip = create_status_chip(f.severity.value, styles)
            p_title = Paragraph(f"<b>{_safe_xml(f.title)}</b>", styles["TableCellText"])
            p_loc = Paragraph(f"<code>{_safe_xml(f.file)}:{f.line_start}</code>", styles["TableCellText"])
            classif = _safe_xml(f.cwe)
            if f.owasp:
                classif += f"<br/><font color='#64748B'>{_safe_xml(f.owasp)}</font>"
            p_cwe = Paragraph(classif, styles["TableCellText"])
            table_rows.append([chip, p_title, p_loc, p_cwe])

        t_summary = Table(table_rows, colWidths=[70, 220, 140, 110])
        t_summary.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_ACCENT_DARK),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_CANVAS, COLOR_CARD_BG]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_summary)

        # Section 2: Detailed Remediation Cards & Git Patches
        story.append(PageBreak())
        story.append(Paragraph("2. Vulnerability Details &amp; One-Click Remediation Patches", styles["AuditH1"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=COLOR_ACCENT, spaceBefore=2, spaceAfter=8))

        for idx, f in enumerate(findings, 1):
            detail_flowables = []
            header_text = f"<b>Finding #{idx}: [{_safe_xml(f.severity.value.upper())}] {_safe_xml(f.title)}</b>"
            detail_flowables.append(Paragraph(header_text, styles["AuditH2"]))
            detail_flowables.append(Paragraph(f"<b>Location:</b> <code>{_safe_xml(f.file)} (Lines {f.line_start}-{f.line_end})</code> | <b>CWE:</b> {_safe_xml(f.cwe)}", styles["AuditBody"]))
            detail_flowables.append(Paragraph(f"<b>Description:</b> {_safe_xml(f.description)}", styles["AuditBody"]))
            
            if f.evidence:
                detail_flowables.append(Paragraph("<b>Vulnerable Code Evidence:</b>", styles["TableCellBold"]))
                ev_safe = _safe_xml(f.evidence).replace("\n", "<br/>")
                p_ev = Paragraph(f"<code>{ev_safe}</code>", styles["AuditCodeBlock"])
                t_ev = Table([[p_ev]], colWidths=[510])
                t_ev.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), COLOR_CARD_ALT),
                    ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                detail_flowables.append(t_ev)
                detail_flowables.append(Spacer(1, 4))

            detail_flowables.append(Paragraph(f"<b>Remediation Guidance:</b> {_safe_xml(f.remediation)}", styles["AuditBody"]))

            # Render Git Diff Patch if present
            if f.patch:
                detail_flowables.append(Paragraph("<b>One-Click Remediation Patch (Git Diff):</b>", styles["TableCellBold"]))
                patch_html = _safe_xml(f.patch).replace("\n", "<br/>")
                p_patch = Paragraph(f"<code>{patch_html}</code>", styles["AuditCodeBlock"])
                t_patch = Table([[p_patch]], colWidths=[510])
                t_patch.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#BBF7D0")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                detail_flowables.append(t_patch)

            card_table = Table([[detail_flowables]], colWidths=[530])
            card_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), COLOR_CARD_BG),
                ("BOX", (0, 0), (-1, -1), 0.75, COLOR_BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(card_table)
            story.append(Spacer(1, 10))

    # Build PDF
    doc = SimpleDocTemplate(
        str(dest.resolve()),
        pagesize=letter,
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch
    )
    doc.build(story, canvasmaker=WhiteThemeNumberedCanvas)
    return str(dest.resolve())
