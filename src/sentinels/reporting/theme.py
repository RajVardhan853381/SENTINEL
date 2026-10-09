# src/sentinels/reporting/theme.py
"""
White Theme ReportLab Styling & Canvas Engine for Sentinels.
Executive Stripe Radar / McKinsey aesthetic: crisp white canvas (#FFFFFF),
deep slate typography (#0F172A), electric indigo brand accents (#4F46E5),
slate-50 card surfaces (#F8FAFC), and pastel semantic status badges.
"""
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle

# ------------------------------------------------------------------------------
# 1. White Theme Color Palette Tokens
# ------------------------------------------------------------------------------
COLOR_CANVAS = colors.HexColor("#FFFFFF")
COLOR_PRIMARY_TEXT = colors.HexColor("#0F172A")    # Deep Navy Slate (900)
COLOR_SECONDARY_TEXT = colors.HexColor("#475569")  # Slate 600
COLOR_MUTED_TEXT = colors.HexColor("#64748B")      # Slate 500

COLOR_ACCENT = colors.HexColor("#4F46E5")          # Electric Indigo (600)
COLOR_ACCENT_DARK = colors.HexColor("#312E81")     # Indigo 900
COLOR_ACCENT_LIGHT = colors.HexColor("#EEF2FF")    # Indigo 50

COLOR_CARD_BG = colors.HexColor("#F8FAFC")         # Slate 50
COLOR_CARD_ALT = colors.HexColor("#F1F5F9")        # Slate 100
COLOR_BORDER = colors.HexColor("#E2E8F0")          # Slate 200

# Semantic Status Badge Palettes
STATUS_COLORS = {
    "CRITICAL": {
        "bg": colors.HexColor("#FEF2F2"),
        "text": colors.HexColor("#DC2626"),
        "border": colors.HexColor("#FECACA")
    },
    "HIGH": {
        "bg": colors.HexColor("#FFF7ED"),
        "text": colors.HexColor("#EA580C"),
        "border": colors.HexColor("#FED7AA")
    },
    "MEDIUM": {
        "bg": colors.HexColor("#FFFBEB"),
        "text": colors.HexColor("#D97706"),
        "border": colors.HexColor("#FDE68A")
    },
    "LOW": {
        "bg": colors.HexColor("#F0F9FF"),
        "text": colors.HexColor("#0284C7"),
        "border": colors.HexColor("#BAE6FD")
    },
    "INFO": {
        "bg": colors.HexColor("#F8FAFC"),
        "text": colors.HexColor("#475569"),
        "border": colors.HexColor("#E2E8F0")
    },
    "PASS": {
        "bg": colors.HexColor("#F0FDF4"),
        "text": colors.HexColor("#16A34A"),
        "border": colors.HexColor("#BBF7D0")
    }
}

# ------------------------------------------------------------------------------
# 2. Dynamic Two-Pass NumberedCanvas ("Page X of Y" + Running Header)
# ------------------------------------------------------------------------------
class WhiteThemeNumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages: int):
        if self._pageNumber == 1:
            return  # Skip running headers on cover page

        self.saveState()
        page_width, page_height = 8.5 * inch, 11 * inch
        margin = 0.5 * inch

        # Header
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(COLOR_ACCENT)
        self.drawString(margin, page_height - 0.42 * inch, "SENTINELS")
        self.setFont("Helvetica", 7.5)
        self.setFillColor(COLOR_MUTED_TEXT)
        self.drawString(margin + 58, page_height - 0.42 * inch, "|  AUTONOMOUS SECURITY AUDIT REPORT")
        
        self.setStrokeColor(COLOR_BORDER)
        self.setLineWidth(0.75)
        self.line(margin, page_height - 0.48 * inch, page_width - margin, page_height - 0.48 * inch)

        # Footer
        self.line(margin, 0.52 * inch, page_width - margin, 0.52 * inch)
        self.setFont("Helvetica", 7.5)
        self.setFillColor(COLOR_MUTED_TEXT)
        self.drawString(margin, 0.38 * inch, "CONFIDENTIAL  —  Automated Agentic Security Verification")
        
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(page_width - margin, 0.38 * inch, page_str)
        self.restoreState()

# ------------------------------------------------------------------------------
# 3. Typography Stylesheet Factory
# ------------------------------------------------------------------------------
def get_white_theme_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="CoverTitle",
        fontName="Helvetica-Bold",
        fontSize=26,
        leading=32,
        textColor=COLOR_PRIMARY_TEXT,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        name="CoverSubtitle",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=COLOR_ACCENT,
        spaceAfter=14,
    ))

    styles.add(ParagraphStyle(
        name="CoverMeta",
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=COLOR_SECONDARY_TEXT,
        spaceAfter=4,
    ))

    styles.add(ParagraphStyle(
        name="AuditH1",
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=COLOR_PRIMARY_TEXT,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True,
    ))

    styles.add(ParagraphStyle(
        name="AuditH2",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=COLOR_ACCENT_DARK,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True,
    ))

    styles.add(ParagraphStyle(
        name="AuditBody",
        fontName="Helvetica",
        fontSize=8.5,
        leading=12.5,
        textColor=COLOR_PRIMARY_TEXT,
        spaceAfter=5,
    ))

    styles.add(ParagraphStyle(
        name="AuditBullet",
        fontName="Helvetica",
        fontSize=8,
        leading=12,
        textColor=COLOR_PRIMARY_TEXT,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=2,
    ))

    styles.add(ParagraphStyle(
        name="TableHeadText",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
    ))

    styles.add(ParagraphStyle(
        name="TableCellText",
        fontName="Helvetica",
        fontSize=7.5,
        leading=10.5,
        textColor=COLOR_PRIMARY_TEXT,
    ))

    styles.add(ParagraphStyle(
        name="TableCellBold",
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=10.5,
        textColor=COLOR_PRIMARY_TEXT,
    ))

    styles.add(ParagraphStyle(
        name="AuditCodeBlock",
        fontName="Courier",
        fontSize=7,
        leading=9.5,
        textColor=COLOR_PRIMARY_TEXT,
    ))

    return styles

def create_status_chip(status_str: str, styles) -> Table:
    """Creates a high-contrast rounded chip for status values."""
    key = status_str.upper()
    cfg = STATUS_COLORS.get(key, STATUS_COLORS["INFO"])

    p = Paragraph(
        f"<b><font size='6.5' color='{cfg['text'].hexval()}'>{status_str}</font></b>",
        styles["TableCellText"]
    )
    t = Table([[p]], colWidths=[65], rowHeights=[14])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), cfg["bg"]),
        ("BOX", (0, 0), (-1, -1), 0.75, cfg["border"]),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
    ]))
    return t

def create_metric_card(title: str, value: str, subtitle: str, styles, accent_color=COLOR_ACCENT) -> Table:
    """Creates a high-density 4-corner KPI card for executive summaries."""
    p_title = Paragraph(f"<font size='6.5' color='{COLOR_MUTED_TEXT.hexval()}'><b>{title.upper()}</b></font>", styles["TableCellText"])
    p_val = Paragraph(f"<font size='13' color='{COLOR_PRIMARY_TEXT.hexval()}'><b>{value}</b></font>", styles["TableCellText"])
    p_sub = Paragraph(f"<font size='6.5' color='{COLOR_SECONDARY_TEXT.hexval()}'>{subtitle}</font>", styles["TableCellText"])

    t = Table([[p_title], [p_val], [p_sub]], colWidths=[128])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_CARD_BG),
        ("BOX", (0, 0), (-1, -1), 0.75, COLOR_BORDER),
        ("LINEBEFORE", (0, 0), (0, -1), 2.5, accent_color),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t
