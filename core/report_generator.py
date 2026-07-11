"""
Report Generator
================
Produces PDF reports from module execution results.

Every audit or attack module returns a standardised result dict containing
a 'findings' list. This generator formats those findings into a single
professional PDF report per run, using reportlab.

PDF was chosen as the only supported output format on purpose: TXT/CSV
reports were dropped, since in a real engagement the only deliverable that
matters is a polished PDF a client or jury can actually read.

Report naming convention:
    reports/<label>_<YYYYMMDD_HHMMSS>.pdf
"""

import os
from datetime import datetime
from typing import Union

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

from core.logger import FrameworkLogger
from utils.format_utils import print_success, print_error

logger = FrameworkLogger("ReportGenerator")

# Reports are saved in reports/ at the project root
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)  # Create reports/ directory if needed

# Risk level -> background color for the findings table (mirrors risk_badge()
# in utils/format_utils.py, which uses the same French risk vocabulary).
_RISK_COLORS = {
    "Critique": colors.HexColor("#e53935"),
    "Élevé":    colors.HexColor("#fb8c00"),
    "Critical": colors.HexColor("#e53935"),
    "High":     colors.HexColor("#fb8c00"),
    "Moyen":    colors.HexColor("#fdd835"),
    "Medium":   colors.HexColor("#fdd835"),
    "Faible":   colors.HexColor("#43a047"),
    "Low":      colors.HexColor("#43a047"),
    "Info":     colors.HexColor("#1e88e5"),
}
_DEFAULT_RISK_COLOR = colors.HexColor("#9e9e9e")


class ReportGenerator:
    """
    Generates a PDF report from module results.

    Args:
        output_format (str): Kept for backward-compatible call sites; the
                              only supported value is 'pdf'.

    Usage:
        gen = ReportGenerator()
        gen.generate(results, label="blue_team_audit")
    """

    def __init__(self, output_format: str = "pdf", secrets: list = None):
        self.output_format = "pdf"
        # Known sensitive values (e.g. configured passwords) to redact from
        # report text as a defense-in-depth layer, on top of modules already
        # masking cleartext credentials in their own findings.
        self._secrets = [s for s in (secrets or []) if s]

    def generate(self, results: Union[dict, list], label: str, output_format: str = None):
        """
        Generate a PDF report for the given module results.

        Args:
            results       : Single result dict or list of result dicts.
            label         : Base filename label (e.g. 'blue_team_full').
            output_format : Ignored except for backward compatibility; PDF is
                            the only supported format.
        """
        # Normalise to list — a single result dict is wrapped in a list
        if not isinstance(results, list):
            results = [results]

        # Build timestamped filename
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(REPORTS_DIR, f"{label}_{ts}.pdf")

        self._write_pdf(results, path)

    # ── Redaction ─────────────────────────────────────────────────────────────

    def _redact(self, text) -> str:
        """
        Mask any configured secret values that appear verbatim in report text.

        This is a defense-in-depth safety net on top of modules masking
        cleartext credentials in their own findings (e.g. password_spray.py);
        it catches known config-level passwords that shouldn't end up in a
        written report even if they were echoed somewhere unexpected.
        """
        text = str(text) if text is not None else ""
        for secret in self._secrets:
            if secret and secret in text:
                text = text.replace(secret, "*" * min(len(secret), 8))
        return text

    # ── PDF report ────────────────────────────────────────────────────────────

    def _write_pdf(self, results: list, path: str):
        """Write a single PDF report covering all module results."""
        try:
            doc = SimpleDocTemplate(
                path, pagesize=A4,
                topMargin=2 * cm, bottomMargin=2 * cm,
                leftMargin=2 * cm, rightMargin=2 * cm,
            )
            styles = self._styles()
            story = []

            story += self._pdf_title_page(styles)
            for res in results:
                story += self._pdf_module_section(res, styles)
            story += self._pdf_summary(results, styles)

            doc.build(story)
            print_success(f"PDF report: {path}")
            logger.info(f"PDF report generated: {path}")
        except Exception as e:
            print_error(f"PDF generation error: {e}")

    def _styles(self):
        """Build the paragraph styles used throughout the PDF."""
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="ReportTitle", parent=styles["Title"], fontSize=20, spaceAfter=6,
        ))
        styles.add(ParagraphStyle(
            name="ReportSubtitle", parent=styles["Normal"], fontSize=10,
            textColor=colors.grey, alignment=TA_CENTER, spaceAfter=4,
        ))
        styles.add(ParagraphStyle(
            name="ModuleHeading", parent=styles["Heading2"],
            textColor=colors.HexColor("#1e293b"), spaceBefore=14, spaceAfter=6,
        ))
        styles.add(ParagraphStyle(
            name="CellText", parent=styles["Normal"], fontSize=8, leading=10,
        ))
        styles.add(ParagraphStyle(
            name="CellTextBold", parent=styles["CellText"], fontName="Helvetica-Bold",
        ))
        return styles

    def _pdf_title_page(self, styles) -> list:
        """Build the cover section: title, generation timestamp, authors."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story = [
            Spacer(1, 4 * cm),
            Paragraph("AD Attack &amp; Defense Simulation", styles["ReportTitle"]),
            Paragraph("Rapport d'exécution", styles["ReportSubtitle"]),
            Spacer(1, 0.5 * cm),
            Paragraph(f"Généré le {now}", styles["ReportSubtitle"]),
            Paragraph("NISSEKONG Georges Owen | DIOP Salla", styles["ReportSubtitle"]),
            PageBreak(),
        ]
        return story

    def _pdf_module_section(self, res: dict, styles) -> list:
        """Build the section for a single module: metadata + findings table."""
        story = []
        module = self._redact(res.get("module", "N/A"))
        story.append(Paragraph(module, styles["ModuleHeading"]))

        meta_rows = [
            ["Status",   self._redact(res.get("status", "N/A"))],
            ["Duration", f"{res.get('elapsed_s', 0)}s"],
            ["Date",     self._redact(res.get("timestamp", "N/A"))],
        ]
        if res.get("message"):
            meta_rows.append(["Message", self._redact(res["message"])])

        meta_table = Table(
            [[Paragraph(k, styles["CellTextBold"]), Paragraph(v, styles["CellText"])] for k, v in meta_rows],
            colWidths=[3 * cm, 13 * cm],
        )
        meta_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.3 * cm))

        findings = res.get("findings", [])
        if findings:
            story.append(self._findings_table(findings, styles))
        else:
            story.append(Paragraph("Aucun finding pour ce module.", styles["CellText"]))

        story.append(Spacer(1, 0.4 * cm))
        return story

    def _findings_table(self, findings: list, styles) -> Table:
        """Build a color-coded table of findings (risk / title / description / mitigation)."""
        header = [Paragraph(h, styles["CellTextBold"]) for h in
                  ("Risque", "Titre", "Description", "Mitigation")]
        rows = [header]
        row_risk_colors = [None]  # header row has no risk color

        for f in findings:
            risk  = f.get("risk", "Info")
            title = self._redact(f.get("title", "—"))
            desc  = self._redact(f.get("description", ""))
            mitig = self._redact(f.get("mitigation", ""))
            rows.append([
                Paragraph(risk, styles["CellTextBold"]),
                Paragraph(title, styles["CellText"]),
                Paragraph(desc, styles["CellText"]),
                Paragraph(mitig, styles["CellText"]),
            ])
            row_risk_colors.append(_RISK_COLORS.get(risk, _DEFAULT_RISK_COLOR))

        table = Table(rows, colWidths=[2 * cm, 3.5 * cm, 5.5 * cm, 5 * cm], repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]
        # Tint the risk column per-row according to severity
        for i, color in enumerate(row_risk_colors):
            if color is not None:
                style.append(("BACKGROUND", (0, i), (0, i), color))
                style.append(("TEXTCOLOR", (0, i), (0, i), colors.white))
        table.setStyle(TableStyle(style))
        return table

    def _pdf_summary(self, results: list, styles) -> list:
        """Build the closing summary section with aggregated statistics."""
        total    = len(results)
        errors   = sum(1 for r in results if r.get("status") == "error")
        findings = sum(len(r.get("findings", [])) for r in results)
        critical = sum(
            1 for r in results
            for f in r.get("findings", [])
            if f.get("risk") in ("Critique", "Élevé", "Critical", "High")
        )

        rows = [
            ["Modules exécutés", str(total)],
            ["Erreurs",          str(errors)],
            ["Total findings",   str(findings)],
            ["Critique/Élevé",   str(critical)],
        ]
        table = Table(
            [[Paragraph(k, styles["CellTextBold"]), Paragraph(v, styles["CellText"])] for k, v in rows],
            colWidths=[6 * cm, 4 * cm],
        )
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))

        return [
            PageBreak(),
            Paragraph("Résumé", styles["ModuleHeading"]),
            table,
        ]
