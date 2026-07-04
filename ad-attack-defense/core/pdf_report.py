"""
PDF Report Generator
====================
Produces two types of professional PDF reports from framework results:

  1. TECHNICAL report  — full detail for SOC analysts, pentesters, developers.
     Includes: Event IDs, MITRE ATT&CK mappings, tool names, command examples,
     detection rules, CVE references, raw finding counts.

  2. GOVERNANCE report — executive summary for CISO, management, auditors.
     Includes: business risk ratings, impact on operations, remediation priority,
     compliance implications. No technical jargon or raw Event IDs.

Both reports support before/after comparison when two result sets are provided,
showing measurable security improvement between audit runs.

Library: ReportLab (Platypus high-level API)
Usage:
    from core.pdf_report import PDFReportGenerator
    gen = PDFReportGenerator()
    gen.generate(results, label="audit_2026", report_type="technical")
    gen.generate(results, label="audit_2026", report_type="governance")
"""

import os
from datetime import datetime
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Wedge, Circle
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

from core.logger import FrameworkLogger

logger = FrameworkLogger("PDFReport")

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "reports"
)
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Brand colours ─────────────────────────────────────────────────────────────
C_DARK    = colors.HexColor("#1A1A2E")   # Deep navy  — headers
C_PRIMARY = colors.HexColor("#16213E")   # Dark blue  — section bars
C_ACCENT  = colors.HexColor("#0F3460")   # Mid blue   — sub-headers
C_RED     = colors.HexColor("#E94560")   # Alert red  — critique
C_ORANGE  = colors.HexColor("#F5A623")   # Orange     — élevé
C_YELLOW  = colors.HexColor("#F7DC6F")   # Yellow     — moyen
C_GREEN   = colors.HexColor("#27AE60")   # Green      — info/ok
C_LIGHT   = colors.HexColor("#ECF0F1")   # Light grey — table rows
C_WHITE   = colors.white
C_BLACK   = colors.HexColor("#2C3E50")

RISK_COLOURS = {
    "Critique": C_RED,
    "Critical":  C_RED,
    "Élevé":    C_ORANGE,
    "High":      C_ORANGE,
    "Moyen":    C_YELLOW,
    "Medium":    C_YELLOW,
    "Faible":   C_GREEN,
    "Low":       C_GREEN,
    "Info":      colors.HexColor("#85C1E9"),
}

RISK_ORDER = ["Critique", "Élevé", "Moyen", "Faible", "Info",
              "Critical", "High", "Medium", "Low"]


# ── Main generator class ───────────────────────────────────────────────────────

class PDFReportGenerator:
    """
    Generates Technical or Governance PDF reports from framework results.

    Args:
        output_dir (str): Directory where PDFs will be saved (default: reports/).
    """

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or REPORTS_DIR
        os.makedirs(self.output_dir, exist_ok=True)
        self.styles = self._build_styles()

    def generate(
        self,
        results: list | dict,
        label: str = "report",
        report_type: str = "technical",
        baseline: Optional[list] = None,
    ) -> str:
        """
        Generate a PDF report.

        Args:
            results     : Current audit/attack results (list of result dicts).
            label       : Base filename label.
            report_type : 'technical' or 'governance'.
            baseline    : Optional previous results for before/after comparison.

        Returns:
            str: Absolute path to the generated PDF.
        """
        if not isinstance(results, list):
            results = [results]
        results = [r for r in results if isinstance(r, dict)]

        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{label}_{report_type}_{ts}.pdf"
        path     = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2.5*cm, bottomMargin=2*cm,
            title=f"AD Security Report — {report_type.capitalize()}",
            author="AD Attack & Defense Framework",
        )

        if report_type == "governance":
            story = self._build_governance(results, baseline)
        else:
            story = self._build_technical(results, baseline)

        doc.build(
            story,
            onFirstPage=self._header_footer,
            onLaterPages=self._header_footer,
        )

        logger.info(f"PDF report generated: {path}")
        return path

    # ── Technical report ───────────────────────────────────────────────────────

    def _build_technical(self, results: list, baseline: list = None) -> list:
        """Build the full technical report story."""
        s      = self.styles
        story  = []
        all_f  = self._all_findings(results)
        counts = self._count_by_risk(all_f)

        # ── Cover page ────────────────────────────────────────────────────────
        story += self._cover(
            title="Active Directory Security Assessment",
            subtitle="Technical Report — SOC / Pentest",
            badge_colour=C_PRIMARY,
        )
        story.append(PageBreak())

        # ── Executive summary ─────────────────────────────────────────────────
        story.append(Paragraph("1. Executive Summary", s["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=C_ACCENT, spaceAfter=8))
        story += self._tech_summary_table(counts, results)
        story.append(Spacer(1, 0.4*cm))

        # ── Risk distribution chart ───────────────────────────────────────────
        story.append(Paragraph("Risk Distribution", s["SubHeader"]))
        story.append(Spacer(1, 0.2*cm))
        story.append(self._pie_chart(counts))
        story.append(Spacer(1, 0.4*cm))

        # ── Findings by module bar chart ──────────────────────────────────────
        mod_counts = self._findings_by_module(results)
        if mod_counts:
            story.append(Paragraph("Findings per Module", s["SubHeader"]))
            story.append(Spacer(1, 0.2*cm))
            story.append(self._bar_chart(mod_counts))
            story.append(Spacer(1, 0.4*cm))

        # ── Before / After comparison ─────────────────────────────────────────
        if baseline:
            story.append(PageBreak())
            story.append(Paragraph("2. Before / After Comparison", s["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1,
                                    color=C_ACCENT, spaceAfter=8))
            story += self._comparison_section(baseline, results)

        # ── Detailed findings ─────────────────────────────────────────────────
        section_num = 3 if baseline else 2
        story.append(PageBreak())
        story.append(Paragraph(f"{section_num}. Detailed Findings", s["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=C_ACCENT, spaceAfter=8))

        for priority in ["Critique", "Élevé", "Moyen", "Faible", "Info"]:
            pf = [f for f in all_f if f.get("risk") == priority]
            if not pf:
                continue
            story.append(Paragraph(
                f"{'⬛' if priority in ('Critique','Élevé') else '◾'} {priority} ({len(pf)})",
                s["RiskHeader"]
            ))
            story.append(Spacer(1, 0.15*cm))
            for finding in pf:
                story += self._tech_finding_block(finding)
            story.append(Spacer(1, 0.3*cm))

        # ── MITRE ATT&CK mapping ──────────────────────────────────────────────
        story.append(PageBreak())
        section_num += 1
        story.append(Paragraph(f"{section_num}. MITRE ATT&CK Mapping", s["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=C_ACCENT, spaceAfter=8))
        story += self._mitre_table(results)

        return story

    # ── Governance report ──────────────────────────────────────────────────────

    def _build_governance(self, results: list, baseline: list = None) -> list:
        """Build the governance/executive report story — no technical jargon."""
        s      = self.styles
        story  = []
        all_f  = self._all_findings(results)
        counts = self._count_by_risk(all_f)
        total  = sum(counts.values())
        crit   = counts.get("Critique", 0) + counts.get("Critical", 0)
        high   = counts.get("Élevé", 0) + counts.get("High", 0)

        # ── Cover ─────────────────────────────────────────────────────────────
        story += self._cover(
            title="Active Directory Security Assessment",
            subtitle="Governance Report — Executive Summary",
            badge_colour=C_DARK,
        )
        story.append(PageBreak())

        # ── Overall security posture ──────────────────────────────────────────
        story.append(Paragraph("1. Overall Security Posture", s["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=C_ACCENT, spaceAfter=8))
        posture, posture_colour = self._posture(crit, high, total)
        story.append(self._posture_badge(posture, posture_colour))
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph(
            self._governance_posture_text(crit, high, total, posture),
            s["BodyJustify"]
        ))
        story.append(Spacer(1, 0.5*cm))
        story.append(self._pie_chart(counts))
        story.append(Spacer(1, 0.5*cm))

        # ── Business risk summary ─────────────────────────────────────────────
        story.append(PageBreak())
        story.append(Paragraph("2. Business Risk Summary", s["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=C_ACCENT, spaceAfter=8))
        story.append(Paragraph(
            "The following table summarises the key security risks identified, "
            "their potential business impact, and the recommended priority for remediation.",
            s["BodyJustify"]
        ))
        story.append(Spacer(1, 0.3*cm))
        story += self._governance_risk_table(all_f)
        story.append(Spacer(1, 0.5*cm))

        # ── Before / After (governance view) ─────────────────────────────────
        if baseline:
            story.append(PageBreak())
            story.append(Paragraph("3. Security Improvement Tracking", s["SectionHeader"]))
            story.append(HRFlowable(width="100%", thickness=1,
                                    color=C_ACCENT, spaceAfter=8))
            story.append(Paragraph(
                "This section compares the current security posture against "
                "the previous assessment, showing measurable improvements.",
                s["BodyJustify"]
            ))
            story.append(Spacer(1, 0.3*cm))
            story += self._governance_comparison(baseline, results)

        # ── Remediation roadmap ───────────────────────────────────────────────
        section_num = 4 if baseline else 3
        story.append(PageBreak())
        story.append(Paragraph(f"{section_num}. Remediation Roadmap", s["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=C_ACCENT, spaceAfter=8))
        story.append(Paragraph(
            "Recommended remediation actions ranked by business priority. "
            "Items marked IMMEDIATE should be addressed within 48 hours.",
            s["BodyJustify"]
        ))
        story.append(Spacer(1, 0.3*cm))
        story += self._remediation_roadmap(all_f)

        # ── Compliance note ───────────────────────────────────────────────────
        section_num += 1
        story.append(PageBreak())
        story.append(Paragraph(f"{section_num}. Compliance Considerations", s["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=C_ACCENT, spaceAfter=8))
        story += self._compliance_section(crit, high)

        return story

    # ── Shared building blocks ─────────────────────────────────────────────────

    def _cover(self, title: str, subtitle: str, badge_colour) -> list:
        """Generate cover page elements."""
        s     = self.styles
        story = []
        story.append(Spacer(1, 3*cm))

        # Title block
        story.append(self._colour_bar(badge_colour, height=0.8*cm))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(title, s["CoverTitle"]))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(subtitle, s["CoverSubtitle"]))
        story.append(self._colour_bar(badge_colour, height=0.3*cm))
        story.append(Spacer(1, 2*cm))

        # Metadata table
        now  = datetime.now()
        meta = [
            ["Report Date",   now.strftime("%B %d, %Y")],
            ["Generated",     now.strftime("%H:%M UTC")],
            ["Framework",     "AD Attack & Defense Simulation v1.1"],
            ["Authors",       "NISSEKONG Georges Owen | DIOP Salla"],
            ["Lab",           "GOAD — Game of Active Directory"],
            ["Classification","CONFIDENTIAL — Internal Use Only"],
        ]
        t = Table(meta, colWidths=[5*cm, 11*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), C_PRIMARY),
            ("TEXTCOLOR",  (0, 0), (0, -1), C_WHITE),
            ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("BACKGROUND", (1, 0), (1, -1), C_LIGHT),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.white),
            ("ROWBACKGROUNDS", (1, 0), (1, -1), [C_LIGHT, C_WHITE]),
            ("TOPPADDING",  (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(t)
        return story

    def _tech_summary_table(self, counts: dict, results: list) -> list:
        """Summary KPI table for technical report."""
        s       = self.styles
        total   = sum(counts.values())
        crit    = counts.get("Critique", 0) + counts.get("Critical", 0)
        high    = counts.get("Élevé", 0) + counts.get("High", 0)
        modules = len([r for r in results if r.get("status") != "error"])
        errors  = len([r for r in results if r.get("status") == "error"])

        kpis = [
            ["Metric",            "Value",  "Status"],
            ["Modules executed",  str(modules), "—"],
            ["Module errors",     str(errors),  "REVIEW" if errors else "OK"],
            ["Total findings",    str(total),   "—"],
            ["Critical findings", str(crit),    "CRITICAL" if crit else "OK"],
            ["High findings",     str(high),    "HIGH" if high else "OK"],
        ]
        t = Table(kpis, colWidths=[7*cm, 4*cm, 5*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        # Colour the status column
        status_colours = {
            "CRITICAL": (C_RED,    C_WHITE),
            "HIGH":     (C_ORANGE, C_BLACK),
            "REVIEW":   (C_YELLOW, C_BLACK),
            "OK":       (C_GREEN,  C_WHITE),
        }
        for i, row in enumerate(kpis[1:], 1):
            status = row[2]
            if status in status_colours:
                bg, fg = status_colours[status]
                t.setStyle(TableStyle([
                    ("BACKGROUND", (2, i), (2, i), bg),
                    ("TEXTCOLOR",  (2, i), (2, i), fg),
                    ("FONTNAME",   (2, i), (2, i), "Helvetica-Bold"),
                ]))
        return [t]

    def _tech_finding_block(self, finding: dict) -> list:
        """Render a single finding as a detailed technical block."""
        s     = self.styles
        story = []
        risk  = finding.get("risk", "Info")
        colour = RISK_COLOURS.get(risk, colors.grey)

        # Finding header bar
        header_data = [[
            Paragraph(f"[{risk}]", s["FindingRisk"]),
            Paragraph(finding.get("title", "—"), s["FindingTitle"]),
        ]]
        ht = Table(header_data, colWidths=[2.5*cm, 13.5*cm])
        ht.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colour),
            ("TEXTCOLOR",     (0, 0), (-1, -1), C_WHITE if risk in
             ("Critique", "Élevé", "Critical", "High") else C_BLACK),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(KeepTogether([ht]))

        # Detail rows
        details = []
        if finding.get("description"):
            details.append(["Description", finding["description"]])
        if finding.get("mitigation"):
            details.append(["Mitigation",  finding["mitigation"]])
        if finding.get("event_ids"):
            eids = ", ".join(str(e) for e in finding["event_ids"])
            details.append(["Event IDs",   eids])
        if finding.get("mitre"):
            details.append(["MITRE",       finding["mitre"]])

        if details:
            dt = Table(
                [[Paragraph(k, s["DetailKey"]),
                  Paragraph(str(v), s["DetailVal"])]
                 for k, v in details],
                colWidths=[3*cm, 13*cm],
            )
            dt.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (0, -1), colors.HexColor("#F8F9FA")),
                ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("GRID",          (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(dt)

        story.append(Spacer(1, 0.25*cm))
        return story

    def _governance_risk_table(self, findings: list) -> list:
        """Business risk table — no Event IDs, plain language."""
        s    = self.styles
        rows = [["Risk Level", "Issue", "Business Impact", "Priority"]]

        # Business impact translations (no technical jargon)
        impact_map = {
            "Critique": "Complete domain compromise possible. All systems and data at risk.",
            "Élevé":    "Significant risk of data breach or service disruption.",
            "Moyen":    "Moderate risk — could facilitate more serious attacks.",
            "Faible":   "Limited risk — best practice deviation.",
            "Info":     "Informational — no immediate risk.",
        }
        priority_map = {
            "Critique": "IMMEDIATE (< 48h)",
            "Élevé":    "URGENT (< 1 week)",
            "Moyen":    "SCHEDULED (< 1 month)",
            "Faible":   "PLANNED (quarterly)",
            "Info":     "MONITORING",
        }

        for finding in findings:
            risk = finding.get("risk", "Info")
            # Clean up title for non-technical audience
            title = finding.get("title", "—")
            # Remove technical prefixes like "Event ID 4625"
            for tech_term in ["Event ID", "UAC flag", "SPN", "TGS", "NTLM",
                              "LDAP", "GPO", "4625", "4769", "7045"]:
                title = title.replace(tech_term, "").strip()

            rows.append([
                risk,
                title[:60],
                impact_map.get(risk, "Risk identified."),
                priority_map.get(risk, "REVIEW"),
            ])

        if len(rows) == 1:
            rows.append(["Info", "No findings", "No risk identified", "—"])

        t = Table(rows, colWidths=[2.5*cm, 5.5*cm, 6*cm, 3*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP",      (0, 0), (-1, -1), True),
        ]))
        # Colour risk column
        for i, row in enumerate(rows[1:], 1):
            risk   = row[0]
            colour = RISK_COLOURS.get(risk, colors.grey)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, i), (0, i), colour),
                ("TEXTCOLOR",  (0, i), (0, i),
                 C_WHITE if risk in ("Critique","Élevé","Critical","High")
                 else C_BLACK),
                ("FONTNAME",   (0, i), (0, i), "Helvetica-Bold"),
                ("ALIGN",      (0, i), (0, i), "CENTER"),
            ]))

        return [t]

    def _governance_posture_text(self, crit, high, total, posture) -> str:
        """Plain-English security posture description for executives."""
        if posture == "CRITICAL":
            return (
                f"The Active Directory environment presents <b>critical security vulnerabilities</b> "
                f"that require immediate attention. {crit} critical and {high} high-severity issues "
                f"were identified, which could allow an attacker to gain complete control of the "
                f"organisation's IT infrastructure. Immediate action by the IT security team is required."
            )
        elif posture == "HIGH RISK":
            return (
                f"The Active Directory environment presents <b>significant security risks</b>. "
                f"{high} high-severity issues were identified that could lead to a data breach or "
                f"service disruption. The IT security team should prioritise remediation within one week."
            )
        elif posture == "MODERATE":
            return (
                f"The Active Directory environment presents <b>moderate security risks</b>. "
                f"{total} issues were identified, none immediately critical. "
                f"Remediation should be planned and executed within the next monthly security cycle."
            )
        else:
            return (
                f"The Active Directory environment presents a <b>satisfactory security posture</b>. "
                f"{total} minor observations were identified. Continue monitoring and apply "
                f"the listed best practices."
            )

    def _posture(self, crit, high, total):
        if crit > 0:
            return "CRITICAL",  C_RED
        elif high > 2:
            return "HIGH RISK", C_ORANGE
        elif total > 10:
            return "MODERATE",  C_YELLOW
        else:
            return "SATISFACTORY", C_GREEN

    def _posture_badge(self, posture: str, colour) -> Table:
        """Large coloured badge showing overall security posture."""
        data = [[Paragraph(
            f"<b>OVERALL SECURITY POSTURE: {posture}</b>",
            ParagraphStyle("Badge",
                           fontName="Helvetica-Bold", fontSize=14,
                           textColor=C_WHITE, alignment=TA_CENTER)
        )]]
        t = Table(data, colWidths=[17*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colour),
            ("TOPPADDING",    (0, 0), (-1, -1), 14),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
            ("ROUNDEDCORNERS",(0, 0), (-1, -1), [6, 6, 6, 6]),
        ]))
        return t

    def _comparison_section(self, baseline: list, current: list) -> list:
        """Technical before/after comparison."""
        s       = self.styles
        story   = []
        b_count = self._count_by_risk(self._all_findings(baseline))
        c_count = self._count_by_risk(self._all_findings(current))

        story.append(Paragraph(
            "Comparison between the baseline audit and the current assessment.",
            s["BodyJustify"]
        ))
        story.append(Spacer(1, 0.3*cm))

        rows = [["Risk Level", "Before", "After", "Delta", "Trend"]]
        for risk in ["Critique", "Élevé", "Moyen", "Faible", "Info"]:
            before = b_count.get(risk, 0)
            after  = c_count.get(risk, 0)
            delta  = after - before
            trend  = ("▼ IMPROVED" if delta < 0 else
                      "▲ WORSENED" if delta > 0 else "= NO CHANGE")
            rows.append([risk, str(before), str(after),
                         f"{delta:+d}", trend])

        t = Table(rows, colWidths=[3.5*cm, 3*cm, 3*cm, 2.5*cm, 5*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        for i, row in enumerate(rows[1:], 1):
            delta = int(row[3])
            trend = row[4]
            if delta < 0:
                t.setStyle(TableStyle([
                    ("TEXTCOLOR", (4, i), (4, i), C_GREEN),
                    ("FONTNAME",  (4, i), (4, i), "Helvetica-Bold"),
                ]))
            elif delta > 0:
                t.setStyle(TableStyle([
                    ("TEXTCOLOR", (4, i), (4, i), C_RED),
                    ("FONTNAME",  (4, i), (4, i), "Helvetica-Bold"),
                ]))

        story.append(t)
        story.append(Spacer(1, 0.4*cm))
        story.append(self._comparison_bar_chart(b_count, c_count))
        return story

    def _governance_comparison(self, baseline: list, current: list) -> list:
        """Plain-language before/after for governance report."""
        s       = self.styles
        story   = []
        b_all   = self._all_findings(baseline)
        c_all   = self._all_findings(current)
        b_count = self._count_by_risk(b_all)
        c_count = self._count_by_risk(c_all)
        b_crit  = b_count.get("Critique", 0) + b_count.get("Critical", 0)
        c_crit  = c_count.get("Critique", 0) + c_count.get("Critical", 0)
        b_total = sum(b_count.values())
        c_total = sum(c_count.values())
        improved = b_total - c_total

        summary = (
            f"Since the previous assessment, the security team has resolved "
            f"<b>{max(improved, 0)} issue(s)</b>. "
            f"Critical issues moved from <b>{b_crit}</b> to <b>{c_crit}</b>. "
        )
        if c_crit < b_crit:
            summary += "This represents a <b>measurable improvement</b> in security posture."
        elif c_crit == b_crit:
            summary += "Critical risks remain at the same level — further action is required."
        else:
            summary += "<b>Critical risks have increased</b> — urgent remediation is needed."

        story.append(Paragraph(summary, s["BodyJustify"]))
        story.append(Spacer(1, 0.4*cm))

        rows = [
            ["",             "Previous Assessment", "Current Assessment", "Change"],
            ["Total Issues",  str(b_total), str(c_total),
             f"{'↓' if c_total < b_total else '↑'} {abs(c_total - b_total)}"],
            ["Critical/High", str(b_crit + b_count.get("Élevé",0)),
             str(c_crit + c_count.get("Élevé",0)),
             "Improved" if c_crit <= b_crit else "Worsened"],
        ]
        t = Table(rows, colWidths=[4*cm, 5*cm, 5*cm, 3*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3*cm))
        story.append(self._comparison_bar_chart(b_count, c_count))
        return story

    def _remediation_roadmap(self, findings: list) -> list:
        """Prioritised remediation roadmap in plain language."""
        priority_map = {
            "Critique": ("1 — IMMEDIATE",    "< 48 hours",   C_RED),
            "Élevé":    ("2 — URGENT",       "< 1 week",     C_ORANGE),
            "Moyen":    ("3 — SCHEDULED",    "< 1 month",    C_YELLOW),
            "Faible":   ("4 — PLANNED",      "Quarterly",    C_GREEN),
            "Info":     ("5 — MONITORING",   "Ongoing",      colors.grey),
        }
        rows = [["Priority", "Timeframe", "Action Required"]]
        seen = set()

        for risk_level in ["Critique", "Élevé", "Moyen", "Faible", "Info"]:
            pf = [f for f in findings if f.get("risk") == risk_level]
            if not pf:
                continue
            pri, timeframe, _ = priority_map[risk_level]
            # Group findings of same risk into one row
            actions = []
            for f in pf[:5]:  # Max 5 per risk level
                m = f.get("mitigation", "")
                # Take first sentence only — keep it readable
                first_sentence = m.split(".")[0] + "." if m else "Investigate and remediate."
                if first_sentence not in seen:
                    actions.append(first_sentence)
                    seen.add(first_sentence)

            if actions:
                rows.append([pri, timeframe, "\n".join(actions[:3])])

        t = Table(rows, colWidths=[4*cm, 3*cm, 10*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        return [t]

    def _compliance_section(self, crit: int, high: int) -> list:
        """Compliance implications in plain language."""
        s     = self.styles
        story = []
        story.append(Paragraph(
            "The identified vulnerabilities may have implications for the following "
            "regulatory frameworks and compliance standards:",
            s["BodyJustify"]
        ))
        story.append(Spacer(1, 0.3*cm))

        frameworks = [
            ["Framework",        "Relevant Finding",                  "Status"],
            ["ISO 27001 A.9",    "Access control & privileged accounts",
             "NON-COMPLIANT" if crit + high > 0 else "COMPLIANT"],
            ["ISO 27001 A.12",   "Operations security & logging",
             "REVIEW REQUIRED" if high > 0 else "COMPLIANT"],
            ["GDPR Art. 32",     "Security of processing — data breach risk",
             "NON-COMPLIANT" if crit > 0 else "REVIEW REQUIRED"],
            ["NIS2 Art. 21",     "Cybersecurity risk management measures",
             "NON-COMPLIANT" if crit > 0 else "REVIEW REQUIRED"],
            ["CIS Controls v8",  "Identity & access management",
             "PARTIAL" if high > 0 else "COMPLIANT"],
        ]
        t = Table(frameworks, colWidths=[4*cm, 8*cm, 5*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        for i, row in enumerate(frameworks[1:], 1):
            status = row[2]
            colour = (C_RED    if "NON-COMPLIANT" in status else
                      C_ORANGE if "REVIEW"        in status else
                      C_YELLOW if "PARTIAL"       in status else C_GREEN)
            t.setStyle(TableStyle([
                ("BACKGROUND", (2, i), (2, i), colour),
                ("TEXTCOLOR",  (2, i), (2, i),
                 C_WHITE if "NON-COMPLIANT" in status else C_BLACK),
                ("FONTNAME",   (2, i), (2, i), "Helvetica-Bold"),
                ("ALIGN",      (2, i), (2, i), "CENTER"),
            ]))
        story.append(t)
        return story

    def _mitre_table(self, results: list) -> list:
        """MITRE ATT&CK technique mapping for technical report."""
        rows = [["Module", "Technique", "Tactic", "Detection"]]
        mitre_map = {
            "red_team.password_spray":    ("T1110.003", "Credential Access / Initial Access", "Event 4625 volume spike"),
            "red_team.kerberoasting":     ("T1558.003", "Credential Access",                  "Event 4769 volume spike"),
            "red_team.llmnr_poisoning":   ("T1557.001", "Credential Access / MITM",           "Network — LLMNR traffic"),
            "red_team.pth":               ("T1550.002", "Lateral Movement",                   "Event 4624 type 3 pattern"),
            "red_team.lateral_mouvement": ("T1021.002 / T1047", "Lateral Movement",           "Event 7045 / 4688"),
        }
        for res in results:
            module  = res.get("module", "")
            mapping = mitre_map.get(module)
            if mapping:
                rows.append([module.replace("red_team.", ""),
                             mapping[0], mapping[1], mapping[2]])

        if len(rows) == 1:
            rows.append(["No red team results", "—", "—", "—"])

        t = Table(rows, colWidths=[4*cm, 3.5*cm, 5*cm, 4.5*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
            ("GRID",          (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ]))
        return [t]

    # ── Charts ─────────────────────────────────────────────────────────────────

    def _pie_chart(self, counts: dict) -> Drawing:
        """Pie chart showing risk distribution."""
        labels  = []
        data    = []
        colours = []

        for risk in ["Critique", "Élevé", "Moyen", "Faible", "Info"]:
            val = counts.get(risk, 0)
            if val > 0:
                labels.append(f"{risk} ({val})")
                data.append(val)
                colours.append(RISK_COLOURS.get(risk, colors.grey))

        if not data:
            data    = [1]
            labels  = ["No findings"]
            colours = [C_GREEN]

        d   = Drawing(400, 180)
        pie = Pie()
        pie.x      = 30
        pie.y      = 10
        pie.width  = 130
        pie.height = 130
        pie.data   = data
        pie.labels = [f"{v}" for v in data]
        pie.slices.strokeWidth = 0.5
        pie.slices.strokeColor = C_WHITE
        for i, c in enumerate(colours):
            pie.slices[i].fillColor = c
        d.add(pie)

        # Legend
        y = 130
        for i, (label, colour) in enumerate(zip(labels, colours)):
            r = Rect(180, y, 14, 10, fillColor=colour,
                     strokeColor=C_WHITE, strokeWidth=0.5)
            t = String(200, y + 1, label,
                       fontName="Helvetica", fontSize=8,
                       fillColor=C_BLACK)
            d.add(r)
            d.add(t)
            y -= 18

        return d

    def _bar_chart(self, mod_counts: dict) -> Drawing:
        """Horizontal findings count per module."""
        modules = list(mod_counts.keys())[:8]  # Max 8
        values  = [mod_counts[m] for m in modules]
        short   = [m.replace("blue_team.", "BT.").replace("red_team.", "RT.")
                     .replace("purple_team.", "PT.").replace("response.", "R.")
                   for m in modules]

        d   = Drawing(430, max(120, len(modules) * 22 + 40))
        bc  = VerticalBarChart()
        bc.x           = 60
        bc.y           = 20
        bc.width       = 340
        bc.height      = max(100, len(modules) * 18)
        bc.data        = [values]
        bc.categoryAxis.categoryNames = short
        bc.bars[0].fillColor         = C_ACCENT
        bc.valueAxis.valueMin        = 0
        bc.categoryAxis.labels.angle = 30
        bc.categoryAxis.labels.fontSize = 7
        bc.categoryAxis.labels.dy    = -10
        bc.valueAxis.labels.fontSize = 8
        d.add(bc)
        return d

    def _comparison_bar_chart(self, before: dict, after: dict) -> Drawing:
        """Grouped bar chart — before vs after per risk level."""
        risks   = ["Critique", "Élevé", "Moyen", "Faible", "Info"]
        b_vals  = [before.get(r, 0) for r in risks]
        a_vals  = [after.get(r, 0)  for r in risks]

        d  = Drawing(430, 180)
        bc = VerticalBarChart()
        bc.x      = 50
        bc.y      = 30
        bc.width  = 340
        bc.height = 120
        bc.data   = [b_vals, a_vals]
        bc.categoryAxis.categoryNames = risks
        bc.bars[0].fillColor = colors.HexColor("#5D8AA8")  # Before — blue
        bc.bars[1].fillColor = C_GREEN                      # After  — green
        bc.valueAxis.valueMin       = 0
        bc.categoryAxis.labels.fontSize = 8
        bc.valueAxis.labels.fontSize    = 8

        # Legend
        d.add(Rect(50,  10, 12, 10, fillColor=colors.HexColor("#5D8AA8"),
                   strokeWidth=0))
        d.add(String(66, 11, "Before", fontName="Helvetica",
                     fontSize=8, fillColor=C_BLACK))
        d.add(Rect(120, 10, 12, 10, fillColor=C_GREEN, strokeWidth=0))
        d.add(String(136, 11, "After", fontName="Helvetica",
                     fontSize=8, fillColor=C_BLACK))
        d.add(bc)
        return d

    # ── Page template ──────────────────────────────────────────────────────────

    def _header_footer(self, canvas, doc):
        """Draw header and footer on every page."""
        canvas.saveState()
        w, h = A4

        # Header bar
        canvas.setFillColor(C_DARK)
        canvas.rect(0, h - 1.5*cm, w, 1.5*cm, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(2*cm, h - 1*cm,
                          "AD Attack & Defense Simulation Framework — CONFIDENTIAL")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 2*cm, h - 1*cm,
                               datetime.now().strftime("%Y-%m-%d"))

        # Footer line
        canvas.setStrokeColor(C_ACCENT)
        canvas.setLineWidth(0.5)
        canvas.line(2*cm, 1.5*cm, w - 2*cm, 1.5*cm)
        canvas.setFillColor(colors.grey)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(2*cm, 0.8*cm,
                          "NISSEKONG Georges Owen | DIOP Salla | 2025-2026")
        canvas.drawRightString(w - 2*cm, 0.8*cm,
                               f"Page {doc.page}")
        canvas.restoreState()

    # ── Style helpers ──────────────────────────────────────────────────────────

    def _colour_bar(self, colour, height: float = 0.4*cm) -> Table:
        t = Table([[""]], colWidths=[17*cm], rowHeights=[height])
        t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), colour)]))
        return t

    def _build_styles(self) -> dict:
        base = getSampleStyleSheet()
        def ps(name, **kw):
            return ParagraphStyle(name, **kw)

        return {
            "CoverTitle": ps("CoverTitle",
                fontName="Helvetica-Bold", fontSize=24,
                textColor=C_DARK, alignment=TA_LEFT, spaceAfter=6),
            "CoverSubtitle": ps("CoverSub",
                fontName="Helvetica", fontSize=14,
                textColor=C_ACCENT, alignment=TA_LEFT, spaceAfter=4),
            "SectionHeader": ps("SectionHeader",
                fontName="Helvetica-Bold", fontSize=13,
                textColor=C_PRIMARY, spaceBefore=12, spaceAfter=4),
            "SubHeader": ps("SubHeader",
                fontName="Helvetica-Bold", fontSize=10,
                textColor=C_ACCENT, spaceBefore=8, spaceAfter=2),
            "RiskHeader": ps("RiskHeader",
                fontName="Helvetica-Bold", fontSize=10,
                textColor=C_BLACK, spaceBefore=10, spaceAfter=2),
            "BodyJustify": ps("BodyJustify",
                fontName="Helvetica", fontSize=9,
                textColor=C_BLACK, alignment=TA_JUSTIFY,
                leading=14, spaceAfter=4),
            "FindingRisk": ps("FindingRisk",
                fontName="Helvetica-Bold", fontSize=8,
                textColor=C_WHITE, alignment=TA_CENTER),
            "FindingTitle": ps("FindingTitle",
                fontName="Helvetica-Bold", fontSize=9,
                textColor=C_WHITE),
            "DetailKey": ps("DetailKey",
                fontName="Helvetica-Bold", fontSize=8,
                textColor=C_BLACK),
            "DetailVal": ps("DetailVal",
                fontName="Helvetica", fontSize=8,
                textColor=C_BLACK, leading=11),
        }

    # ── Data helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _all_findings(results: list) -> list:
        findings = []
        for r in results:
            if isinstance(r, dict):
                findings.extend(r.get("findings", []) or [])
        return [f for f in findings if isinstance(f, dict)]

    @staticmethod
    def _count_by_risk(findings: list) -> dict:
        counts = {}
        for f in findings:
            risk = f.get("risk", "Info")
            counts[risk] = counts.get(risk, 0) + 1
        return counts

    @staticmethod
    def _findings_by_module(results: list) -> dict:
        counts = {}
        for r in results:
            if not isinstance(r, dict):
                continue
            module = r.get("module", "unknown")
            n      = len(r.get("findings", []) or [])
            if n > 0:
                counts[module] = n
        return counts
