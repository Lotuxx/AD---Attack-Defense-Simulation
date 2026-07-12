"""
Report Generator
================
Produces PDF reports from module execution results.

Every audit or attack module returns a standardised result dict containing
a 'findings' list (and, for Red Team modules, an 'attack_meta' dict).
This generator turns those results into TWO separate PDF deliverables per
run, as required by the cahier des charges:

    - Rapport TECHNIQUE    : full detail for a security-literate reader
                              (Blue Team: vulnérabilité / niveau de risque /
                              risques exploitables / mitigation technique
                              et humaine ; Red Team: attaques réalisées /
                              journaux et alertes SIEM / impact sur AD /
                              recommandations / explications techniques).
    - Rapport GOUVERNANCE  : executive summary for a non-technical reader
                              (risk posture, detection coverage, priorities —
                              no Event IDs, no hashes, no exploit commands).

PDF was chosen as the only supported output format on purpose: TXT/CSV
reports were dropped, since in a real engagement the only deliverable that
matters is a polished PDF a client or jury can actually read.

Report naming convention:
    reports/<label>_technique_<YYYYMMDD_HHMMSS>.pdf
    reports/<label>_gouvernance_<YYYYMMDD_HHMMSS>.pdf
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

# Risk level -> background color (mirrors risk_badge() in utils/format_utils.py,
# which uses the same French risk vocabulary).
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

_AUTHORS = "NISSEKONG Georges Owen | DIOP Salla"


class ReportGenerator:
    """
    Generates the two PDF reports (technique + gouvernance) from module results.

    Args:
        output_format (str): Kept for backward-compatible call sites; the
                              only supported value is 'pdf'.

    Usage:
        gen = ReportGenerator()
        gen.generate(results, label="blue_team_audit")   # writes both PDFs
        gen.generate(results, label="...", report_types=["technique"])
    """

    def __init__(self, output_format: str = "pdf", secrets: list = None):
        self.output_format = "pdf"
        # Known sensitive values (e.g. configured passwords) to redact from
        # report text as a defense-in-depth layer, on top of modules already
        # masking cleartext credentials in their own findings.
        self._secrets = [s for s in (secrets or []) if s]

    def generate(self, results: Union[dict, list], label: str,
                 output_format: str = None, report_types: list = None) -> list:
        """
        Generate the PDF report(s) for the given module results.

        Args:
            results       : Single result dict or list of result dicts.
            label         : Base filename label (e.g. 'blue_team_full').
            output_format : Ignored except for backward compatibility; PDF is
                            the only supported format.
            report_types  : Which reports to produce. Default: both
                            ['technique', 'gouvernance'], per cahier des
                            charges. Pass a subset to restrict.

        Returns:
            list[str]: Paths of the PDF file(s) generated.
        """
        if not isinstance(results, list):
            results = [results]
        report_types = report_types or ["technique", "gouvernance"]

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        paths = []

        if "technique" in report_types:
            path = os.path.join(REPORTS_DIR, f"{label}_technique_{ts}.pdf")
            self._write_technical_pdf(results, path)
            paths.append(path)

        if "gouvernance" in report_types:
            path = os.path.join(REPORTS_DIR, f"{label}_gouvernance_{ts}.pdf")
            self._write_governance_pdf(results, path)
            paths.append(path)

        return paths

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

    # ── Shared styles ─────────────────────────────────────────────────────────

    def _styles(self):
        """Build the paragraph styles used throughout both PDFs."""
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
            name="SubHeading", parent=styles["Heading3"],
            textColor=colors.HexColor("#334155"), spaceBefore=8, spaceAfter=4,
        ))
        styles.add(ParagraphStyle(
            name="CellText", parent=styles["Normal"], fontSize=8, leading=10,
        ))
        styles.add(ParagraphStyle(
            name="CellTextBold", parent=styles["CellText"], fontName="Helvetica-Bold",
        ))
        styles.add(ParagraphStyle(
            name="CellTextWhite", parent=styles["CellTextBold"], textColor=colors.white,
        ))
        styles.add(ParagraphStyle(
            name="ExecBody", parent=styles["Normal"], fontSize=10.5, leading=15,
        ))
        return styles

    def _title_page(self, subtitle: str, styles) -> list:
        """Build the cover section shared by both report types."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return [
            Spacer(1, 4 * cm),
            Paragraph("AD Attack &amp; Defense Simulation", styles["ReportTitle"]),
            Paragraph(subtitle, styles["ReportSubtitle"]),
            Spacer(1, 0.5 * cm),
            Paragraph(f"Généré le {now}", styles["ReportSubtitle"]),
            Paragraph(_AUTHORS, styles["ReportSubtitle"]),
            PageBreak(),
        ]

    def _meta_table(self, res: dict, styles) -> Table:
        """Small module metadata table (status / duration / date) shared by both reports."""
        meta_rows = [
            ["Status",   self._redact(res.get("status", "N/A"))],
            ["Duration", f"{res.get('elapsed_s', 0)}s"],
            ["Date",     self._redact(res.get("timestamp", "N/A"))],
        ]
        if res.get("message"):
            meta_rows.append(["Message", self._redact(res["message"])])
        table = Table(
            [[Paragraph(k, styles["CellTextBold"]), Paragraph(v, styles["CellText"])] for k, v in meta_rows],
            colWidths=[3 * cm, 13 * cm],
        )
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
        ]))
        return table

    # ── Catalogue / detection-matrix lookups ────────────────────────────────────

    def _catalog_entry(self, attack_name: str) -> dict:
        """Look up the static attack catalogue (preconditions/exploit/impact) by name."""
        try:
            from core.database import DatabaseManager
            entry = DatabaseManager().get_attack(attack_name)
            return entry or {}
        except Exception:
            return {}

    def _expected_wazuh_rules(self, attack_name: str) -> dict:
        """Look up the expected Wazuh rules / Event IDs for an attack (Purple Team matrix)."""
        try:
            from modules.purple_team.validate_detection import DETECTION_MATRIX
            return DETECTION_MATRIX.get(attack_name, {})
        except Exception:
            return {}

    # ══════════════════════════════════════════════════════════════════════════
    # RAPPORT TECHNIQUE
    # ══════════════════════════════════════════════════════════════════════════

    def _write_technical_pdf(self, results: list, path: str):
        """Write the technical PDF: full detail per module (Blue + Red + Purple)."""
        try:
            doc = SimpleDocTemplate(
                path, pagesize=A4,
                topMargin=2 * cm, bottomMargin=2 * cm,
                leftMargin=2 * cm, rightMargin=2 * cm,
            )
            styles = self._styles()
            story = self._title_page("Rapport Technique", styles)

            for res in results:
                story += self._technical_module_section(res, styles)

            story += self._technical_summary(results, styles)

            doc.build(story)
            print_success(f"Rapport technique : {path}")
            logger.info(f"Technical PDF generated: {path}")
        except Exception as e:
            print_error(f"Erreur génération rapport technique : {e}")

    def _technical_module_section(self, res: dict, styles) -> list:
        """Dispatch a module result to the right technical section builder."""
        module = self._redact(res.get("module", "N/A"))
        story = [Paragraph(module, styles["ModuleHeading"]), self._meta_table(res, styles), Spacer(1, 0.3 * cm)]

        if res.get("attack_meta"):
            story += self._red_team_block(res, styles)
        elif "detection_rate_pct" in res.get("summary", {}) or res.get("module") == "purple_team.validate_detection":
            story += self._purple_team_block(res, styles)
        else:
            story += self._blue_team_block(res, styles)

        story.append(Spacer(1, 0.4 * cm))
        return story

    # ── Blue Team ───────────────────────────────────────────────────────────

    def _blue_team_block(self, res: dict, styles) -> list:
        """Blue Team audit section: one detailed card per finding."""
        findings = res.get("findings", [])
        if not findings:
            return [Paragraph("Aucun finding pour ce module.", styles["CellText"])]

        story = []
        for f in findings:
            story.append(self._finding_card(f, styles))
            story.append(Spacer(1, 0.25 * cm))
        return story

    def _finding_card(self, f: dict, styles) -> Table:
        """
        One finding rendered as a labeled card covering exactly the fields
        required by the cahier des charges for Blue Team reports:
        Vulnérabilité / Niveau de risque / Risques exploitables /
        Moyens de prévention techniques et humains.
        """
        risk  = f.get("risk", "Info")
        title = self._redact(f.get("title", "—"))
        desc  = self._redact(f.get("description", ""))
        risques   = self._redact(f.get("risques_exploitables", "")) or "—"
        mitig_t   = self._redact(f.get("mitigation", "")) or "—"
        mitig_h   = self._redact(f.get("mitigation_humaine", "")) or "—"
        event_ids = f.get("event_ids", [])

        rows = [
            [Paragraph(risk, styles["CellTextWhite"]), Paragraph(title, styles["CellTextWhite"])],
            [Paragraph("Vulnérabilité", styles["CellTextBold"]), Paragraph(desc, styles["CellText"])],
            [Paragraph("Risques exploitables", styles["CellTextBold"]), Paragraph(risques, styles["CellText"])],
            [Paragraph("Mitigation technique", styles["CellTextBold"]), Paragraph(mitig_t, styles["CellText"])],
            [Paragraph("Mitigation humaine", styles["CellTextBold"]), Paragraph(mitig_h, styles["CellText"])],
        ]
        if event_ids:
            rows.append([Paragraph("Event IDs", styles["CellTextBold"]),
                         Paragraph(", ".join(str(e) for e in event_ids), styles["CellText"])])

        table = Table(rows, colWidths=[4 * cm, 12 * cm])
        risk_color = _RISK_COLORS.get(risk, _DEFAULT_RISK_COLOR)
        table.setStyle(TableStyle([
            ("SPAN", (0, 0), (1, 0)),
            ("BACKGROUND", (0, 0), (-1, 0), risk_color),
            ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f1f5f9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    # ── Red Team ────────────────────────────────────────────────────────────

    def _red_team_block(self, res: dict, styles) -> list:
        """
        Red Team attack section covering exactly the fields required by the
        cahier des charges: attaque(s) réalisée(s), journaux générés et
        alertes SIEM, impact sur AD, recommandations, explications techniques.
        """
        meta    = res.get("attack_meta", {})
        name    = meta.get("name", res.get("module", "N/A"))
        catalog = self._catalog_entry(name)
        expected = self._expected_wazuh_rules(name)

        findings  = res.get("findings", [])
        iocs      = res.get("iocs", [])
        artifacts = res.get("artifacts", {})
        summary   = res.get("summary", {})

        # Attaque réalisée
        header_rows = [
            [Paragraph("<b>Attaque réalisée</b>", styles["CellTextWhite"]), Paragraph(name, styles["CellTextWhite"])],
            [Paragraph("Phase / MITRE", styles["CellTextBold"]),
             Paragraph(f"{meta.get('phase', '—')} / {meta.get('mitre', '—')}", styles["CellText"])],
            [Paragraph("Outils utilisés", styles["CellTextBold"]),
             Paragraph(", ".join(meta.get("tools", [])) or catalog.get("tools", "—"), styles["CellText"])],
            [Paragraph("Préconditions", styles["CellTextBold"]),
             Paragraph(catalog.get("preconditions", "—"), styles["CellText"])],
        ]
        header_table = Table(header_rows, colWidths=[4 * cm, 12 * cm])
        header_table.setStyle(TableStyle([
            ("SPAN", (0, 0), (1, 0)),
            ("BACKGROUND", (0, 0), (-1, 0), _RISK_COLORS.get(meta.get("risk", "Info"), _DEFAULT_RISK_COLOR)),
            ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f1f5f9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story = [header_table, Spacer(1, 0.25 * cm)]

        # Journaux générés et alertes SIEM
        event_ids = sorted(set(meta.get("event_ids", []) + [i.get("value") for i in iocs if i.get("type") == "event_id"]))
        rules = expected.get("wazuh_rules", [])
        siem_lines = []
        if event_ids:
            siem_lines.append(f"Event IDs générés : {', '.join(str(e) for e in event_ids)}")
        if rules:
            siem_lines.append(f"Règles Wazuh attendues : {', '.join(str(r) for r in rules)} "
                               f"(seuil de détection : {expected.get('threshold', '—')} alerte(s))")
        if not siem_lines:
            siem_lines.append("Aucun Event ID Windows natif — détection réseau/comportementale uniquement.")
        story.append(Paragraph("Journaux générés et alertes SIEM", styles["SubHeading"]))
        story.append(Paragraph("<br/>".join(siem_lines), styles["CellText"]))
        story.append(Spacer(1, 0.2 * cm))

        # Impact sur AD
        impact_bits = [catalog.get("impact", "")]
        for key in ("hashes_extracted", "total_hashes_extracted", "total_roastable",
                    "domain_compromised", "forest_compromise", "credentials_found", "hosts_compromised"):
            if key in summary:
                impact_bits.append(f"{key.replace('_', ' ')} : {summary[key]}")
        impact_text = self._redact(" — ".join(b for b in impact_bits if b)) or "—"
        story.append(Paragraph("Impact sur AD", styles["SubHeading"]))
        story.append(Paragraph(impact_text, styles["CellText"]))
        story.append(Spacer(1, 0.2 * cm))

        # Recommandations (aggregated from findings + catalogue)
        reco_bits = [catalog.get("mitigation", "")]
        for f in findings:
            if f.get("mitigation"):
                reco_bits.append(self._redact(f["mitigation"]))
        reco_text = "<br/>".join(dict.fromkeys(b for b in reco_bits if b)) or "—"
        story.append(Paragraph("Recommandations pour la mitigation", styles["SubHeading"]))
        story.append(Paragraph(reco_text, styles["CellText"]))
        story.append(Spacer(1, 0.25 * cm))

        # Détail des findings de l'exécution (preuves)
        if findings:
            story.append(Paragraph("Détail de l'exécution", styles["SubHeading"]))
            story.append(self._findings_table(findings, styles))

        return story

    def _findings_table(self, findings: list, styles) -> Table:
        """Compact risk/title/description table used for Red Team execution evidence."""
        header = [Paragraph(h, styles["CellTextBold"]) for h in ("Risque", "Titre", "Description")]
        rows = [header]
        row_risk_colors = [None]
        for f in findings:
            risk = f.get("risk", "Info")
            rows.append([
                Paragraph(risk, styles["CellTextBold"]),
                Paragraph(self._redact(f.get("title", "—")), styles["CellText"]),
                Paragraph(self._redact(f.get("description", "")), styles["CellText"]),
            ])
            row_risk_colors.append(_RISK_COLORS.get(risk, _DEFAULT_RISK_COLOR))

        table = Table(rows, colWidths=[2 * cm, 4.5 * cm, 9.5 * cm], repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("VALIGN",     (0, 0), (-1, -1), "TOP"),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]
        for i, color in enumerate(row_risk_colors):
            if color is not None:
                style.append(("BACKGROUND", (0, i), (0, i), color))
                style.append(("TEXTCOLOR", (0, i), (0, i), colors.white))
        table.setStyle(TableStyle(style))
        return table

    # ── Purple Team ─────────────────────────────────────────────────────────

    def _purple_team_block(self, res: dict, styles) -> list:
        """Purple Team detection-validation section: per-attack SIEM coverage."""
        findings = res.get("findings", [])
        summary  = res.get("summary", {})
        story = []
        if summary:
            rows = [
                ["Attaques couvertes",  str(summary.get("total_attacks", "—"))],
                ["Détectées",           str(summary.get("detected", "—"))],
                ["Non détectées",       str(summary.get("missed", "—"))],
                ["Taux de détection",   f"{summary.get('detection_rate_pct', '—')}%"],
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
            story += [table, Spacer(1, 0.3 * cm)]
        if findings:
            story.append(self._findings_table(findings, styles))
        return story

    # ── Résumé technique ─────────────────────────────────────────────────────

    def _technical_summary(self, results: list, styles) -> list:
        """Closing summary section with aggregated statistics (all modules)."""
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
        return [PageBreak(), Paragraph("Résumé", styles["ModuleHeading"]), table]

    # ══════════════════════════════════════════════════════════════════════════
    # RAPPORT GOUVERNANCE
    # ══════════════════════════════════════════════════════════════════════════

    def _write_governance_pdf(self, results: list, path: str):
        """
        Write the governance PDF: executive summary for a non-technical
        reader. No Event IDs, no hashes, no exploit commands — risk posture,
        detection coverage, and remediation priorities only.
        """
        try:
            doc = SimpleDocTemplate(
                path, pagesize=A4,
                topMargin=2 * cm, bottomMargin=2 * cm,
                leftMargin=2 * cm, rightMargin=2 * cm,
            )
            styles = self._styles()
            story = self._title_page("Rapport de Gouvernance — Synthèse Exécutive", styles)

            story += self._governance_overview(styles)
            story += self._governance_run_summary(results, styles)
            story += self._governance_priorities(results, styles)

            doc.build(story)
            print_success(f"Rapport de gouvernance : {path}")
            logger.info(f"Governance PDF generated: {path}")
        except Exception as e:
            print_error(f"Erreur génération rapport de gouvernance : {e}")

    def _governance_overview(self, styles) -> list:
        """Global security posture pulled from the historical database (all runs to date)."""
        story = [Paragraph("Posture de sécurité globale", styles["ModuleHeading"])]
        try:
            from core.database import DatabaseManager
            db = DatabaseManager()
            stats    = db.get_global_stats()
            findings = db.get_findings_summary()
            rates    = db.get_detection_rate()
        except Exception as e:
            story.append(Paragraph(f"Statistiques indisponibles ({e}).", styles["CellText"]))
            return story

        rows = [
            ["Exécutions Red Team",           str(stats.get("total_executions", 0))],
            ["Taux de succès des attaques",   f"{stats.get('success_rate', 0)}%"],
            ["Findings Blue Team (total)",    str(stats.get("total_findings", 0))],
            ["Findings critiques/élevés",     str(stats.get("critical_findings", 0))],
            ["Taux de détection SIEM moyen",  f"{stats.get('avg_detection_rate', 0)}%"],
        ]
        table = Table(
            [[Paragraph(k, styles["CellTextBold"]), Paragraph(v, styles["CellText"])] for k, v in rows],
            colWidths=[8 * cm, 6 * cm],
        )
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story += [table, Spacer(1, 0.4 * cm)]

        if findings:
            story.append(Paragraph("Répartition des findings par niveau de risque", styles["SubHeading"]))
            frows = [["Niveau", "Nombre"]] + [[level, str(count)] for level, count in findings.items()]
            ftable = Table(frows, colWidths=[6 * cm, 4 * cm])
            style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
            for i, (level, _) in enumerate(findings.items(), start=1):
                color = _RISK_COLORS.get(level, _DEFAULT_RISK_COLOR)
                style.append(("BACKGROUND", (0, i), (0, i), color))
                style.append(("TEXTCOLOR", (0, i), (0, i), colors.white))
            ftable.setStyle(TableStyle(style))
            story += [ftable, Spacer(1, 0.4 * cm)]

        if rates:
            story.append(Paragraph("Couverture de détection par attaque", styles["SubHeading"]))
            rrows = [["Attaque", "Taux de détection", "Exécutions"]] + [
                [name, f"{d['rate']}%", str(d["runs"])] for name, d in rates.items()
            ]
            rtable = Table(rrows, colWidths=[6 * cm, 4 * cm, 3 * cm])
            rtable.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]))
            story += [rtable, Spacer(1, 0.4 * cm)]

        return story

    def _governance_run_summary(self, results: list, styles) -> list:
        """Plain-language summary of the current run, without technical detail."""
        story = [PageBreak(), Paragraph("Résultat de cette exécution", styles["ModuleHeading"])]
        for res in results:
            module = self._redact(res.get("module", "N/A"))
            status = res.get("status", "N/A")
            findings = res.get("findings", [])
            critical = sum(1 for f in findings if f.get("risk") in ("Critique", "Élevé"))

            if res.get("attack_meta"):
                name = res["attack_meta"].get("name", module)
                text = (
                    f"<b>{name}</b> — statut : {status}. "
                    f"{critical} constat(s) à risque critique/élevé identifié(s) lors de la simulation."
                )
            else:
                text = (
                    f"<b>{module}</b> — statut : {status}. "
                    f"{len(findings)} constat(s), dont {critical} critique(s)/élevé(s)."
                )
            story.append(Paragraph(text, styles["ExecBody"]))
            story.append(Spacer(1, 0.15 * cm))
        return story

    def _governance_priorities(self, results: list, styles) -> list:
        """Top remediation priorities: titles + risk level only, no technical detail."""
        all_findings = [
            (f, res) for res in results for f in res.get("findings", [])
            if f.get("risk") in ("Critique", "Élevé", "Critical", "High")
        ]
        story = [Spacer(1, 0.3 * cm), Paragraph("Priorités de remédiation", styles["ModuleHeading"])]
        if not all_findings:
            story.append(Paragraph("Aucun constat critique ou élevé sur cette exécution.", styles["ExecBody"]))
            return story

        rows = [["Priorité", "Constat", "Recommandation"]]
        for i, (f, _res) in enumerate(all_findings[:15], start=1):
            reco = f.get("mitigation_humaine") or f.get("mitigation") or "—"
            rows.append([
                str(i),
                Paragraph(self._redact(f.get("title", "—")), styles["CellText"]),
                Paragraph(self._redact(reco), styles["CellText"]),
            ])
        table = Table(rows, colWidths=[1.5 * cm, 6.5 * cm, 8 * cm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(table)
        return story
