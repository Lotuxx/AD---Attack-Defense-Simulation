"""
Report Generator
================
Produces TXT and CSV reports from module execution results.

BUG FIX (v1.1):
    The variable 'f' was used both as the file handle in _write_txt()
    (with open(path) as f:) and as the loop variable in _format_result_txt()
    (for f in findings:). The inner assignment silently overwrote the file
    handle, causing write-after-close errors and repeated content in reports.
    Fixed by renaming all loop variables to 'finding' throughout.
"""

import csv
import os
from datetime import datetime
from typing import Union

from core.logger import FrameworkLogger
from utils.format_utils import print_success, print_error

logger = FrameworkLogger("ReportGenerator")

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


class ReportGenerator:
    """
    Generates TXT and/or CSV reports from module results.

    Args:
        output_format (str): Default format — 'txt', 'csv', or 'both'.
    """

    def __init__(self, output_format: str = "both"):
        self.output_format = output_format

    def generate(self, results: Union[dict, list], label: str,
                 output_format: str = None):
        """
        Generate report(s) for the given module results.

        Args:
            results       : Single result dict or list of result dicts.
            label         : Base filename label (e.g. 'blue_team_full').
            output_format : Override default ('txt', 'csv', 'both').
        """
        fmt = output_format or self.output_format

        # Normalise to list — a single dict is wrapped
        if not isinstance(results, list):
            results = [results]

        # Sanitise: skip any non-dict items that may have crept in
        results = [r for r in results if isinstance(r, dict)]

        if not results:
            print_error("ReportGenerator: no valid results to write.")
            return

        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(REPORTS_DIR, f"{label}_{ts}")

        if fmt in ("txt",  "both"): self._write_txt(results, base + ".txt")
        if fmt in ("csv",  "both"): self._write_csv(results, base + ".csv")

    # ── TXT ──────────────────────────────────────────────────────────────────

    def _write_txt(self, results: list, path: str):
        """Write a human-readable TXT report."""
        try:
            # Use 'fh' (file handle) — NOT 'f' — to avoid shadowing
            # the loop variable used later in _format_result_txt()
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self._txt_header())
                for res in results:
                    fh.write(self._format_result_txt(res))
                fh.write(self._txt_footer(results))
            print_success(f"Rapport TXT : {path}")
            logger.info(f"TXT report generated: {path}")
        except Exception as e:
            print_error(f"TXT generation error: {e}")
            logger.error(f"TXT error: {e}")

    def _txt_header(self) -> str:
        """Build the report header."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return (
            "=" * 70 + "\n"
            "  AD ATTACKS & DEFENSE SIMULATION — RAPPORT\n"
            f"  Généré le : {now}\n"
            "  NISSEKONG Georges Owen | DIOP Salla\n"
            "=" * 70 + "\n\n"
        )

    def _format_result_txt(self, res: dict) -> str:
        """
        Format a single module result as a TXT section.

        IMPORTANT: loop variable is named 'finding' (not 'f') to avoid
        shadowing the file handle 'fh' in the caller.
        """
        lines = []
        lines.append(f"── Module  : {res.get('module', 'N/A')}")
        lines.append(f"   Statut  : {res.get('status', 'N/A')}")
        lines.append(f"   Durée   : {res.get('elapsed_s', 0)}s")
        lines.append(f"   Date    : {res.get('timestamp', 'N/A')}")

        if res.get("message"):
            lines.append(f"   Message : {res['message']}")

        findings = res.get("findings", [])

        # Guard: findings must be a list of dicts
        if not isinstance(findings, list):
            findings = []

        if findings:
            lines.append(f"\n   Résultats ({len(findings)}) :")
            # Variable named 'finding' — NOT 'f' — to avoid any shadowing
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                risk  = finding.get("risk",        "Info")
                title = finding.get("title",       "—")
                desc  = finding.get("description", "")
                mitig = finding.get("mitigation",  "")
                lines.append(f"   [{risk}] {title}")
                if desc:  lines.append(f"           → {desc}")
                if mitig: lines.append(f"           ✓ Mitigation : {mitig}")
        else:
            lines.append("   Aucun finding.")

        lines.append("")
        return "\n".join(lines) + "\n"

    def _txt_footer(self, results: list) -> str:
        """Build the summary footer."""
        total    = len(results)
        errors   = sum(1 for r in results if r.get("status") == "error")
        findings = sum(
            len(r.get("findings", [])) for r in results
            if isinstance(r.get("findings"), list)
        )
        critical = sum(
            1 for r in results
            for finding in (r.get("findings") or [])
            if isinstance(finding, dict)
            and finding.get("risk") in ("Critique", "Élevé", "Critical", "High")
        )
        return (
            "\n" + "=" * 70 + "\n"
            "  RÉSUMÉ\n"
            "=" * 70 + "\n"
            f"  Modules exécutés  : {total}\n"
            f"  Erreurs           : {errors}\n"
            f"  Findings totaux   : {findings}\n"
            f"  Critique / Élevé  : {critical}\n"
            "=" * 70 + "\n"
        )

    # ── CSV ───────────────────────────────────────────────────────────────────

    def _write_csv(self, results: list, path: str):
        """Write a machine-readable CSV report. One row per finding."""
        try:
            fieldnames = [
                "module", "status", "elapsed_s", "timestamp",
                "risk", "title", "description", "mitigation", "event_ids"
            ]
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()

                for res in results:
                    if not isinstance(res, dict):
                        continue
                    findings = res.get("findings", [])
                    if not isinstance(findings, list):
                        findings = []

                    if findings:
                        for finding in findings:
                            if not isinstance(finding, dict):
                                continue
                            writer.writerow({
                                "module":      res.get("module",    ""),
                                "status":      res.get("status",    ""),
                                "elapsed_s":   res.get("elapsed_s", ""),
                                "timestamp":   res.get("timestamp", ""),
                                "risk":        finding.get("risk",        ""),
                                "title":       finding.get("title",       ""),
                                "description": finding.get("description", ""),
                                "mitigation":  finding.get("mitigation",  ""),
                                "event_ids":   ", ".join(
                                    map(str, finding.get("event_ids", []))
                                ),
                            })
                    else:
                        # Module ran but no findings — still record it
                        writer.writerow({
                            "module":    res.get("module",    ""),
                            "status":    res.get("status",    ""),
                            "elapsed_s": res.get("elapsed_s", ""),
                            "timestamp": res.get("timestamp", ""),
                        })

            print_success(f"Rapport CSV : {path}")
            logger.info(f"CSV report generated: {path}")
        except Exception as e:
            print_error(f"CSV generation error: {e}")
            logger.error(f"CSV error: {e}")
