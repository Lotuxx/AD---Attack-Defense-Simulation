"""
Report Generator (v1.2)
========================
Entry point for all report generation.

Now generates PDF only (TXT/CSV removed per teacher feedback).
Delegates to PDFReportGenerator for both report types:
  - 'technical'  : Full technical detail for SOC / pentest teams
  - 'governance' : Executive summary for CISO / management

Usage:
    gen = ReportGenerator()
    gen.generate(results, "blue_team_audit", report_type="both")
    gen.generate(results, "red_team_attack", report_type="technical")
"""

import os
from datetime import datetime
from typing import Union, Optional

from core.logger import FrameworkLogger
from core.pdf_report import PDFReportGenerator
from utils.format_utils import print_success, print_error, print_info

logger = FrameworkLogger("ReportGenerator")

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


class ReportGenerator:
    """
    Facade for PDF report generation.

    Args:
        output_format : Kept for CLI compatibility — now ignored (always PDF).
        report_type   : 'technical' | 'governance' | 'both' (default: 'both')
    """

    def __init__(self, output_format: str = "both", report_type: str = "both"):
        self.report_type = report_type
        self._pdf        = PDFReportGenerator(output_dir=REPORTS_DIR)

    def generate(
        self,
        results: Union[dict, list],
        label: str,
        output_format: str = None,    # kept for backwards-compat — ignored
        report_type: str = None,
        baseline: Optional[list] = None,
    ) -> list:
        """
        Generate PDF report(s).

        Args:
            results     : Module result dict or list of dicts.
            label       : Base filename label.
            output_format: Ignored (kept for backwards-compat with old CLI calls).
            report_type : 'technical' | 'governance' | 'both'.
                          Overrides instance default if provided.
            baseline    : Optional previous results for before/after comparison.

        Returns:
            list[str]: Paths of generated PDF files.
        """
        rtype = report_type or self.report_type

        # Normalise to list and strip non-dicts
        if not isinstance(results, list):
            results = [results]
        results = [r for r in results if isinstance(r, dict)]

        if not results:
            print_error("ReportGenerator: no valid results to report.")
            return []

        generated = []
        types_to_generate = (
            ["technical", "governance"] if rtype == "both"
            else [rtype]
        )

        for rt in types_to_generate:
            print_info(f"Generating {rt} PDF report...")
            try:
                path = self._pdf.generate(
                    results=results,
                    label=label,
                    report_type=rt,
                    baseline=baseline,
                )
                print_success(f"{rt.capitalize()} PDF: {path}")
                logger.info(f"{rt} PDF generated: {path}")
                generated.append(path)
            except Exception as e:
                print_error(f"PDF generation failed ({rt}): {e}")
                logger.error(f"PDF error ({rt}): {e}")

        return generated
