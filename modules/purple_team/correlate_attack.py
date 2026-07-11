"""
Purple Team — Attack / Alert Correlation
==========================================
Correlates executed Red Team attacks with Wazuh SIEM alerts to compute
the overall detection coverage of the lab environment.

Workflow:
    1. Scan /reports/ for recent Red Team execution reports
    2. Query Wazuh for alerts matching each attack's expected rule IDs
    3. Compare alert counts against per-attack detection thresholds
    4. Classify each attack as: detected / partial / missed / not_run
    5. Compute an overall detection rate percentage

Output includes:
    - Per-attack detection status table
    - Visual detection coverage bar (0-100%)
    - Gap analysis with specific remediation steps for missed attacks
    - Actionable recommendations for improving Wazuh rule coverage

"""

import os
import json
import glob
from datetime import datetime

from core.wazuh_api import WazuhAPI, connect_or_warn
from utils.format_utils import (
    print_info, print_success, print_warning, print_error,
    format_table, Colors
)

# Expected detection mapping: attack module → Wazuh rule IDs + Event IDs
CORRELATION_MAP = {
    "red_team.password_spray": {
        "label":       "Password Spraying",
        "wazuh_rules": [60204, 60122, 18152],
        "event_ids":   [4625, 4740],
        "threshold":   5,
    },
    "red_team.kerberoasting": {
        "label":       "Kerberoasting",
        "wazuh_rules": [60106, 100001, 100002],
        "event_ids":   [4769],
        "threshold":   3,
    },
    "red_team.llmnr_poisoning": {
        "label":       "LLMNR/NBT-NS Poisoning",
        "wazuh_rules": [60106, 17501],
        "event_ids":   [],
        "threshold":   1,
    },
    "red_team.pth": {
        "label":       "Pass-the-Hash",
        "wazuh_rules": [60106, 60122, 18107],
        "event_ids":   [4624, 4648],
        "threshold":   1,
    },
    "red_team.lateral_mouvement": {
        "label":       "Lateral Movement",
        "wazuh_rules": [92213, 92057, 60106],
        "event_ids":   [4624, 7045],
        "threshold":   1,
    },
    "red_team.asrep_roasting": {
        "label":       "AS-REP Roasting",
        "wazuh_rules": [100003, 60106],
        "event_ids":   [4768],
        "threshold":   1,
    },
    "red_team.dcsync": {
        "label":       "DCSync",
        "wazuh_rules": [100004, 60106],
        "event_ids":   [4662],
        "threshold":   1,
    },
    "red_team.golden_ticket": {
        "label":       "Golden Ticket",
        "wazuh_rules": [100005, 60106],
        "event_ids":   [4769],
        "threshold":   1,
    },
}


def run(**kwargs) -> dict:
    """
    1. Load recent red team results from /reports/
    2. Query Wazuh for corresponding alerts
    3. Compute detection coverage per attack
    4. Build gap analysis
    """
    minutes = kwargs.get("minutes", 120)
    print_info(f"Corrélation attaques/alertes (fenêtre: {minutes} min)...")

    # Load executed attacks from recent reports
    executed = _load_executed_attacks()
    if not executed:
        print_warning("Aucun rapport d'attaque trouvé — exécuter des modules Red Team d'abord.")
        executed = list(CORRELATION_MAP.keys())  # Use all known attacks as demo

    # Query Wazuh
    api, connected = connect_or_warn("Wazuh hors ligne — simulation de données de détection partielle.")

    if connected:
        alert_counts = api.count_alerts_by_rule(
            [r for meta in CORRELATION_MAP.values() for r in meta["wazuh_rules"]],
            minutes=minutes
        )
    else:
        print_warning("Wazuh hors ligne — simulation de données de détection partielle.")
        alert_counts = _demo_alert_counts()

    # Correlate
    results   = []
    detected  = []
    missed    = []
    partial   = []

    for module_path in CORRELATION_MAP:
        meta      = CORRELATION_MAP[module_path]
        label     = meta["label"]
        rules     = meta["wazuh_rules"]
        threshold = meta["threshold"]
        was_run   = module_path in executed

        total_hits = sum(alert_counts.get(str(r), 0) for r in rules)
        det_status = _detection_status(total_hits, threshold, was_run)

        results.append({
            "module":      module_path,
            "label":       label,
            "was_run":     was_run,
            "alert_count": total_hits,
            "threshold":   threshold,
            "rules":       rules,
            "status":      det_status,
        })

        if det_status == "detected":
            detected.append(label)
        elif det_status == "missed":
            missed.append(label)
        elif det_status == "partial":
            partial.append(label)

    # Print correlation table
    _print_correlation_table(results)

    # Detection rate
    run_count = sum(1 for r in results if r["was_run"])
    det_count = len(detected)
    rate      = (det_count / run_count * 100) if run_count else 0

    _print_coverage_bar(rate)

    # Build findings
    findings = _build_findings(results, missed, partial, rate)

    return {
        "module":    "purple_team.correlate_attack",
        "status":    "success",
        "timestamp": datetime.now().isoformat(),
        "findings":  findings,
        "correlation_results": results,
        "summary": {
            "attacks_executed":    run_count,
            "attacks_detected":    det_count,
            "attacks_missed":      len(missed),
            "attacks_partial":     len(partial),
            "detection_rate_pct":  round(rate, 1),
            "missed_attacks":      missed,
            "partial_attacks":     partial,
            "wazuh_connected":     connected,
        },
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _detection_status(hits: int, threshold: int, was_run: bool) -> str:
    if not was_run:
        return "not_run"
    if hits >= threshold:
        return "detected"
    if hits > 0:
        return "partial"
    return "missed"


def _load_executed_attacks() -> list:
    """Scan /reports/ for red_*.pdf to find which attacks were run."""
    base = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        __file__))), "reports")
    executed = []
    for path in glob.glob(os.path.join(base, "red_*.pdf")):
        fname = os.path.basename(path)
        for module_path in CORRELATION_MAP:
            short = module_path.replace("red_team.", "")
            if short in fname:
                if module_path not in executed:
                    executed.append(module_path)
    return executed


def _print_correlation_table(results: list):
    ICONS = {
        "detected":  f"{Colors.GREEN}✔ Détecté{Colors.RESET}",
        "missed":    f"{Colors.RED}✘ Manqué{Colors.RESET}",
        "partial":   f"{Colors.YELLOW}~ Partiel{Colors.RESET}",
        "not_run":   f"{Colors.DIM}— Non exécuté{Colors.RESET}",
    }
    rows = []
    for r in results:
        run_icon = f"{Colors.CYAN}●{Colors.RESET}" if r["was_run"] else f"{Colors.DIM}○{Colors.RESET}"
        rows.append([
            run_icon + " " + r["label"],
            str(r["alert_count"]),
            str(r["threshold"]),
            ICONS.get(r["status"], r["status"]),
        ])
    print("\n" + format_table(
        ["Attaque", "Alertes", "Seuil", "Statut détection"],
        rows
    ))


def _print_coverage_bar(rate: float):
    filled = int(rate / 5)
    bar    = Colors.GREEN + "█" * filled + Colors.DIM + "░" * (20 - filled) + Colors.RESET
    color  = Colors.GREEN if rate >= 80 else Colors.YELLOW if rate >= 50 else Colors.RED
    print(f"\n  Taux de détection : [{bar}] {color}{rate:.0f}%{Colors.RESET}\n")


def _build_findings(results: list, missed: list, partial: list, rate: float) -> list:
    findings = []

    if missed:
        findings.append({
            "risk":  "Critique",
            "title": f"{len(missed)} attaque(s) non détectée(s) par le SIEM",
            "description": (
                f"Attaques sans alerte : {', '.join(missed)}. "
                "Ces attaques peuvent se dérouler sans aucune visibilité pour l'équipe sécurité."
            ),
            "mitigation": (
                "1. Créer des règles Wazuh personnalisées pour ces attaques.\n"
                "2. Vérifier que l'audit policy Windows est bien activée (auditpol).\n"
                "3. Valider que l'agent Wazuh tourne sur toutes les machines cibles."
            ),
            "event_ids": [],
        })

    if partial:
        findings.append({
            "risk":  "Élevé",
            "title": f"{len(partial)} attaque(s) partiellement détectée(s)",
            "description": (
                f"Détection incomplète pour : {', '.join(partial)}. "
                "Alertes sous le seuil de déclenchement — tuning des règles nécessaire."
            ),
            "mitigation": (
                "Ajuster les seuils des règles Wazuh correspondantes. "
                "Valider les Event IDs ciblés dans les règles."
            ),
            "event_ids": [],
        })

    if rate >= 80:
        findings.append({
            "risk":  "Info",
            "title": f"Bonne couverture de détection ({rate:.0f}%)",
            "description": "Le SIEM détecte la majorité des attaques simulées.",
            "mitigation": "Maintenir la politique d'audit et les règles Wazuh à jour.",
            "event_ids": [],
        })
    elif rate < 50:
        findings.append({
            "risk":  "Critique",
            "title": f"Couverture de détection insuffisante ({rate:.0f}%)",
            "description": "Moins de la moitié des attaques sont détectées — risque opérationnel élevé.",
            "mitigation": (
                "Révision complète des règles Wazuh recommandée. "
                "Vérifier la collecte des logs (agents, canaux, audit policy). "
                "Envisager des règles custom pour les attaques AD non couvertes."
            ),
            "event_ids": [],
        })

    return findings


def _demo_alert_counts() -> dict:
    """Simulate partial Wazuh coverage for offline demo."""
    return {
        "18152": 8,   # spray detected
        "60204": 3,
        "60106": 5,   # kerberoasting detected
        "17501": 0,   # LLMNR missed
        "18107": 1,   # PtH partial
        "60301": 0,
        "18104": 2,   # lateral movement detected
        "60401": 1,
    }
