"""
Purple Team — Detection Validation
====================================
Validates whether the Wazuh SIEM correctly detected each simulated attack
by querying the API for expected rule triggers.

For each attack in the detection matrix, this module:
    1. Queries Wazuh for alerts matching the expected rule IDs
    2. Compares the alert count against a minimum detection threshold
    3. Classifies the result as: detected / partial / missed

Detection matrix covers:
    - Password Spraying   → Wazuh rules 18152, 60204 | Event ID 4625
    - Kerberoasting       → Wazuh rule  60106         | Event ID 4769
    - LLMNR Poisoning     → Wazuh rule  17501
    - Pass-the-Hash       → Wazuh rules 18107, 60301  | Event ID 4624
    - Lateral Movement    → Wazuh rules 18104, 60401  | Event IDs 4688, 7045

Runs in offline/demo mode if Wazuh is unreachable, using simulated
alert data to demonstrate the Purple Team workflow.

"""

from datetime import datetime

from core.wazuh_api import WazuhAPI, connect_or_warn
from utils.format_utils import (
    print_info, print_success, print_warning, print_error, format_table
)


# Map attack → expected Wazuh rule IDs / Event IDs
DETECTION_MATRIX = {
    "Password Spraying": {
        "event_ids":    [4625],
        "wazuh_rules":  [60204, 60122, 18152],
        "description":  "Multiples échecs de connexion depuis une même source",
        "threshold":    5,
    },
    "Kerberoasting": {
        "event_ids":    [4769],
        "wazuh_rules":  [60106, 100001, 100002],
        "description":  "Volume anormal de Kerberos Service Ticket Requests",
        "threshold":    3,
    },
    "LLMNR Poisoning": {
        "event_ids":    [],
        "wazuh_rules":  [17501, 60106],
        "description":  "Détection de trafic LLMNR/NBT-NS suspect",
        "threshold":    1,
    },
    "Pass-the-Hash": {
        "event_ids":    [4624],
        "wazuh_rules":  [60106, 60122, 18107],
        "description":  "Authentification NTLM type 3 suspecte",
        "threshold":    1,
    },
    "Lateral Movement": {
        "event_ids":    [4624, 7045],
        "wazuh_rules":  [92213, 92057, 60106],
        "description":  "Exécution distante via PsExec/WMI",
        "threshold":    2,
    },
    "AS-REP Roasting": {
        "event_ids":    [4768],
        "wazuh_rules":  [100003, 60106],
        "description":  "Compte sans pré-authentification Kerberos exploité",
        "threshold":    1,
    },
    "DCSync": {
        "event_ids":    [4662],
        "wazuh_rules":  [100004, 60106],
        "description":  "Réplication AD non autorisée détectée",
        "threshold":    1,
    },
    "Golden Ticket": {
        "event_ids":    [4769],
        "wazuh_rules":  [100005, 60106],
        "description":  "Ticket Kerberos forgé détecté",
        "threshold":    1,
    },
}


def run(**kwargs) -> dict:
    """
    For each attack in the detection matrix:
    1. Query Wazuh for expected alerts (last 60 min)
    2. Compute detection rate
    3. Flag undetected attacks
    """
    print_info("Purple Team — Validation de la détection SIEM...")

    api, connected = connect_or_warn("Wazuh inaccessible — simulation avec données fictives (mode démo)")

    findings  = []
    validated = []
    missed    = []

    for attack_name, meta in DETECTION_MATRIX.items():
        print_info(f"Vérification : {attack_name}...")
        rule_ids = meta["wazuh_rules"]

        if connected:
            counts = api.count_alerts_by_rule(rule_ids, minutes=60)
            total_alerts = sum(counts.values())
        else:
            # Demo mode — simulate partial detection
            import random
            total_alerts = random.choice([0, 0, 3, 8, 15])

        detected   = total_alerts >= meta["threshold"]
        rate_label = "✔ Détecté" if detected else "✘ Non détecté"

        finding = {
            "risk":        "Info" if detected else "Élevé",
            "title":       f"{rate_label} — {attack_name}",
            "description": (
                f"{meta['description']}. "
                f"Alertes trouvées : {total_alerts} "
                f"(seuil : {meta['threshold']}). "
                f"Event IDs cibles : {meta['event_ids']}."
            ),
            "mitigation": (
                "RAS — détection opérationnelle." if detected else
                f"Créer/ajuster les règles Wazuh {rule_ids} pour détecter cette attaque."
            ),
            "event_ids":   meta["event_ids"],
        }
        findings.append(finding)

        if detected:
            validated.append(attack_name)
        else:
            missed.append(attack_name)

    # Print summary table
    rows = []
    for attack_name, meta in DETECTION_MATRIX.items():
        det = "✔" if attack_name in validated else "✘"
        rows.append([attack_name, meta["description"][:40] + "…", det])
    print("\n" + format_table(["Attaque", "Description", "Détecté"], rows))

    detection_rate = len(validated) / len(DETECTION_MATRIX) * 100 if DETECTION_MATRIX else 0
    print_info(f"Taux de détection global : {detection_rate:.0f}%")

    if detection_rate < 60:
        print_warning("Taux de détection faible — réviser les règles Wazuh et l'audit policy Windows.")
    else:
        print_success("Couverture de détection satisfaisante.")

    # Log dans la base de données
    try:
        from core.database import DatabaseManager
        db = DatabaseManager()
        for attack_name, meta in DETECTION_MATRIX.items():
            detected = attack_name in validated
            db.log_detection(
                execution_id   = None,
                attack_name    = attack_name,
                alert_count    = meta.get("alert_count", 0),
                rule_ids       = meta.get("wazuh_rules", []),
                detected       = detected,
                detection_rate = 100.0 if detected else 0.0,
            )
    except Exception as db_err:
        pass

    return {
        "module":         "purple_team.validate_detection",
        "status":         "success",
        "timestamp":      datetime.now().isoformat(),
        "findings":       findings,
        "summary": {
            "total_attacks":    len(DETECTION_MATRIX),
            "detected":         len(validated),
            "missed":           len(missed),
            "detection_rate_pct": round(detection_rate, 1),
            "missed_attacks":   missed,
        },
    }
