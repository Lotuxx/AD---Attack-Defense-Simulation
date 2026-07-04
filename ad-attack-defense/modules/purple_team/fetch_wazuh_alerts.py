"""
Purple Team — Récupération des alertes Wazuh via API REST.
Formate et classe les alertes par sévérité et type d'attaque.
"""

import json
from datetime import datetime, timedelta

from core.wazuh_api import WazuhAPI
from utils.format_utils import (
    print_info, print_success, print_warning,
    format_table, risk_badge, Colors
)

RULE_ATTACK_MAP = {
    18152: "Password Spraying",  60204: "Password Spraying",
    60106: "Kerberoasting",
    17501: "LLMNR Poisoning",
    18107: "Pass-the-Hash",      60301: "Pass-the-Hash",
    18104: "Lateral Movement",   60401: "Lateral Movement",
    60501: "DCSync",
    63001: "Log Tampering",
    18151: "AD Recon",           60100: "AD Recon",
}

SEVERITY_MAP = [
    (range(1,  4),  "Faible",   "Info"),
    (range(4,  8),  "Moyen",    "Moyen"),
    (range(8,  12), "Élevé",    "Élevé"),
    (range(12, 16), "Critique", "Critique"),
]


def run(**kwargs) -> dict:
    minutes   = kwargs.get("minutes", 60)
    min_level = kwargs.get("min_level", 3)

    print_info(f"Récupération des alertes Wazuh (dernières {minutes} min, niveau >= {min_level})...")

    api       = WazuhAPI()
    connected = api.authenticate()

    if not connected:
        print_warning("Wazuh inaccessible — données de démonstration utilisées.")
        raw_alerts = _demo_alerts()
    else:
        raw_alerts = api.get_alerts(minutes=minutes, min_level=min_level)

    if not raw_alerts:
        print_warning("Aucune alerte trouvée dans la fenêtre de temps.")
        return _build_result([], {}, minutes)

    print_success(f"{len(raw_alerts)} alerte(s) récupérée(s).")

    alerts      = [_parse_alert(a) for a in raw_alerts]
    by_category = {}
    for alert in alerts:
        by_category.setdefault(alert["category"], []).append(alert)

    _print_summary_table(by_category)
    findings = _build_findings(by_category)

    return _build_result(alerts, by_category, minutes, findings)


def _parse_alert(raw: dict) -> dict:
    rule  = raw.get("rule", {})
    rid   = rule.get("id", 0)
    level = rule.get("level", 0)
    agent = raw.get("agent", {})
    ts    = raw.get("timestamp", "")
    return {
        "id":         raw.get("id", ""),
        "timestamp":  ts[:19] if ts else "",
        "rule_id":    rid,
        "rule_desc":  rule.get("description", ""),
        "level":      level,
        "severity":   _level_label(level, 0),
        "risk":       _level_label(level, 1),
        "category":   RULE_ATTACK_MAP.get(int(rid) if rid else 0, "Autre"),
        "agent_name": agent.get("name", "unknown"),
        "agent_ip":   agent.get("ip", "unknown"),
        "groups":     rule.get("groups", []),
    }


def _level_label(level: int, idx: int) -> str:
    for r, sev, risk in SEVERITY_MAP:
        if level in r:
            return (sev, risk)[idx]
    return ("Critique", "Critique")[idx]


def _print_summary_table(by_category: dict):
    rows = []
    for cat, alerts in sorted(by_category.items(), key=lambda x: -len(x[1])):
        max_lvl = max(a["level"] for a in alerts)
        risk    = _level_label(max_lvl, 1)
        agents  = ", ".join(set(a["agent_name"] for a in alerts))[:35]
        rows.append([cat, str(len(alerts)), risk, agents])
    print("\n" + format_table(["Catégorie", "Alertes", "Risque max", "Agents"], rows))


def _build_findings(by_category: dict) -> list:
    findings = []
    for cat, alerts in by_category.items():
        max_lvl  = max(a["level"] for a in alerts)
        risk     = _level_label(max_lvl, 1)
        agents   = list(set(a["agent_name"] for a in alerts))
        rule_ids = list(set(a["rule_id"] for a in alerts))
        findings.append({
            "risk":       risk,
            "title":      f"{len(alerts)} alerte(s) Wazuh — {cat}",
            "description": (
                f"Règles : {rule_ids}. "
                f"Agents : {', '.join(agents[:5])}. "
                f"Exemple : {alerts[0]['rule_desc']}"
            ),
            "mitigation": _mitigation_for_category(cat),
            "event_ids":  [],
        })
    return findings


def _mitigation_for_category(cat: str) -> str:
    m = {
        "Password Spraying": "Bloquer l'IP source. Activer MFA. Vérifier les comptes ciblés.",
        "Kerberoasting":     "Renforcer les mots de passe SPN. Surveiller les 4769 en masse.",
        "LLMNR Poisoning":   "Désactiver LLMNR/NBT-NS via GPO. Activer SMB Signing.",
        "Pass-the-Hash":     "Activer Credential Guard. Déployer LAPS. Désactiver NTLMv1.",
        "Lateral Movement":  "Segmenter le réseau. Restreindre ADMIN$. Surveiller 7045.",
        "DCSync":            "Révoquer les droits de réplication. Investiguer immédiatement.",
        "Log Tampering":     "Centraliser les logs vers Wazuh en temps réel.",
        "AD Recon":          "Surveiller les requêtes LDAP massives. Limiter l'énumération AD.",
    }
    return m.get(cat, "Investiguer et corréler avec les autres événements.")


def _build_result(alerts, by_category, minutes, findings=None):
    return {
        "module":      "purple_team.fetch_wazuh_alerts",
        "status":      "success",
        "timestamp":   datetime.now().isoformat(),
        "findings":    findings or [],
        "alerts":      alerts,
        "by_category": {k: len(v) for k, v in by_category.items()},
        "summary": {
            "total_alerts":    len(alerts),
            "categories_hit":  len(by_category),
            "window_minutes":  minutes,
            "critical_alerts": sum(1 for a in alerts if a.get("risk") == "Critique"),
        },
    }


def _demo_alerts() -> list:
    now = datetime.now()
    data = [
        (18152, 10, "Multiple auth failures — password spray",         "WIN-CLIENT01", "192.168.56.11"),
        (18152, 10, "Multiple auth failures — password spray",         "WIN-CLIENT01", "192.168.56.11"),
        (18152, 10, "Multiple auth failures — password spray",         "WIN-DC01",     "192.168.56.10"),
        (60106,  9, "Kerberos TGS request anomaly detected",           "WIN-DC01",     "192.168.56.10"),
        (60106,  9, "Kerberos TGS request anomaly detected",           "WIN-DC01",     "192.168.56.10"),
        (18107, 12, "Pass-the-Hash attempt detected",                  "WIN-CLIENT02", "192.168.56.12"),
        (18104, 11, "Remote execution via PsExec detected",            "WIN-CLIENT02", "192.168.56.12"),
        (60501, 14, "DCSync attack — DRSUAPI replication detected",    "WIN-DC01",     "192.168.56.10"),
        (17501,  8, "LLMNR poisoning attempt",                         "WIN-CLIENT01", "192.168.56.11"),
    ]
    return [
        {
            "id": f"demo_{i}",
            "timestamp": (now - timedelta(minutes=i * 3)).isoformat(),
            "rule":  {"id": rid, "level": lvl, "description": desc, "groups": []},
            "agent": {"name": agent, "ip": ip},
        }
        for i, (rid, lvl, desc, agent, ip) in enumerate(data)
    ]
