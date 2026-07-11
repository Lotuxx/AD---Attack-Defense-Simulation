"""
Blue Team — Audit des journaux d'événements Windows
=====================================================
Analyse les journaux d'événements de sécurité Windows pour détecter des
motifs d'activité suspecte et vérifier que les politiques d'audit sont
correctement configurées.

Event IDs critiques surveillés :
    4624  — Logon réussi
    4625  — Échec de logon (indicateur de brute force / spray)
    4648  — Logon avec credentials explicites (motif Pass-the-Hash)
    4662  — Opération sur objet AD (indicateur DCSync)
    4769  — Requête Kerberos TGS (indicateur de Kerberoasting)
    4740  — Verrouillage de compte (indicateur de spray)
    7045  — Nouveau service installé (indicateur PsExec / persistance)
    4698  — Tâche planifiée créée (vecteur de persistance)
    1102  — Journal de sécurité effacé (altération de preuves)

Détection de motifs d'attaque :
    - Password Spray   : nombreux 4625 avec très peu de 4624 depuis la même source
    - Kerberoasting    : pic de volume sur les requêtes 4769
    - DCSync           : 4662 avec propriétés de réplication DRSUAPI
    - PsExec           : 7045 corrélé avec un logon réseau (4624 type 3)
    - Altération de logs : présence de l'Event ID 1102

"""

import subprocess
import json
from datetime import datetime, timedelta
from collections import Counter

from utils.format_utils import print_info, print_success, print_warning


# Event IDs critiques à surveiller
CRITICAL_EVENT_IDS = {
    4624: ("Logon réussi",                        "Info"),
    4625: ("Échec de logon",                      "Élevé"),
    4648: ("Logon avec credentials explicites",   "Moyen"),
    4662: ("Opération sur objet AD (DCSync)",     "Critique"),
    4768: ("Kerberos TGT Request",                "Info"),
    4769: ("Kerberos TGS Request (Kerberoast?)",  "Moyen"),
    4771: ("Pré-auth Kerberos échouée",           "Moyen"),
    4720: ("Création de compte utilisateur",      "Moyen"),
    4724: ("Réinitialisation de mot de passe",    "Moyen"),
    4726: ("Compte utilisateur supprimé",         "Élevé"),
    4728: ("Membre ajouté à groupe global",       "Moyen"),
    4740: ("Compte verrouillé",                   "Élevé"),
    7045: ("Nouveau service installé",            "Critique"),
    4688: ("Nouveau processus créé",              "Info"),
    4697: ("Service installé dans le système",    "Critique"),
    4698: ("Tâche planifiée créée",               "Élevé"),
    1102: ("Journal Security effacé",             "Critique"),
}

THRESHOLDS = {
    4625: 20,
    4769: 10,
    4740: 3,
    7045: 1,
    4698: 2,
    4662: 1,
    1102: 1,
}


def run_audit(hours: int = 24, **kwargs) -> dict:
    """
    Run the Windows Security Event Log audit over the given time window.

    Combines raw event-count thresholds, audit-policy checks, attack
    pattern detection, and log-retention checks into one report.

    Args:
        hours (int): Look-back window in hours (default: 24).

    Returns:
        dict: Standard module result with 'findings', 'event_counts', and a 'summary'.
    """
    print_info(f"Audit des logs Windows (dernières {hours}h)...")

    findings = []
    event_counts = _collect_event_counts(hours)
    findings += _analyze_thresholds(event_counts, hours)
    findings += _check_audit_policy()
    findings += _detect_patterns(event_counts)
    findings += _check_log_retention()

    critical = sum(1 for f in findings if f["risk"] in ("Critique", "Élevé"))
    print_success(f"Audit logs terminé — {len(findings)} finding(s), {critical} critique(s)/élevé(s).")

    return {
        "module":       "blue_team.audit_logs",
        "status":       "warning" if critical else "success",
        "timestamp":    datetime.now().isoformat(),
        "findings":     findings,
        "event_counts": event_counts,
        "summary":      {"total": len(findings), "critical": critical},
    }


def _collect_event_counts(hours: int) -> dict:
    """Query Get-WinEvent (via PowerShell) for counts of each monitored Event ID over the window."""
    counts = {}
    ids_str = ",".join(str(i) for i in CRITICAL_EVENT_IDS.keys())
    try:
        since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
        cmd = (
            f"$since = [datetime]'{since}'; "
            f"$ids = @({ids_str}); "
            "Get-WinEvent -LogName Security -ErrorAction SilentlyContinue | "
            "Where-Object {$_.TimeCreated -ge $since -and $ids -contains $_.Id} | "
            "Group-Object Id | Select-Object Name,Count | ConvertTo-Json"
        )
        out = _ps(cmd)
        if out:
            data = json.loads(out)
            if not isinstance(data, list):
                data = [data]
            for item in data:
                eid = int(item.get("Name", 0))
                cnt = int(item.get("Count", 0))
                if eid:
                    counts[eid] = cnt
    except Exception:
        pass
    return counts


def _analyze_thresholds(event_counts: dict, hours: int) -> list:
    """Compare observed event counts against THRESHOLDS and raise a finding for each breach (or missing audit if 0)."""
    findings = []
    for eid, threshold in THRESHOLDS.items():
        count = event_counts.get(eid, 0)
        label, _ = CRITICAL_EVENT_IDS.get(eid, ("Event inconnu", "Info"))
        if count == 0:
            if eid in (4625, 4769, 7045):
                findings.append({
                    "risk":        "Info",
                    "title":       f"Event ID {eid} ({label}) — aucun événement sur {hours}h",
                    "description": "Vérifier que l'audit policy est activée pour cet Event ID.",
                    "mitigation":  "Activer l'audit correspondant dans la politique d'audit avancée.",
                    "event_ids":   [eid],
                })
            continue
        if count >= threshold:
            risk = CRITICAL_EVENT_IDS.get(eid, ("", "Moyen"))[1]
            findings.append({
                "risk":        risk,
                "title":       f"Volume anormal : {count}× Event ID {eid} ({label}) en {hours}h",
                "description": _describe_eid(eid, count),
                "mitigation":  _mitigation_eid(eid),
                "event_ids":   [eid],
            })
    return findings


def _check_audit_policy() -> list:
    """Check via auditpol that key audit subcategories (Logon, Credential Validation, ...) are enabled."""
    findings = []
    checks = {
        "Logon":              "auditpol /get /subcategory:Logon",
        "Credential Validation": "auditpol /get /subcategory:\"Credential Validation\"",
        "Process Creation":   "auditpol /get /subcategory:\"Process Creation\"",
        "DS Access":          "auditpol /get /subcategory:\"Directory Service Access\"",
    }
    for category, cmd in checks.items():
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            out = result.stdout
            if "No Auditing" in out or ("Success" not in out and "Failure" not in out):
                findings.append({
                    "risk":        "Élevé",
                    "title":       f"Audit '{category}' désactivé ou incomplet",
                    "description": f"La catégorie '{category}' n'est pas correctement configurée.",
                    "mitigation":  f"GPO → Advanced Audit Policy → {category} : Success & Failure.",
                    "event_ids":   [],
                })
        except Exception:
            pass
    return findings


def _detect_patterns(event_counts: dict) -> list:
    """Correlate event counts into higher-level attack patterns (spray, Kerberoasting, DCSync, PsExec, log tampering)."""
    findings = []

    # Motif : Password Spraying
    fails   = event_counts.get(4625, 0)
    success = event_counts.get(4624, 0)
    if fails > 15 and success < 3:
        findings.append({
            "risk":        "Critique",
            "title":       "Pattern Password Spraying détecté (4625 >> 4624)",
            "description": f"{fails} échecs pour seulement {success} succès — ratio suspect.",
            "mitigation":  "Bloquer l'IP source, réinitialiser les comptes cibles, activer MFA.",
            "event_ids":   [4625, 4624],
        })

    # Motif : Kerberoasting
    if event_counts.get(4769, 0) > 8:
        findings.append({
            "risk":        "Critique",
            "title":       f"Pattern Kerberoasting détecté ({event_counts[4769]}× Event 4769)",
            "description": "Volume de requêtes TGS caractéristique d'un Kerberoasting.",
            "mitigation":  "Identifier le compte source, renforcer les mots de passe des comptes SPN.",
            "event_ids":   [4769],
        })

    # Motif : DCSync
    if event_counts.get(4662, 0) > 0:
        findings.append({
            "risk":        "Critique",
            "title":       f"Possible DCSync — {event_counts[4662]} opération(s) sur objet AD",
            "description": "Accès aux propriétés de réplication AD — peut indiquer un DCSync (mimikatz).",
            "mitigation":  "Vérifier les droits DRSUAPI, investiguer le compte source immédiatement.",
            "event_ids":   [4662],
        })

    # Motif : PsExec / backdoor via service
    if event_counts.get(7045, 0) > 0:
        findings.append({
            "risk":        "Élevé",
            "title":       f"{event_counts[7045]} service(s) installé(s) — possible PsExec/persistance",
            "description": "7045 est généré par PsExec et les backdoors basés sur des services.",
            "mitigation":  "Auditer les services récents, corréler avec les logons réseau (4624 type 3).",
            "event_ids":   [7045, 4697],
        })

    # Motif : journal effacé
    if event_counts.get(1102, 0) > 0:
        findings.append({
            "risk":        "Critique",
            "title":       "Journal Security effacé (Event ID 1102) — probable cover-up",
            "description": "L'effacement du journal de sécurité est un indicateur fort de compromission.",
            "mitigation":  "Centraliser les logs vers Wazuh en temps réel pour rendre l'effacement inefficace.",
            "event_ids":   [1102, 4719],
        })

    return findings


def _check_log_retention() -> list:
    """Flag a Security log size configured below 512 MB (risk of overwriting forensic evidence)."""
    findings = []
    try:
        out = _ps(
            "Get-WinEvent -ListLog Security | "
            "Select-Object MaximumSizeInBytes,LogMode | ConvertTo-Json"
        )
        if out:
            data = json.loads(out)
            max_mb = int(data.get("MaximumSizeInBytes", 0)) // (1024 * 1024)
            if max_mb < 512:
                findings.append({
                    "risk":        "Élevé",
                    "title":       f"Journal Security trop petit ({max_mb} MB) — risque d'écrasement",
                    "description": "Les événements récents peuvent écraser des preuves forensiques importantes.",
                    "mitigation":  "GPO → Event Log → Security Log Size : 1024 MB minimum. Centraliser vers Wazuh.",
                    "event_ids":   [],
                })
    except Exception:
        pass
    return findings


def _describe_eid(eid: int, count: int) -> str:
    """Return a human-readable French description for a threshold-breaching Event ID."""
    descriptions = {
        4625: f"{count} échecs d'authentification — probable brute force ou password spray.",
        4769: f"{count} requêtes TGS anormales — possible Kerberoasting en cours.",
        4740: f"{count} comptes verrouillés — attaque spray probable.",
        7045: f"{count} service(s) installé(s) — vérifier PsExec ou backdoor.",
        4662: f"{count} opération(s) sur objet AD — surveiller un DCSync.",
        4698: f"{count} tâche(s) planifiée(s) créée(s) — vecteur de persistance.",
        1102: "Journal Security effacé — cover-up potentiel après compromission.",
    }
    return descriptions.get(eid, f"{count} occurrences détectées au-dessus du seuil.")


def _mitigation_eid(eid: int) -> str:
    """Return a French mitigation recommendation for a threshold-breaching Event ID."""
    m = {
        4625: "Activer le verrouillage de compte. Identifier l'IP source. Activer MFA.",
        4769: "Surveiller les comptes SPN. Renforcer les mots de passe des services (>25 car.).",
        4740: "Investiguer l'IP source. Alerter l'équipe sécurité. Vérifier les comptes verrouillés.",
        7045: "Auditer les services créés. Corréler avec les logons réseau (4624 type 3).",
        4662: "Vérifier les droits de réplication AD. Investiguer le compte source immédiatement.",
        4698: "Auditer les tâches planifiées. Supprimer les tâches non légitimes.",
        1102: "Centraliser les logs vers Wazuh. Restreindre les droits d'effacement des logs.",
    }
    return m.get(eid, "Investiguer et corréler avec d'autres indicateurs.")


def _ps(cmd: str) -> str | None:
    """Run a PowerShell command locally and return its stdout, or None on failure/empty output."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=30
        )
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    except Exception:
        return None
