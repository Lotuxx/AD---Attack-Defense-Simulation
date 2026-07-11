"""
Response / SOAR — Disable Compromised Account (Linux/Kali version)
===================================================================
Désactive un compte AD compromis depuis Kali via netexec/impacket.
"""

import subprocess
from datetime import datetime
from utils.format_utils import print_info, print_success, print_warning, print_error


def _load_config() -> dict:
    import os, yaml
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "config.yaml")
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def run(username: str = None, reason: str = "Compte désactivé suite à détection SIEM", **kwargs) -> dict:
    if not username:
        return _error("Paramètre 'username' requis.")

    print_info(f"[RESPONSE] Désactivation du compte : {username}")

    cfg      = _load_config()
    dc_ip    = cfg.get("dc_ip", "192.168.56.12")
    domain   = cfg.get("domain", "essos.local")
    user     = cfg.get("domain_user", "vagrant")
    password = cfg.get("domain_password", "vagrant")

    actions  = []
    findings = []

    # Désactiver le compte via netexec
    cmd = [
        "netexec", "smb", dc_ip,
        "-u", user, "-p", password, "-d", domain,
        "-x", f"powershell -Command \"Disable-ADAccount -Identity '{username}'; Write-Output 'ok'\""
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        success = result.returncode == 0 and ("ok" in result.stdout.lower() or "pwn3d" in result.stdout.lower())

        if success:
            actions.append({
                "action":    "disable_account",
                "target":    username,
                "timestamp": datetime.now().isoformat(),
                "status":    "success",
            })
            print_success(f"Compte '{username}' désactivé avec succès.")
            findings.append({
                "risk":        "Info",
                "title":       f"Compte désactivé : {username}",
                "description": f"Raison : {reason}. Désactivé le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.",
                "mitigation":  "Investiguer la compromission avant de réactiver le compte.",
                "event_ids":   [4725],
            })
            return _build_result("success", username, actions, findings)
        else:
            print_error(f"Échec : {result.stdout[:200]}")
            findings.append({
                "risk":        "Élevé",
                "title":       f"Échec désactivation : {username}",
                "description": f"netexec a échoué : {result.stdout[:100]}",
                "mitigation":  f"Désactiver manuellement : Disable-ADAccount -Identity {username}",
                "event_ids":   [],
            })
            return _build_result("failed", username, actions, findings)

    except Exception as e:
        return _error(f"Exception : {e}")


def _build_result(status, username, actions, findings):
    return {
        "module":    "response.linux.disable_user",
        "status":    status,
        "timestamp": datetime.now().isoformat(),
        "target":    username,
        "findings":  findings,
        "actions":   actions,
        "summary":   {"account": username, "result": status, "actions_taken": len(actions)},
    }


def _error(msg):
    print_error(msg)
    return {
        "module":    "response.linux.disable_user",
        "status":    "error",
        "timestamp": datetime.now().isoformat(),
        "message":   msg,
        "findings":  [],
        "actions":   [],
    }
