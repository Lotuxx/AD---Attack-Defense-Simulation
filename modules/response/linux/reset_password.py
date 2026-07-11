"""
Response / SOAR — Force Password Reset (Linux/Kali version)
============================================================
Réinitialise le mot de passe d'un compte AD depuis Kali via netexec.
"""
import subprocess
import secrets
import string
from datetime import datetime
from utils.format_utils import print_info, print_success, print_error


def _load_config() -> dict:
    import os, yaml
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "config.yaml")
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def run(username: str = None, new_password: str = None,
        reason: str = "Réinitialisation suite à détection SIEM", **kwargs) -> dict:
    if not username:
        return _error("Paramètre 'username' requis.")
    print_info(f"[RESPONSE] Réinitialisation mot de passe : {username}")
    cfg      = _load_config()
    dc_ip    = cfg.get("dc_ip", "192.168.56.12")
    domain   = cfg.get("domain", "essos.local")
    user     = cfg.get("domain_user", "vagrant")
    password = cfg.get("domain_password", "vagrant")
    if not new_password:
        new_password = _generate_strong_password()
        print_info(f"Mot de passe généré ({len(new_password)} car.)")
    actions, findings = [], []
    cmd = [
        "netexec", "smb", dc_ip,
        "-u", user, "-p", password, "-d", domain,
        "-x", f"powershell -Command \"$pw = ConvertTo-SecureString '{new_password}' -AsPlainText -Force; Set-ADAccountPassword -Identity '{username}' -NewPassword $pw -Reset; Set-ADUser -Identity '{username}' -ChangePasswordAtLogon $true; Write-Output 'ok'\""
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        success = result.returncode == 0 and ("ok" in result.stdout.lower() or "pwn3d" in result.stdout.lower())
        if success:
            actions.append({"action": "reset_password", "target": username,
                            "timestamp": datetime.now().isoformat(), "status": "success"})
            print_success(f"Mot de passe réinitialisé pour '{username}'.")
            findings.append({"risk": "Info", "title": f"Mot de passe réinitialisé : {username}",
                             "description": f"Raison : {reason}. Changement forcé au prochain login.",
                             "mitigation": "Transmettre le nouveau mot de passe via canal sécurisé.",
                             "event_ids": [4723, 4724]})
            return {"module": "response.linux.reset_password", "status": "success",
                    "timestamp": datetime.now().isoformat(), "target": username,
                    "findings": findings, "actions": actions, "new_password": new_password,
                    "summary": {"account": username, "password_reset": True}}
        else:
            return _error(f"Échec : {result.stdout[:100]}")
    except Exception as e:
        return _error(f"Exception : {e}")


def _generate_strong_password(length: int = 24) -> str:
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "!@#$%^&*()"
    pwd = [secrets.choice(string.ascii_uppercase), secrets.choice(string.ascii_lowercase),
           secrets.choice(string.digits), secrets.choice("!@#$%^&*()")]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def _error(msg):
    print_error(msg)
    return {"module": "response.linux.reset_password", "status": "error",
            "timestamp": datetime.now().isoformat(), "message": msg, "findings": [], "actions": []}
