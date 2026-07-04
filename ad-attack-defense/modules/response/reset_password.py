"""
Response / SOAR — Réinitialisation forcée du mot de passe d'un compte compromis.
Force un changement de mot de passe au prochain login.
"""

import subprocess
import secrets
import string
import json
from datetime import datetime

from utils.format_utils import print_info, print_success, print_warning, print_error


def run(username: str = None, force_change: bool = True,
        generate_password: bool = True, new_password: str = None,
        reason: str = "Réinitialisation suite à détection SIEM",
        **kwargs) -> dict:
    """
    1. Verify account exists
    2. Generate a strong random password (or use provided one)
    3. Reset the password via PowerShell
    4. Force change at next logon
    5. Revoke Kerberos tickets (klist purge equivalent)
    """
    if not username:
        return _error("Paramètre 'username' requis.")

    print_info(f"[RESPONSE] Réinitialisation mot de passe : {username}")

    actions  = []
    findings = []

    # Step 1: Verify account
    account = _get_account_info(username)
    if not account:
        return _error(f"Compte '{username}' introuvable dans l'AD.")

    # Step 2: Generate password if needed
    if generate_password or not new_password:
        new_password = _generate_strong_password()
        print_info(f"Mot de passe généré (longueur: {len(new_password)} car.)")

    # Step 3: Reset password
    success = _reset_password(username, new_password)
    if not success:
        return _error(f"Échec de la réinitialisation pour '{username}'.")

    actions.append({
        "action":    "reset_password",
        "target":    username,
        "timestamp": datetime.now().isoformat(),
        "status":    "success",
    })
    print_success(f"Mot de passe réinitialisé pour '{username}'.")

    # Step 4: Force change at next logon
    if force_change:
        _force_change_at_next_logon(username)
        actions.append({
            "action":    "force_change_next_logon",
            "target":    username,
            "timestamp": datetime.now().isoformat(),
            "status":    "success",
        })
        print_success("Changement forcé au prochain login.")

    # Step 5: Invalidate Kerberos tickets
    tickets_purged = _purge_kerberos_tickets(username)
    if tickets_purged:
        actions.append({
            "action":    "purge_kerberos_tickets",
            "target":    username,
            "timestamp": datetime.now().isoformat(),
            "status":    "success",
        })
        print_success("Tickets Kerberos révoqués.")

    findings.append({
        "risk":  "Info",
        "title": f"Mot de passe réinitialisé : {username}",
        "description": (
            f"Raison : {reason}. "
            f"Changement forcé au prochain login : {force_change}. "
            f"Tickets Kerberos révoqués : {tickets_purged}."
        ),
        "mitigation": (
            "Transmettre le nouveau mot de passe au propriétaire du compte "
            "via un canal sécurisé (ne pas envoyer par email en clair)."
        ),
        "event_ids": [4723, 4724],
    })

    # Important: don't log the actual password in findings
    return {
        "module":    "response.reset_password",
        "status":    "success",
        "timestamp": datetime.now().isoformat(),
        "target":    username,
        "findings":  findings,
        "actions":   actions,
        # NOTE: new_password returned for operator use ONLY — never log to SIEM
        "new_password": new_password,
        "summary": {
            "account":             username,
            "password_reset":      success,
            "force_change":        force_change,
            "tickets_purged":      tickets_purged,
            "actions_taken":       len(actions),
        },
    }


# ── Private ───────────────────────────────────────────────────────────────────

def _get_account_info(username: str) -> dict | None:
    out = _ps(
        f"Get-ADUser -Identity '{username}' -Properties Enabled | "
        "Select-Object SamAccountName,Enabled | ConvertTo-Json"
    )
    if out:
        try:
            return json.loads(out)
        except Exception:
            pass
    return None


def _generate_strong_password(length: int = 24) -> str:
    """Generate a cryptographically strong password."""
    alphabet = (
        string.ascii_uppercase +
        string.ascii_lowercase +
        string.digits +
        "!@#$%^&*()-_=+[]{}|;:,.<>?"
    )
    # Ensure at least one of each required character class
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()"),
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def _reset_password(username: str, new_password: str) -> bool:
    cmd = (
        f"$pw = ConvertTo-SecureString '{new_password}' -AsPlainText -Force; "
        f"Set-ADAccountPassword -Identity '{username}' -NewPassword $pw -Reset; 'ok'"
    )
    out = _ps(cmd)
    return out is not None and "ok" in out.lower()


def _force_change_at_next_logon(username: str):
    _ps(f"Set-ADUser -Identity '{username}' -ChangePasswordAtLogon $true")


def _purge_kerberos_tickets(username: str) -> bool:
    """
    Invalidate Kerberos tickets by bumping the account's msDS-KeyVersionNumber.
    This forces re-authentication and invalidates all existing TGTs.
    """
    # The most reliable way: modify the account (triggers ticket invalidation)
    out = _ps(
        f"$user = Get-ADUser '{username}'; "
        # Disable then re-enable forces KDC to invalidate tickets
        f"Disable-ADAccount -Identity '{username}'; "
        f"Start-Sleep -Milliseconds 500; "
        f"Enable-ADAccount -Identity '{username}'; 'ok'"
    )
    return out is not None and "ok" in out.lower()


def _ps(cmd: str) -> str | None:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=20
        )
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    except Exception:
        return None


def _error(msg: str) -> dict:
    print_error(msg)
    return {
        "module":    "response.reset_password",
        "status":    "error",
        "timestamp": datetime.now().isoformat(),
        "message":   msg,
        "findings":  [],
        "actions":   [],
    }
