"""
Response / SOAR — Désactivation d'un compte utilisateur AD compromis.
Action de remédiation immédiate après détection d'une compromission.
"""

import subprocess
import json
from datetime import datetime

from utils.format_utils import print_info, print_success, print_warning, print_error


def run(username: str = None, reason: str = "Compte désactivé suite à détection SIEM",
        notify: bool = True, **kwargs) -> dict:
    """
    1. Vérifier que le compte existe et est actif
    2. Désactiver le compte
    3. Révoquer les sessions actives (optionnel)
    4. Journaliser l'action
    """
    if not username:
        return _error("Paramètre 'username' requis.")

    print_info(f"[RESPONSE] Désactivation du compte : {username}")
    actions  = []
    findings = []

    # Step 1: Check account exists
    account = _get_account_info(username)
    if not account:
        return _error(f"Compte '{username}' introuvable dans l'AD.")

    if not account.get("Enabled", True):
        print_warning(f"Le compte '{username}' est déjà désactivé.")
        return _build_result("already_disabled", username, actions, findings)

    # Step 2: Disable the account
    success = _disable_account(username)
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
    else:
        print_error(f"Échec de la désactivation de '{username}'.")
        findings.append({
            "risk":        "Élevé",
            "title":       f"Échec de désactivation : {username}",
            "description": "La désactivation automatique a échoué — intervention manuelle requise.",
            "mitigation":  f"Désactiver manuellement : Disable-ADAccount -Identity {username}",
            "event_ids":   [],
        })
        return _build_result("failed", username, actions, findings)

    # Step 3: Kill active sessions
    sessions_killed = _kill_user_sessions(username)
    if sessions_killed:
        actions.append({
            "action":    "kill_sessions",
            "target":    username,
            "timestamp": datetime.now().isoformat(),
            "status":    "success",
            "detail":    f"{sessions_killed} session(s) terminée(s)",
        })
        print_success(f"{sessions_killed} session(s) active(s) terminée(s).")

    # Step 4: Add description/note to account
    _set_account_description(username, reason)

    return _build_result("success", username, actions, findings)


# ── Private ───────────────────────────────────────────────────────────────────

def _get_account_info(username: str) -> dict | None:
    out = _ps(
        f"Get-ADUser -Identity '{username}' -Properties Enabled,DistinguishedName "
        "| Select-Object SamAccountName,Enabled,DistinguishedName | ConvertTo-Json"
    )
    if out:
        try:
            return json.loads(out)
        except Exception:
            pass
    return None


def _disable_account(username: str) -> bool:
    out = _ps(f"Disable-ADAccount -Identity '{username}'; 'ok'")
    return out is not None and "ok" in out.lower()


def _kill_user_sessions(username: str) -> int:
    """Log off active sessions for the user on all domain computers."""
    count = 0
    try:
        # Query sessions on DC
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"$sessions = query user /server:localhost 2>$null | "
             f"Where-Object {{$_ -like '*{username}*'}}; "
             "$sessions | ForEach-Object {{ "
             "$id = ($_ -split ' +')[2]; "
             "logoff $id /server:localhost 2>$null }}; "
             "($sessions | Measure-Object).Count"
             ],
            capture_output=True, text=True, timeout=15
        )
        val = result.stdout.strip()
        if val.isdigit():
            count = int(val)
    except Exception:
        pass
    return count


def _set_account_description(username: str, reason: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    _ps(f"Set-ADUser -Identity '{username}' -Description '[SIEM AUTO-DISABLED {ts}] {reason}'")


def _ps(cmd: str) -> str | None:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=20
        )
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    except Exception:
        return None


def _build_result(status: str, username: str, actions: list, findings: list) -> dict:
    return {
        "module":    "response.disable_user",
        "status":    status,
        "timestamp": datetime.now().isoformat(),
        "target":    username,
        "findings":  findings,
        "actions":   actions,
        "summary": {
            "account":        username,
            "result":         status,
            "actions_taken":  len(actions),
        },
    }


def _error(msg: str) -> dict:
    print_error(msg)
    return {
        "module":    "response.disable_user",
        "status":    "error",
        "timestamp": datetime.now().isoformat(),
        "message":   msg,
        "findings":  [],
        "actions":   [],
    }
