"""
Response / SOAR — Disable Compromised Account
===============================================
Immediately disables an Active Directory account identified as compromised,
preventing further authentication and lateral movement.

Uses LDAP operations (works from Kali/Linux), not local PowerShell.

Actions performed:
    1. Verify the account exists and is currently enabled
    2. Disable the account via LDAP (set userAccountControl flag)
    3. Set the account description to record the disable event and reason
    4. Optionally force password change at next logon

Event IDs generated:
    - 4725: User account disabled
"""

import json
from datetime import datetime

from core.config import Config
from utils.format_utils import print_info, print_success, print_warning, print_error


def run(username: str = None, reason: str = "Compte désactivé suite à détection SIEM",
        force_pwd_change: bool = True, domain: str = None, user: str = None, 
        password: str = None, **kwargs) -> dict:
    """
    Disable a compromised AD account via LDAP (works from Kali).

    Args:
        username: Target account to disable
        reason: Text reason recorded in account description
        force_pwd_change: Force password change at next logon
        domain, user, password: Override Config for auth
    """
    if not username:
        return _error("Paramètre 'username' requis.")

    print_info(f"[RESPONSE] Désactivation du compte : {username}")
    actions  = []
    findings = []

    # Load config and apply overrides
    cfg = Config()
    domain = domain or cfg.domain
    user = user or cfg.domain_user
    password = password or cfg.domain_password

    try:
        import ldap3
        
        # Step 1: Connect to LDAP
        dc_ip = cfg.dc_ip
        server = ldap3.Server(dc_ip, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=f"{user}@{domain}", password=password, auto_bind=True)
        
        base_dn = ",".join([f"DC={p}" for p in domain.split(".")])
        
        # Step 2: Find account
        conn.search(base_dn, f"(sAMAccountName={username})", attributes=["userAccountControl", "dn"])
        
        if not conn.entries:
            return _error(f"Compte '{username}' introuvable dans l'AD.")
        
        entry = conn.entries[0]
        dn = entry.entry_dn
        uac = int(entry.userAccountControl.value or 512)
        
        # Check if already disabled (flag 2 = ACCOUNTDISABLE)
        if uac & 2:
            print_warning(f"Le compte '{username}' est déjà désactivé.")
            conn.unbind()
            return _build_result("already_disabled", username, actions, findings)
        
        # Step 3: Disable the account (set ACCOUNTDISABLE flag)
        new_uac = uac | 2
        conn.modify(dn, {"userAccountControl": [(ldap3.MODIFY_REPLACE, [str(new_uac)])]})
        
        if conn.result["result"] == 0:
            print_success(f"Compte '{username}' désactivé avec succès.")
            actions.append({
                "action":    "disable_account",
                "target":    username,
                "timestamp": datetime.now().isoformat(),
                "status":    "success",
            })
            findings.append({
                "risk":        "Info",
                "title":       f"Compte désactivé : {username}",
                "description": f"Raison : {reason}. Désactivé le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.",
                "mitigation":  "Investiguer la compromission avant de réactiver le compte.",
                "event_ids":   [4725],
            })
        else:
            print_error(f"Échec de la désactivation de '{username}': {conn.result}")
            findings.append({
                "risk":        "Élevé",
                "title":       f"Échec de désactivation : {username}",
                "description": f"Erreur LDAP : {conn.result['message']}",
                "mitigation":  f"Désactiver manuellement via AD Users & Computers.",
                "event_ids":   [],
            })
            conn.unbind()
            return _build_result("failed", username, actions, findings)
        
        # Step 4: Set description
        conn.modify(dn, {"description": [(ldap3.MODIFY_REPLACE, [reason[:255]])]})
        
        # Step 5: Optionally force password change at next logon
        if force_pwd_change:
            conn.modify(dn, {"pwdLastSet": [(ldap3.MODIFY_REPLACE, ["0"])]})
            print_info(f"  → Mot de passe changement forcé à la prochaine connexion.")
        
        conn.unbind()
        return _build_result("success", username, actions, findings)

    except ImportError:
        return _error("ldap3 library not available. Install: pip install ldap3")
    except Exception as e:
        return _error(f"Erreur LDAP : {str(e)}")
    except Exception as e:
        return _error(f"Erreur lors de la désactivation : {str(e)}")


def _error(message: str) -> dict:
    """Build an error result."""
    print_error(message)
    return {
        "status":   "error",
        "message":  message,
        "actions":  [],
        "findings": [],
    }


def _build_result(status: str, username: str, actions: list, findings: list) -> dict:
    """Build a standard result dict."""
    return {
        "status":    status,
        "module":    "response.disable_user",
        "timestamp": datetime.now().isoformat(),
        "target":    username,
        "actions":   actions,
        "findings":  findings,
        "summary": {
            "actions_executed": len(actions),
            "findings_generated": len(findings),
        }
    }
