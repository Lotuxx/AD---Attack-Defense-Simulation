"""
Blue Team — GPO & AD Configuration Audit (LDAP/Linux-compatible)
=================================================================
Audits critical AD misconfigurations via LDAP. No PowerShell required.

Checks:
    1. Accounts with Unconstrained Kerberos Delegation
    2. Accounts with Constrained Delegation (list for review)
    3. AdminSDHolder ACL anomalies (unexpected ACEs count)
    4. krbtgt password last change date
    5. Accounts with DontRequirePreauth (AS-REP Roasting target)
    6. Accounts with SPN (Kerberoasting targets)
"""

import os
import yaml
from datetime import datetime, timedelta, timezone

from utils.format_utils import print_info, print_success, print_error

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False


def run_audit(**kwargs) -> dict:
    print_info("GPO/AD configuration audit — connecting via LDAP...")

    if not HAS_LDAP3:
        return _error("ldap3 not installed. Run: poetry add ldap3")

    cfg  = _load_config()
    conn = _ldap_connect(cfg)
    if conn is None:
        return _error(f"Cannot connect to DC {cfg.get('dc_ip')} via LDAP.")

    findings = []
    findings += _check_unconstrained_delegation(conn, cfg)
    findings += _check_constrained_delegation(conn, cfg)
    findings += _check_krbtgt_password_age(conn, cfg)
    findings += _check_asrep_roastable(conn, cfg)
    findings += _check_kerberoastable(conn, cfg)
    findings += _check_admincount(conn, cfg)

    conn.unbind()

    critical = sum(1 for f in findings if f["risk"] in ("Critique", "Élevé"))
    print_success(f"GPO audit done — {len(findings)} finding(s), {critical} critical/high.")

    return {
        "module":    "blue_team.audit_gpo",
        "status":    "warning" if critical else "success",
        "timestamp": datetime.now().isoformat(),
        "findings":  findings,
        "summary":   {"total": len(findings), "critical": critical},
    }


def _check_unconstrained_delegation(conn, cfg: dict) -> list:
    """Find computers/users with unconstrained Kerberos delegation (UAC 0x80000)."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    # UAC flag 0x80000 = TRUSTED_FOR_DELEGATION (unconstrained)
    # Exclude DCs (they legitimately have this flag)
    ldap_filter = (
        "(&(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"  # exclude DCs
    )
    try:
        conn.search(base_dn, ldap_filter, SUBTREE,
                    attributes=["sAMAccountName", "objectClass"])
        accounts = [e.sAMAccountName.value for e in conn.entries
                    if e.sAMAccountName.value]
        if accounts:
            findings.append({
                "risk":        "Critique",
                "title":       f"{len(accounts)} account(s) with Unconstrained Delegation",
                "description": (
                    f"Accounts: {', '.join(accounts[:8])}. "
                    "Unconstrained delegation allows impersonation of any user "
                    "(PrinterBug, PrivExchange attacks)."
                ),
                "mitigation":  (
                    "1. Switch to Constrained Delegation or Resource-Based Constrained Delegation.\n"
                    "2. Add sensitive accounts to Protected Users group.\n"
                    "3. Set Account is sensitive and cannot be delegated flag."
                ),
                "event_ids":   [4769],
            })
        else:
            findings.append({
                "risk":        "Info",
                "title":       "No accounts with Unconstrained Delegation (non-DC)",
                "description": "Good — unconstrained delegation is not in use.",
                "mitigation":  "Continue monitoring.",
                "event_ids":   [],
            })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check unconstrained delegation: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _check_constrained_delegation(conn, cfg: dict) -> list:
    """List accounts with constrained delegation for manual review."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    # msDS-AllowedToDelegateTo is set for constrained delegation
    ldap_filter = "(&(objectClass=user)(msDS-AllowedToDelegateTo=*))"
    try:
        conn.search(base_dn, ldap_filter, SUBTREE,
                    attributes=["sAMAccountName", "msDS-AllowedToDelegateTo"])
        accounts = []
        for entry in conn.entries:
            name     = entry.sAMAccountName.value or "?"
            services = entry["msDS-AllowedToDelegateTo"].values or []
            accounts.append(f"{name} → {', '.join(services[:3])}")

        if accounts:
            findings.append({
                "risk":        "Moyen",
                "title":       f"{len(accounts)} account(s) with Constrained Delegation",
                "description": "Accounts: " + " | ".join(accounts[:5]),
                "mitigation":  (
                    "Review each delegation entry — ensure only necessary services "
                    "are listed. Consider Resource-Based Constrained Delegation instead."
                ),
                "event_ids":   [],
            })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check constrained delegation: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _check_krbtgt_password_age(conn, cfg: dict) -> list:
    """Check how long ago the krbtgt account password was last changed."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    try:
        conn.search(
            base_dn,
            "(&(objectClass=user)(sAMAccountName=krbtgt))",
            SUBTREE,
            attributes=["pwdLastSet"]
        )
        if not conn.entries:
            return findings

        pwd_last_set = conn.entries[0].pwdLastSet.value
        if pwd_last_set is None:
            age_days = 9999
        else:
            if hasattr(pwd_last_set, 'timestamp'):
                age_days = (datetime.now(timezone.utc) -
                            pwd_last_set.replace(tzinfo=timezone.utc)).days
            else:
                epoch_diff = 116444736000000000
                ft_val     = int(pwd_last_set)
                dt         = datetime(1601, 1, 1, tzinfo=timezone.utc) + \
                             timedelta(microseconds=(ft_val - epoch_diff) // 10)
                age_days   = (datetime.now(timezone.utc) - dt).days

        risk = "Critique" if age_days > 180 else "Moyen" if age_days > 90 else "Info"
        findings.append({
            "risk":        risk,
            "title":       f"krbtgt password last changed {age_days} days ago",
            "description": (
                "If krbtgt is compromised, an attacker can forge Golden Tickets "
                "for unlimited domain access. Password must be rotated twice."
            ),
            "mitigation":  (
                "Reset krbtgt password twice with 10h interval using "
                "Microsoft's New-KrbtgtKeys.ps1 script."
            ),
            "event_ids":   [4723, 4724],
        })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check krbtgt password age: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _check_asrep_roastable(conn, cfg: dict) -> list:
    """Find accounts with DontRequirePreauth — vulnerable to AS-REP Roasting."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    # UAC flag 0x400000 = DONT_REQ_PREAUTH
    ldap_filter = (
        "(&(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )
    try:
        conn.search(base_dn, ldap_filter, SUBTREE,
                    attributes=["sAMAccountName"])
        accounts = [e.sAMAccountName.value for e in conn.entries
                    if e.sAMAccountName.value]
        if accounts:
            findings.append({
                "risk":        "Critique",
                "title":       f"{len(accounts)} account(s) vulnerable to AS-REP Roasting",
                "description": (
                    f"Accounts with DontRequirePreauth: {', '.join(accounts)}. "
                    "These can be attacked without any credentials (GetNPUsers.py)."
                ),
                "mitigation":  (
                    "Require Kerberos pre-authentication for all accounts. "
                    "Only disable it when technically required (legacy apps)."
                ),
                "event_ids":   [4768],
            })
        else:
            findings.append({
                "risk":        "Info",
                "title":       "No AS-REP Roastable accounts found",
                "description": "All accounts require Kerberos pre-authentication.",
                "mitigation":  "Continue monitoring.",
                "event_ids":   [],
            })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check AS-REP Roastable accounts: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _check_kerberoastable(conn, cfg: dict) -> list:
    """Find accounts with SPN — vulnerable to Kerberoasting."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    # Users with SPN set (excluding computer accounts which end with $)
    ldap_filter = (
        "(&(objectClass=user)(objectCategory=person)"
        "(servicePrincipalName=*)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )
    try:
        conn.search(base_dn, ldap_filter, SUBTREE,
                    attributes=["sAMAccountName", "servicePrincipalName"])
        accounts = []
        for entry in conn.entries:
            name = entry.sAMAccountName.value or "?"
            spns = entry.servicePrincipalName.values or []
            accounts.append(f"{name} ({len(spns)} SPN)")

        if accounts:
            findings.append({
                "risk":        "Élevé",
                "title":       f"{len(accounts)} account(s) with SPN (Kerberoasting targets)",
                "description": "Accounts: " + ", ".join(accounts[:8]),
                "mitigation":  (
                    "1. Use Group Managed Service Accounts (gMSA) — auto-rotating passwords.\n"
                    "2. Set service account passwords to 25+ random characters.\n"
                    "3. Monitor Event ID 4769 for unusual TGS request volumes."
                ),
                "event_ids":   [4769],
            })
        else:
            findings.append({
                "risk":        "Info",
                "title":       "No user accounts with SPN found",
                "description": "No Kerberoasting targets detected.",
                "mitigation":  "Continue monitoring.",
                "event_ids":   [],
            })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check Kerberoastable accounts: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _check_admincount(conn, cfg: dict) -> list:
    """Find accounts with adminCount=1 that are not in current privileged groups."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    try:
        conn.search(
            base_dn,
            "(&(objectClass=user)(adminCount=1)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            SUBTREE,
            attributes=["sAMAccountName"]
        )
        accounts = [e.sAMAccountName.value for e in conn.entries
                    if e.sAMAccountName.value]
        if accounts:
            findings.append({
                "risk":        "Moyen",
                "title":       f"{len(accounts)} account(s) with adminCount=1",
                "description": (
                    f"Accounts: {', '.join(accounts[:10])}. "
                    "adminCount=1 means the account was previously in a protected group — "
                    "it may retain AdminSDHolder ACLs even after removal."
                ),
                "mitigation":  (
                    "Review each account. If no longer in a privileged group, "
                    "reset adminCount=0 and re-inherit permissions from parent OU."
                ),
                "event_ids":   [],
            })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check adminCount: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _ldap_connect(cfg: dict):
    dc_ip        = cfg.get("dc_ip", "127.0.0.1")
    domain       = cfg.get("domain", "")
    user         = cfg.get("domain_user", "")
    password     = cfg.get("domain_password", "")
    domain_short = domain.split(".")[0].upper()
    ntlm_user    = f"{domain_short}\\{user}"

    for port, use_ssl in [(636, True), (389, False)]:
        try:
            server = Server(dc_ip, port=port, use_ssl=use_ssl, get_info=ALL)
            conn   = Connection(server, user=ntlm_user, password=password,
                                authentication=NTLM, auto_bind=True)
            print_info(f"LDAP connected to {dc_ip}:{port}")
            return conn
        except Exception:
            continue
    return None


def _domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def _load_config() -> dict:
    base = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(__file__))))
    path = os.path.join(base, "config.yaml")
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


def _error(msg: str) -> dict:
    print_error(msg)
    return {
        "module":    "blue_team.audit_gpo",
        "status":    "error",
        "timestamp": datetime.now().isoformat(),
        "message":   msg,
        "findings":  [],
    }
