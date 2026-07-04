"""
Blue Team — Privileged Account Audit (LDAP/Linux-compatible)
=============================================================
Audits privileged AD accounts and group memberships via LDAP.
No PowerShell required.

Checks:
    1. Domain Admins / Enterprise Admins / Schema Admins membership
    2. Disabled accounts still in privileged groups
    3. Service accounts with admin rights
    4. Guest account status
    5. Built-in Administrator rename status
    6. Inactive privileged accounts (no logon in 90+ days)
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

# Well-known SIDs for built-in privileged groups
PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Group Policy Creator Owners",
]


def run_audit(**kwargs) -> dict:
    print_info("Privileged account audit — connecting via LDAP...")

    if not HAS_LDAP3:
        return _error("ldap3 not installed. Run: poetry add ldap3")

    cfg  = _load_config()
    conn = _ldap_connect(cfg)
    if conn is None:
        return _error(f"Cannot connect to DC {cfg.get('dc_ip')} via LDAP.")

    findings = []
    findings += _check_privileged_groups(conn, cfg)
    findings += _check_guest_account(conn, cfg)
    findings += _check_admin_renamed(conn, cfg)
    findings += _check_inactive_admins(conn, cfg)

    conn.unbind()

    critical = sum(1 for f in findings if f["risk"] in ("Critique", "Élevé"))
    print_success(f"Privilege audit done — {len(findings)} finding(s), {critical} critical/high.")

    return {
        "module":    "blue_team.audit_privileges",
        "status":    "warning" if critical else "success",
        "timestamp": datetime.now().isoformat(),
        "findings":  findings,
        "summary":   {"total": len(findings), "critical": critical},
    }


def _check_privileged_groups(conn, cfg: dict) -> list:
    """Enumerate members of privileged groups and flag risks."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    for group_name in PRIVILEGED_GROUPS:
        ldap_filter = f"(&(objectClass=group)(cn={group_name}))"
        try:
            conn.search(base_dn, ldap_filter, SUBTREE,
                        attributes=["member", "cn"])
            if not conn.entries:
                continue

            entry   = conn.entries[0]
            members = entry.member.values if entry.member else []

            if not members:
                continue

            # Resolve each member DN to get account details
            all_members  = []
            svc_accounts = []
            disabled     = []

            for member_dn in members:
                conn.search(
                    member_dn,
                    "(objectClass=*)",
                    ldap3.BASE,
                    attributes=["sAMAccountName", "userAccountControl"]
                )
                if not conn.entries:
                    continue
                m       = conn.entries[0]
                name    = m.sAMAccountName.value or "?"
                uac     = int(m.userAccountControl.value or 0)
                enabled = not bool(uac & 0x2)

                all_members.append(name)
                if not enabled:
                    disabled.append(name)
                if "svc" in name.lower() or "service" in name.lower():
                    svc_accounts.append(name)

            if len(all_members) > 5:
                findings.append({
                    "risk":        "Moyen",
                    "title":       f"'{group_name}' has {len(all_members)} member(s)",
                    "description": "Members: " + ", ".join(all_members[:10]),
                    "mitigation":  "Apply least-privilege. Remove unnecessary members. Use Tier Model.",
                    "event_ids":   [4728, 4732],
                })

            if disabled:
                findings.append({
                    "risk":        "Élevé",
                    "title":       f"Disabled account(s) still in '{group_name}'",
                    "description": "Accounts: " + ", ".join(disabled),
                    "mitigation":  "Remove disabled accounts from privileged groups immediately.",
                    "event_ids":   [4728, 4726],
                })

            if svc_accounts:
                findings.append({
                    "risk":        "Élevé",
                    "title":       f"Service account(s) in '{group_name}'",
                    "description": "Accounts: " + ", ".join(svc_accounts),
                    "mitigation":  "Use gMSA instead. Remove service accounts from admin groups.",
                    "event_ids":   [4728],
                })

        except Exception as e:
            findings.append({
                "risk":        "Info",
                "title":       f"Cannot enumerate '{group_name}': {e}",
                "description": str(e), "mitigation": "", "event_ids": [],
            })

    return findings


def _check_guest_account(conn, cfg: dict) -> list:
    """Check if the built-in Guest account is enabled."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    try:
        # Guest has a well-known RID of 501
        conn.search(
            base_dn,
            "(&(objectClass=user)(objectSid=*-501))",
            SUBTREE,
            attributes=["sAMAccountName", "userAccountControl"]
        )
        for entry in conn.entries:
            uac     = int(entry.userAccountControl.value or 0)
            enabled = not bool(uac & 0x2)
            if enabled:
                findings.append({
                    "risk":        "Élevé",
                    "title":       "Built-in Guest account is enabled",
                    "description": "The Guest account allows anonymous domain access.",
                    "mitigation":  "Disable: net user Guest /active:no (or via LDAP UAC flag).",
                    "event_ids":   [4624],
                })
            else:
                findings.append({
                    "risk":        "Info",
                    "title":       "Guest account is disabled",
                    "description": "Good — built-in Guest is not active.",
                    "mitigation":  "Keep monitoring.",
                    "event_ids":   [],
                })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check Guest account: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _check_admin_renamed(conn, cfg: dict) -> list:
    """Check if the built-in Administrator account (RID 500) has been renamed."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    try:
        conn.search(
            base_dn,
            "(&(objectClass=user)(objectSid=*-500))",
            SUBTREE,
            attributes=["sAMAccountName"]
        )
        for entry in conn.entries:
            name = entry.sAMAccountName.value or ""
            if name.lower() == "administrator":
                findings.append({
                    "risk":        "Moyen",
                    "title":       "Built-in Administrator account not renamed",
                    "description": "Default name 'administrator' is the first target in brute force attacks.",
                    "mitigation":  "Rename via GPO → Account Policies → Rename Administrator Account.",
                    "event_ids":   [],
                })
            else:
                findings.append({
                    "risk":        "Info",
                    "title":       f"Built-in Administrator renamed to '{name}'",
                    "description": "Good — default name has been changed.",
                    "mitigation":  "Consider creating a fake 'administrator' honeypot account.",
                    "event_ids":   [],
                })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check Administrator account: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _check_inactive_admins(conn, cfg: dict) -> list:
    """Find privileged accounts with no logon in the last 90 days."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=90)
    epoch_diff = 116444736000000000
    cutoff_ft  = int(cutoff_dt.timestamp() * 10_000_000) + epoch_diff

    try:
        # Get Domain Admins members first
        conn.search(
            base_dn,
            "(&(objectClass=group)(cn=Domain Admins))",
            SUBTREE,
            attributes=["member"]
        )
        if not conn.entries:
            return findings

        members = conn.entries[0].member.values if conn.entries[0].member else []
        inactive = []

        for member_dn in members:
            conn.search(
                member_dn,
                "(objectClass=*)",
                ldap3.BASE,
                attributes=["sAMAccountName", "lastLogonTimestamp",
                            "userAccountControl"]
            )
            if not conn.entries:
                continue
            m       = conn.entries[0]
            name    = m.sAMAccountName.value or "?"
            uac     = int(m.userAccountControl.value or 0)
            enabled = not bool(uac & 0x2)

            if not enabled:
                continue

            last_logon = m.lastLogonTimestamp.value
            if last_logon is None:
                inactive.append(f"{name} (never logged on)")
            elif hasattr(last_logon, 'timestamp'):
                ts = int(last_logon.timestamp() * 10_000_000) + epoch_diff
                if ts < cutoff_ft:
                    inactive.append(name)
            else:
                try:
                    if int(last_logon) < cutoff_ft:
                        inactive.append(name)
                except Exception:
                    pass

        if inactive:
            findings.append({
                "risk":        "Élevé",
                "title":       f"{len(inactive)} Domain Admin(s) inactive for 90+ days",
                "description": "Accounts: " + ", ".join(inactive[:8]),
                "mitigation":  "Disable or remove stale admin accounts. Review access lifecycle.",
                "event_ids":   [],
            })
        else:
            findings.append({
                "risk":        "Info",
                "title":       "No inactive Domain Admin accounts found",
                "description": "All Domain Admins have logged on within the last 90 days.",
                "mitigation":  "Continue monitoring.",
                "event_ids":   [],
            })

    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check inactive admins: {e}",
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
        "module":    "blue_team.audit_privileges",
        "status":    "error",
        "timestamp": datetime.now().isoformat(),
        "message":   msg,
        "findings":  [],
    }
