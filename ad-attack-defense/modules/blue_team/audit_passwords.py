"""
Blue Team — Password Audit (LDAP/Linux-compatible)
====================================================
Audits Active Directory password policy and risky account configurations
by connecting remotely to the DC via LDAP using ldap3.

No PowerShell required — runs from Kali Linux or any Linux host.

Checks:
    1. Default Domain Password Policy (min length, history, lockout)
    2. Accounts with PasswordNeverExpires
    3. Accounts with PasswordNotRequired (blank passwords allowed)
    4. Active accounts with passwords not changed in 180+ days
"""

import os
import sys
import yaml
from datetime import datetime, timedelta, timezone

from utils.format_utils import print_info, print_warning, print_success, print_error

# ── Optional import — ldap3 must be installed via poetry ──────────────────────
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False


def run_audit(**kwargs) -> dict:
    """
    Main entry point. Connects to the DC via LDAP and runs all password checks.

    Returns:
        dict: Standardised result with status, findings, and summary.
    """
    print_info("Password audit — connecting via LDAP...")

    if not HAS_LDAP3:
        return _error("ldap3 not installed. Run: poetry add ldap3")

    cfg  = _load_config()
    conn = _ldap_connect(cfg)
    if conn is None:
        return _error(f"Cannot connect to DC {cfg.get('dc_ip')} via LDAP.")

    findings = []
    findings += _check_password_policy(conn, cfg)
    findings += _check_password_never_expires(conn, cfg)
    findings += _check_password_not_required(conn, cfg)
    findings += _check_stale_passwords(conn, cfg)

    conn.unbind()

    critical = sum(1 for f in findings if f["risk"] in ("Critique", "Élevé"))
    print_success(f"Password audit done — {len(findings)} finding(s), {critical} critical/high.")

    return {
        "module":    "blue_team.audit_passwords",
        "status":    "warning" if critical else "success",
        "timestamp": datetime.now().isoformat(),
        "findings":  findings,
        "summary":   {"total": len(findings), "critical": critical},
    }


# ── LDAP Checks ───────────────────────────────────────────────────────────────

def _check_password_policy(conn, cfg: dict) -> list:
    """Check Default Domain Password Policy via LDAP rootDSE + domain object."""
    findings = []
    domain   = cfg.get("domain", "")
    base_dn  = _domain_to_dn(domain)

    try:
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=domain)",
            search_scope=ldap3.BASE,
            attributes=[
                "minPwdLength", "pwdHistoryLength",
                "lockoutThreshold", "maxPwdAge", "minPwdAge",
            ]
        )
        if not conn.entries:
            findings.append({
                "risk":        "Info",
                "title":       "Cannot read password policy",
                "description": "No domain object found at base DN.",
                "mitigation":  "Verify domain credentials and DC connectivity.",
                "event_ids":   [],
            })
            return findings

        entry       = conn.entries[0]
        min_len     = int(entry.minPwdLength.value   or 0)
        history     = int(entry.pwdHistoryLength.value or 0)
        lockout     = int(entry.lockoutThreshold.value or 0)

        if min_len < 12:
            findings.append({
                "risk":        "Élevé",
                "title":       f"Minimum password length too short ({min_len} chars)",
                "description": "MinPwdLength < 12 — weak passwords are accepted.",
                "mitigation":  "GPO → Default Domain Policy → MinPasswordLength ≥ 12",
                "event_ids":   [],
            })
        if history < 10:
            findings.append({
                "risk":        "Moyen",
                "title":       f"Password history too short ({history})",
                "description": "Users can reuse old passwords too quickly.",
                "mitigation":  "Set PasswordHistoryCount ≥ 10 in Default Domain Policy.",
                "event_ids":   [],
            })
        if lockout == 0:
            findings.append({
                "risk":        "Critique",
                "title":       "Account lockout disabled (LockoutThreshold = 0)",
                "description": "No lockout means unlimited brute force / spray attempts.",
                "mitigation":  "Set LockoutThreshold ≤ 10 in Default Domain Policy.",
                "event_ids":   [4740],
            })
        if min_len >= 12 and history >= 10 and lockout > 0:
            findings.append({
                "risk":        "Info",
                "title":       "Password policy meets minimum requirements",
                "description": f"MinLen={min_len}, History={history}, Lockout={lockout}.",
                "mitigation":  "Continue monitoring for fine-grained policy exceptions.",
                "event_ids":   [],
            })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Error reading password policy: {e}",
            "description": str(e),
            "mitigation":  "Verify LDAP permissions.",
            "event_ids":   [],
        })
    return findings


def _check_password_never_expires(conn, cfg: dict) -> list:
    """Find enabled accounts where PasswordNeverExpires is set."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    # UAC flag 0x10000 = DONT_EXPIRE_PASSWORD
    # Enabled accounts: !(UAC & 0x2) — bit 0x2 = ACCOUNTDISABLE
    # LDAP filter: enabled + password never expires
    ldap_filter = "(&(objectClass=user)(objectCategory=person)" \
                  "(userAccountControl:1.2.840.113556.1.4.803:=65536)" \
                  "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

    try:
        conn.search(base_dn, ldap_filter, SUBTREE,
                    attributes=["sAMAccountName", "userAccountControl"])
        accounts = [e.sAMAccountName.value for e in conn.entries
                    if e.sAMAccountName.value]
        if accounts:
            findings.append({
                "risk":        "Moyen",
                "title":       f"{len(accounts)} enabled account(s) with PasswordNeverExpires",
                "description": "Accounts: " + ", ".join(accounts[:10]),
                "mitigation":  "Disable PasswordNeverExpires except for gMSA accounts.",
                "event_ids":   [],
            })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check PasswordNeverExpires: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _check_password_not_required(conn, cfg: dict) -> list:
    """Find accounts where PasswordNotRequired flag is set (blank passwords allowed)."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    # UAC flag 0x20 = PASSWD_NOTREQD
    ldap_filter = "(&(objectClass=user)(objectCategory=person)" \
                  "(userAccountControl:1.2.840.113556.1.4.803:=32)" \
                  "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

    try:
        conn.search(base_dn, ldap_filter, SUBTREE,
                    attributes=["sAMAccountName"])
        accounts = [e.sAMAccountName.value for e in conn.entries
                    if e.sAMAccountName.value]
        if accounts:
            findings.append({
                "risk":        "Critique",
                "title":       f"{len(accounts)} account(s) with PasswordNotRequired",
                "description": "Accounts: " + ", ".join(accounts),
                "mitigation":  "Immediately remove the PasswordNotRequired flag.",
                "event_ids":   [4723, 4724],
            })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check PasswordNotRequired: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _check_stale_passwords(conn, cfg: dict) -> list:
    """Find enabled accounts whose password has not changed in 180+ days."""
    findings = []
    base_dn  = _domain_to_dn(cfg.get("domain", ""))

    # pwdLastSet is a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    # Convert 180 days ago to FILETIME for LDAP filter
    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=180)
    # Windows FILETIME epoch offset
    epoch_diff  = 116444736000000000
    cutoff_ft   = int(cutoff_dt.timestamp() * 10_000_000) + epoch_diff

    ldap_filter = (
        f"(&(objectClass=user)(objectCategory=person)"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        f"(pwdLastSet<={cutoff_ft})(!(pwdLastSet=0)))"
    )

    try:
        conn.search(base_dn, ldap_filter, SUBTREE,
                    attributes=["sAMAccountName", "pwdLastSet"])
        accounts = [e.sAMAccountName.value for e in conn.entries
                    if e.sAMAccountName.value]
        if accounts:
            findings.append({
                "risk":        "Moyen",
                "title":       f"{len(accounts)} account(s) with password not changed in 180+ days",
                "description": "Accounts: " + ", ".join(accounts[:10]),
                "mitigation":  "Force password reset and enable automatic rotation policy.",
                "event_ids":   [],
            })
        else:
            findings.append({
                "risk":        "Info",
                "title":       "No accounts with stale passwords (>180 days)",
                "description": "All active accounts have changed passwords within 180 days.",
                "mitigation":  "Continue monitoring.",
                "event_ids":   [],
            })
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check stale passwords: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ldap_connect(cfg: dict):
    """
    Establish an LDAP connection to the DC using NTLM authentication.

    Tries port 636 (LDAPS) first, falls back to 389 (LDAP).
    """
    dc_ip    = cfg.get("dc_ip", "127.0.0.1")
    domain   = cfg.get("domain", "")
    user     = cfg.get("domain_user", "")
    password = cfg.get("domain_password", "")

    # Build NTLM user string: DOMAIN\user
    domain_short = domain.split(".")[0].upper()
    ntlm_user    = f"{domain_short}\\{user}"

    for port, use_ssl in [(636, True), (389, False)]:
        try:
            server = Server(dc_ip, port=port, use_ssl=use_ssl, get_info=ALL)
            conn   = Connection(
                server,
                user=ntlm_user,
                password=password,
                authentication=NTLM,
                auto_bind=True,
            )
            print_info(f"LDAP connected to {dc_ip}:{port} as {ntlm_user}")
            return conn
        except Exception:
            continue

    print_error(f"LDAP connection failed to {dc_ip} (tried 636 and 389)")
    return None


def _domain_to_dn(domain: str) -> str:
    """Convert 'sevenkingdoms.local' → 'DC=sevenkingdoms,DC=local'."""
    return ",".join(f"DC={part}" for part in domain.split("."))


def _load_config() -> dict:
    """Load lab configuration from config.yaml."""
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
        "module":    "blue_team.audit_passwords",
        "status":    "error",
        "timestamp": datetime.now().isoformat(),
        "message":   msg,
        "findings":  [],
    }
