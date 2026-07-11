"""
Blue Team — Password Audit via LDAP
"""
import json
from datetime import datetime, timedelta
from utils.format_utils import print_info, print_success


def run_audit(**kwargs) -> dict:
    """
    Run the password-policy audit over LDAP.

    Checks domain password policy (length/history/lockout), accounts with
    PasswordNeverExpires, accounts with no password required, and stale
    (>180 day) passwords.

    Returns:
        dict: Standard module result with 'findings' and a 'summary'.
    """
    print_info("Audit des mots de passe AD en cours...")
    findings = []
    cfg = _load_config()
    dc_ip    = cfg.get("dc_ip", "192.168.56.12")
    domain   = cfg.get("domain", "essos.local")
    user     = cfg.get("domain_user", "vagrant")
    password = cfg.get("domain_password", "vagrant")
    try:
        import ldap3
        server   = ldap3.Server(dc_ip, get_info=ldap3.ALL)
        bind_user = f"{user}@{domain}"
        conn     = ldap3.Connection(server, user=bind_user, password=password, auto_bind=True)
        base_dn  = ",".join([f"DC={part}" for part in domain.split(".")])
        findings += _check_password_policy(conn, base_dn)
        findings += _check_password_never_expires(conn, base_dn)
        findings += _check_empty_passwords(conn, base_dn)
        findings += _check_stale_passwords(conn, base_dn)
    except Exception as e:
        findings.append({
            "risk": "Info",
            "title": f"Connexion LDAP échouée : {e}",
            "description": f"DC: {dc_ip}, Domain: {domain}",
            "mitigation": "Vérifier les credentials et la connectivité",
            "event_ids": [],
        })
    critical = sum(1 for f in findings if f["risk"] in ("Critique", "Élevé"))
    status   = "warning" if critical else "success"
    print_success(f"Audit terminé — {len(findings)} finding(s), {critical} critique(s)/élevé(s).")
    return {
        "module":    "blue_team.audit_passwords",
        "status":    status,
        "timestamp": datetime.now().isoformat(),
        "findings":  findings,
        "summary":   {"total": len(findings), "critical": critical}
    }


def _check_password_policy(conn, base_dn) -> list:
    """Check the domain-wide password policy: minimum length, history depth, lockout threshold."""
    findings = []
    conn.search(base_dn, "(objectClass=domain)",
                attributes=["minPwdLength", "pwdHistoryLength", "lockoutThreshold"])
    if conn.entries:
        entry   = conn.entries[0]
        min_len = int(entry.minPwdLength.value or 0)
        history = int(entry.pwdHistoryLength.value or 0)
        lockout = int(entry.lockoutThreshold.value or 0)
        if min_len < 12:
            findings.append({
                "risk": "Élevé",
                "title": f"Longueur minimale insuffisante ({min_len} car.)",
                "description": f"MinPasswordLength = {min_len} (recommandé >= 12)",
                "mitigation": "GPO Default Domain Policy → MinPasswordLength >= 12",
                "event_ids": [],
            })
        if history < 10:
            findings.append({
                "risk": "Moyen",
                "title": f"Historique insuffisant ({history})",
                "description": f"PasswordHistoryCount = {history} (recommandé >= 10)",
                "mitigation": "Augmenter PasswordHistoryCount dans la GPO",
                "event_ids": [],
            })
        if lockout == 0:
            findings.append({
                "risk": "Critique",
                "title": "Verrouillage de compte désactivé",
                "description": "LockoutThreshold = 0 — brute force sans blocage",
                "mitigation": "Activer verrouillage <= 10 tentatives",
                "event_ids": [4740],
            })
    return findings


def _check_password_never_expires(conn, base_dn) -> list:
    """Flag active accounts with PasswordNeverExpires set."""
    findings = []
    conn.search(base_dn,
                "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["sAMAccountName"])
    accounts = [str(e.sAMAccountName) for e in conn.entries]
    if accounts:
        findings.append({
            "risk": "Moyen",
            "title": f"{len(accounts)} compte(s) avec mot de passe sans expiration",
            "description": "Comptes : " + ", ".join(accounts[:10]),
            "mitigation": "Désactiver PasswordNeverExpires sauf pour les gMSA",
            "event_ids": [],
        })
    return findings


def _check_empty_passwords(conn, base_dn) -> list:
    """Flag active accounts with the PasswordNotRequired flag set."""
    findings = []
    conn.search(base_dn,
                "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["sAMAccountName"])
    accounts = [str(e.sAMAccountName) for e in conn.entries]
    if accounts:
        findings.append({
            "risk": "Critique",
            "title": f"{len(accounts)} compte(s) sans mot de passe requis",
            "description": "Comptes : " + ", ".join(accounts),
            "mitigation": "Supprimer le flag PasswordNotRequired immédiatement",
            "event_ids": [4723, 4724],
        })
    return findings


def _check_stale_passwords(conn, base_dn) -> list:
    """Flag active accounts whose password hasn't been changed in over 180 days."""
    findings = []
    threshold = datetime.now() - timedelta(days=180)
    ldap_time = threshold.strftime("%Y%m%d%H%M%S") + ".0Z"
    conn.search(base_dn,
                "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["sAMAccountName", "pwdLastSet"])
    stale = []
    for entry in conn.entries:
        try:
            pwd = entry.pwdLastSet.value
            if pwd and hasattr(pwd, "replace"):
                age_days = (datetime.now() - pwd.replace(tzinfo=None)).days
                if age_days > 180:
                    stale.append(str(entry.sAMAccountName))
        except Exception:
            pass
    accounts = stale
    if accounts:
        findings.append({
            "risk": "Moyen",
            "title": f"{len(accounts)} compte(s) avec mot de passe > 180 jours",
            "description": "Comptes : " + ", ".join(accounts[:10]),
            "mitigation": "Forcer la réinitialisation et activer la rotation automatique",
            "event_ids": [],
        })
    return findings


def _load_config() -> dict:
    """Load config.yaml via the centralized loader (core.config.load_config)."""
    from core.config import load_config
    return load_config()
