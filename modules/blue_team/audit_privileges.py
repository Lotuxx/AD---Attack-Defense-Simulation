"""
Blue Team — Privileged Account Audit via LDAP
"""
from datetime import datetime, timedelta
from utils.format_utils import print_info, print_success


def run_audit(**kwargs) -> dict:
    """
    Run the privileged-account audit over LDAP.

    Checks membership of privileged groups, the built-in Guest account,
    service accounts with non-expiring passwords, and stale Domain Admins.

    Returns:
        dict: Standard module result with 'findings' and a 'summary'.
    """
    print_info("Audit des comptes à privilèges AD...")
    findings = []
    cfg      = _load_config()
    dc_ip    = cfg.get("dc_ip", "192.168.56.12")
    domain   = cfg.get("domain", "essos.local")
    user     = cfg.get("domain_user", "vagrant")
    password = cfg.get("domain_password", "vagrant")

    try:
        import ldap3
        server  = ldap3.Server(dc_ip, get_info=ldap3.ALL)
        conn    = ldap3.Connection(server, user=f"{user}@{domain}", password=password, auto_bind=True)
        base_dn = ",".join([f"DC={p}" for p in domain.split(".")])

        findings += _check_domain_admins(conn, base_dn)
        findings += _check_guest_account(conn, base_dn)
        findings += _check_service_accounts(conn, base_dn)
        findings += _check_inactive_admins(conn, base_dn)

    except Exception as e:
        findings.append({
            "risk": "Info",
            "title": f"Connexion LDAP échouée : {e}",
            "description": f"DC: {dc_ip}, Domain: {domain}",
            "mitigation": "Vérifier les credentials et la connectivité",
            "event_ids": [],
        })

    critical = sum(1 for f in findings if f["risk"] in ("Critique", "Élevé"))
    print_success(f"Audit privilèges terminé — {len(findings)} finding(s).")
    return {
        "module":    "blue_team.audit_privileges",
        "status":    "warning" if critical else "success",
        "timestamp": datetime.now().isoformat(),
        "findings":  findings,
        "summary":   {"total": len(findings), "critical": critical}
    }


def _check_domain_admins(conn, base_dn) -> list:
    """Flag privileged groups (Domain Admins, Enterprise Admins, ...) with too many active members, and disabled accounts still listed as members."""
    findings = []
    privileged_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]
    for group in privileged_groups:
        conn.search(base_dn,
                    f"(&(objectClass=user)(memberOf=CN={group},CN=Users,{base_dn}))",
                    attributes=["sAMAccountName", "userAccountControl"])
        members = []
        for entry in conn.entries:
            uac = int(entry.userAccountControl.value or 0)
            disabled = bool(uac & 2)
            members.append({"name": str(entry.sAMAccountName), "disabled": disabled})

        if members:
            disabled = [m["name"] for m in members if m["disabled"]]
            active   = [m["name"] for m in members if not m["disabled"]]
            if len(active) > 5:
                findings.append({
                    "risk": "Élevé",
                    "title": f"{len(active)} comptes actifs dans {group}",
                    "description": "Comptes : " + ", ".join(active[:10]),
                    "mitigation": "Réduire le nombre d'admins. Appliquer le principe de moindre privilège.",
                    "event_ids": [4728, 4732],
                })
            if disabled:
                findings.append({
                    "risk": "Moyen",
                    "title": f"{len(disabled)} compte(s) désactivé(s) encore dans {group}",
                    "description": "Comptes : " + ", ".join(disabled),
                    "mitigation": "Supprimer les comptes désactivés des groupes privilégiés.",
                    "event_ids": [],
                })
    return findings


def _check_guest_account(conn, base_dn) -> list:
    """Flag the built-in Guest account if it hasn't been disabled."""
    findings = []
    conn.search(base_dn,
                "(&(objectClass=user)(sAMAccountName=Guest))",
                attributes=["userAccountControl"])
    for entry in conn.entries:
        uac      = int(entry.userAccountControl.value or 0)
        disabled = bool(uac & 2)
        if not disabled:
            findings.append({
                "risk": "Critique",
                "title": "Compte Guest activé",
                "description": "Le compte Guest est activé — risque d'accès non authentifié.",
                "mitigation": "Désactiver le compte Guest via GPO.",
                "event_ids": [4624],
            })
    return findings


def _check_service_accounts(conn, base_dn) -> list:
    """Flag SPN-bearing service accounts with a non-expiring password (Kerberoasting target)."""
    findings = []
    # Comptes avec SPN (comptes de service) et PasswordNeverExpires
    conn.search(base_dn,
                "(&(objectClass=user)(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
                attributes=["sAMAccountName", "servicePrincipalName"])
    accounts = [str(e.sAMAccountName) for e in conn.entries]
    if accounts:
        findings.append({
            "risk": "Élevé",
            "title": f"{len(accounts)} compte(s) de service avec mot de passe sans expiration",
            "description": "Comptes SPN : " + ", ".join(accounts[:10]),
            "mitigation": "Utiliser des gMSA (Group Managed Service Accounts) avec rotation automatique.",
            "event_ids": [4769],
        })
    return findings


def _check_inactive_admins(conn, base_dn) -> list:
    """Flag Domain Admins accounts with no logon in the last 90 days."""
    findings = []
    threshold = datetime.now() - timedelta(days=90)
    ldap_time = threshold.strftime("%Y%m%d%H%M%S") + ".0Z"
    conn.search(base_dn,
                f"(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,{base_dn})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["sAMAccountName", "lastLogonTimestamp"])
    accounts = []
    for entry in conn.entries:
        try:
            last = entry.lastLogonTimestamp.value
            if last and hasattr(last, "replace"):
                if (datetime.now() - last.replace(tzinfo=None)).days > 90:
                    accounts.append(str(entry.sAMAccountName))
            elif not last:
                accounts.append(str(entry.sAMAccountName))
        except Exception:
            accounts.append(str(entry.sAMAccountName))
    if accounts:
        findings.append({
            "risk": "Moyen",
            "title": f"{len(accounts)} admin(s) inactif(s) depuis 90 jours",
            "description": "Comptes : " + ", ".join(accounts[:10]),
            "mitigation": "Désactiver ou supprimer les comptes admin inactifs.",
            "event_ids": [],
        })
    return findings


def _load_config() -> dict:
    """Load config.yaml via the centralized loader (core.config.load_config)."""
    from core.config import load_config
    return load_config()
