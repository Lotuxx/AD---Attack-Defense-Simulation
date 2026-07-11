"""
Blue Team — GPO & AD Configuration Audit via LDAP
"""
from datetime import datetime
from utils.format_utils import print_info, print_success


def run_audit(**kwargs) -> dict:
    """
    Run the GPO / AD configuration audit over LDAP.

    Checks unconstrained Kerberos delegation, krbtgt password age,
    AdminSDHolder-protected accounts outside privileged groups, and
    AS-REP roastable accounts.

    Returns:
        dict: Standard module result with 'findings' and a 'summary'.
    """
    print_info("Audit des GPO et configurations AD...")
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

        findings += _check_unconstrained_delegation(conn, base_dn)
        findings += _check_krbtgt_password(conn, base_dn)
        findings += _check_adminsdholder(conn, base_dn)
        findings += _check_acl_dangerous(conn, base_dn)

    except Exception as e:
        findings.append({
            "risk": "Info",
            "title": f"Connexion LDAP échouée : {e}",
            "description": f"DC: {dc_ip}, Domain: {domain}",
            "mitigation": "Vérifier les credentials et la connectivité",
            "event_ids": [],
        })

    critical = sum(1 for f in findings if f["risk"] in ("Critique", "Élevé"))
    print_success(f"Audit GPO terminé — {len(findings)} finding(s), {critical} critique(s)/élevé(s).")
    return {
        "module":    "blue_team.audit_gpo",
        "status":    "warning" if critical else "success",
        "timestamp": datetime.now().isoformat(),
        "findings":  findings,
        "summary":   {"total": len(findings), "critical": critical}
    }


def _check_unconstrained_delegation(conn, base_dn) -> list:
    """Detect computers and users configured with unconstrained Kerberos delegation."""
    findings = []
    # userAccountControl flag 524288 = TrustedForDelegation (unconstrained)
    conn.search(base_dn,
                "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                attributes=["sAMAccountName", "dNSHostName"])
    machines = [str(e.sAMAccountName) for e in conn.entries]
    # Exclure les DCs (c'est normal pour eux)
    non_dc = [m for m in machines if not m.upper().endswith("$") or "DC" not in m.upper()]
    if non_dc:
        findings.append({
            "risk": "Critique",
            "title": f"{len(non_dc)} machine(s) avec délégation Kerberos non contrainte",
            "description": "Machines : " + ", ".join(non_dc[:10]),
            "mitigation": "Remplacer par la délégation contrainte (constrained delegation) ou resource-based.",
            "event_ids": [],
        })

    # Comptes utilisateurs avec délégation non contrainte
    conn.search(base_dn,
                "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                attributes=["sAMAccountName"])
    users = [str(e.sAMAccountName) for e in conn.entries]
    if users:
        findings.append({
            "risk": "Critique",
            "title": f"{len(users)} compte(s) utilisateur(s) avec délégation non contrainte",
            "description": "Comptes : " + ", ".join(users[:10]),
            "mitigation": "Supprimer la délégation non contrainte sur les comptes utilisateurs.",
            "event_ids": [],
        })
    return findings


def _check_krbtgt_password(conn, base_dn) -> list:
    """Flag a krbtgt password that hasn't been rotated in over 180 days (Golden Ticket risk)."""
    findings = []
    from datetime import timedelta
    conn.search(base_dn,
                "(&(objectClass=user)(sAMAccountName=krbtgt))",
                attributes=["pwdLastSet"])
    for entry in conn.entries:
        pwd_last_set = entry.pwdLastSet.value
        if pwd_last_set and hasattr(pwd_last_set, "replace"):
            age = (datetime.now() - pwd_last_set.replace(tzinfo=None)).days
            if age > 180:
                findings.append({
                    "risk": "Élevé",
                    "title": f"Mot de passe krbtgt non changé depuis {age} jours",
                    "description": "Un mot de passe krbtgt ancien permet les Golden Ticket attacks.",
                    "mitigation": "Réinitialiser le mot de passe krbtgt deux fois (purge du cache Kerberos).",
                    "event_ids": [],
                })
    return findings


def _check_adminsdholder(conn, base_dn) -> list:
    """Flag accounts with adminCount=1 that are no longer in a privileged group (stale AdminSDHolder)."""
    findings = []
    # Vérifier les comptes protégés par AdminSDHolder (adminCount=1)
    conn.search(base_dn,
                "(&(objectClass=user)(adminCount=1)(!(memberOf=CN=Domain Admins,CN=Users," + base_dn + ")))",
                attributes=["sAMAccountName"])
    accounts = [str(e.sAMAccountName) for e in conn.entries]
    if accounts:
        findings.append({
            "risk": "Moyen",
            "title": f"{len(accounts)} compte(s) avec adminCount=1 hors groupes privilégiés",
            "description": "Comptes : " + ", ".join(accounts[:10]),
            "mitigation": "Vérifier et nettoyer adminCount sur les comptes non privilégiés.",
            "event_ids": [],
        })
    return findings


def _check_acl_dangerous(conn, base_dn) -> list:
    """Detect AS-REP roastable accounts (Kerberos pre-authentication disabled)."""
    findings = []
    # Comptes AS-REP Roastable (no preauth required)
    conn.search(base_dn,
                "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                attributes=["sAMAccountName"])
    accounts = [str(e.sAMAccountName) for e in conn.entries]
    if accounts:
        findings.append({
            "risk": "Élevé",
            "title": f"{len(accounts)} compte(s) vulnérable(s) AS-REP Roasting",
            "description": "Comptes sans pré-authentification Kerberos : " + ", ".join(accounts[:10]),
            "mitigation": "Activer la pré-authentification Kerberos sur tous les comptes.",
            "event_ids": [4768],
        })
    return findings


def _load_config() -> dict:
    """Load config.yaml via the centralized loader (core.config.load_config)."""
    from core.config import load_config
    return load_config()
