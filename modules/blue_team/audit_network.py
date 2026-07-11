"""
Blue Team — Network Audit (SMB Signing, LLMNR) via impacket/nmap
"""
import subprocess
from datetime import datetime
from utils.format_utils import print_info, print_success


def run_audit(**kwargs) -> dict:
    """
    Run the network security audit against the domain controller.

    Checks SMB signing enforcement, world-readable shares, and whether
    the Print Spooler service is exposed (PrintNightmare).

    Returns:
        dict: Standard module result with 'findings' and a 'summary'.
    """
    print_info("Audit réseau AD en cours...")
    findings = []
    cfg   = _load_config()
    dc_ip = cfg.get("dc_ip", "192.168.56.12")

    findings += _check_smb_signing(dc_ip)
    findings += _check_open_shares(dc_ip, cfg)
    findings += _check_spooler(dc_ip, cfg)

    critical = sum(1 for f in findings if f["risk"] in ("Critique", "Élevé"))
    print_success(f"Audit réseau terminé — {len(findings)} finding(s), {critical} critique(s)/élevé(s).")
    return {
        "module":    "blue_team.audit_network",
        "status":    "warning" if critical else "success",
        "timestamp": datetime.now().isoformat(),
        "findings":  findings,
        "summary":   {"total": len(findings), "critical": critical}
    }


def _check_smb_signing(dc_ip) -> list:
    """Check whether SMB signing is enforced on the target (nmap smb-security-mode)."""
    findings = []
    try:
        result = subprocess.run(
            ["nmap", "-p", "445", "--script", "smb-security-mode", dc_ip],
            capture_output=True, text=True, timeout=20
        )
        if "message_signing: disabled" in result.stdout:
            findings.append({
                "risk": "Critique",
                "title": "SMB Signing désactivé",
                "description": f"Le serveur {dc_ip} n'exige pas la signature SMB — NTLM Relay possible.",
                "mitigation": "Activer SMB Signing via GPO : Microsoft network server: Digitally sign communications (always).",
                "event_ids": [],
            })
        elif "message_signing: required" in result.stdout or "message_signing: enabled" in result.stdout:
            findings.append({
                "risk": "Info",
                "title": "SMB Signing activé",
                "description": f"SMB Signing est actif sur {dc_ip}.",
                "mitigation": "Maintenir cette configuration.",
                "event_ids": [],
            })
    except Exception as e:
        findings.append({
            "risk": "Info",
            "title": f"Vérification SMB Signing impossible : {e}",
            "description": "nmap requis pour cette vérification.",
            "mitigation": "Installer nmap et relancer l'audit.",
            "event_ids": [],
        })
    return findings


def _check_open_shares(dc_ip, cfg) -> list:
    """Check for SMB shares readable by a standard domain account (netexec)."""
    findings = []
    try:
        user     = cfg.get("domain_user", "vagrant")
        password = cfg.get("domain_password", "vagrant")
        domain   = cfg.get("domain", "essos.local")
        result   = subprocess.run(
            ["netexec", "smb", dc_ip, "-u", user, "-p", password, "-d", domain, "--shares"],
            capture_output=True, text=True, timeout=20
        )
        readable = []
        for line in result.stdout.splitlines():
            if "READ" in line and "$" not in line:
                parts = line.split()
                if parts:
                    readable.append(parts[-1] if len(parts) > 1 else line)
        if readable:
            findings.append({
                "risk": "Moyen",
                "title": f"{len(readable)} partage(s) lisible(s) par un utilisateur standard",
                "description": "Partages : " + ", ".join(readable[:10]),
                "mitigation": "Restreindre les permissions sur les partages réseau.",
                "event_ids": [5145],
            })
    except Exception as e:
        findings.append({
            "risk": "Info",
            "title": f"Vérification des partages impossible : {e}",
            "description": "netexec requis pour cette vérification.",
            "mitigation": "Installer netexec et relancer l'audit.",
            "event_ids": [],
        })
    return findings


def _check_spooler(dc_ip, cfg) -> list:
    """Check whether the Print Spooler service is running on the DC (PrintNightmare, CVE-2021-34527)."""
    findings = []
    try:
        user     = cfg.get("domain_user", "vagrant")
        password = cfg.get("domain_password", "vagrant")
        domain   = cfg.get("domain", "essos.local")
        result   = subprocess.run(
            ["netexec", "smb", dc_ip, "-u", user, "-p", password, "-d", domain, "-M", "spooler"],
            capture_output=True, text=True, timeout=20
        )
        if "SPOOLER" in result.stdout and "running" in result.stdout.lower():
            findings.append({
                "risk": "Élevé",
                "title": "Print Spooler actif sur le DC",
                "description": "Le service Print Spooler est actif — vulnérable à PrintNightmare (CVE-2021-34527).",
                "mitigation": "Désactiver le service Print Spooler sur tous les DCs.",
                "event_ids": [],
            })
    except Exception:
        pass
    return findings


def _load_config() -> dict:
    """Load config.yaml via the centralized loader (core.config.load_config)."""
    from core.config import load_config
    return load_config()
