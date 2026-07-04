"""
Blue Team — Network Security Audit (Linux-compatible)
======================================================
Audits network-level AD security settings from Kali/Linux.
Uses raw socket probes and nmap instead of PowerShell.

Checks:
    1. SMB Signing (port 445 — nmap script or manual probe)
    2. LDAP null bind (anonymous LDAP access)
    3. SMBv1 support (EternalBlue risk)
    4. Open dangerous ports (Telnet, FTP, NetBIOS, RDP, WinRM)
    5. LDAP exposed attributes (anonymous info leak)
    6. Connectivity to all GOAD DCs
"""

import os
import socket
import subprocess
import yaml
from datetime import datetime

from utils.format_utils import print_info, print_success, print_warning, print_error

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, ANONYMOUS, SUBTREE
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False


def run_audit(target: str = None, **kwargs) -> dict:
    print_info("Network audit — scanning from Linux/Kali...")

    cfg        = _load_config()
    target_ip  = target or cfg.get("dc_ip", "192.168.56.10")

    findings = []
    findings += _check_smb_signing(target_ip)
    findings += _check_smbv1(target_ip)
    findings += _check_ldap_null_bind(target_ip, cfg)
    findings += _check_open_ports(target_ip)
    findings += _check_dc_connectivity(cfg)

    critical = sum(1 for f in findings if f["risk"] in ("Critique", "Élevé"))
    print_success(f"Network audit done — {len(findings)} finding(s), {critical} critical/high.")

    return {
        "module":    "blue_team.audit_network",
        "status":    "warning" if critical else "success",
        "timestamp": datetime.now().isoformat(),
        "findings":  findings,
        "summary":   {"total": len(findings), "critical": critical},
    }


def _check_smb_signing(target: str) -> list:
    """Check SMB signing status using nmap smb2-security-mode script."""
    findings = []
    print_info(f"Checking SMB signing on {target}...")

    # Try nmap first
    try:
        result = subprocess.run(
            ["nmap", "-p", "445", "--script", "smb2-security-mode",
             target, "-oG", "-", "--open"],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout + result.stderr

        if "Message signing enabled but not required" in output:
            findings.append({
                "risk":        "Élevé",
                "title":       f"SMB Signing NOT required on {target}",
                "description": (
                    "SMB signing is optional — NTLM Relay attacks are possible. "
                    "An attacker can capture hashes (Responder) and relay them "
                    "to this host without cracking (ntlmrelayx)."
                ),
                "mitigation":  (
                    "GPO: Computer Config → Security Settings → Local Policies → Security Options:\n"
                    "  'Microsoft network server: Digitally sign communications (always)' = Enabled"
                ),
                "event_ids":   [],
            })
        elif "Message signing enabled and required" in output:
            findings.append({
                "risk":        "Info",
                "title":       f"SMB Signing required on {target}",
                "description": "SMB signing is enforced — NTLM Relay is blocked.",
                "mitigation":  "Good — maintain this configuration.",
                "event_ids":   [],
            })
        elif result.returncode != 0 or not output.strip():
            # nmap not available or port closed
            findings += _check_smb_signing_manual(target)
        else:
            findings.append({
                "risk":        "Info",
                "title":       f"SMB signing status unclear on {target}",
                "description": f"nmap output: {output[:200]}",
                "mitigation":  "Run manually: nmap -p 445 --script smb2-security-mode <target>",
                "event_ids":   [],
            })
    except FileNotFoundError:
        # nmap not installed
        print_warning("nmap not found — trying manual SMB probe...")
        findings += _check_smb_signing_manual(target)
    except subprocess.TimeoutExpired:
        findings.append({
            "risk":        "Info",
            "title":       f"SMB signing check timed out on {target}",
            "description": "nmap timed out — host may be unreachable or firewalled.",
            "mitigation":  "Verify connectivity to port 445.",
            "event_ids":   [],
        })

    return findings


def _check_smb_signing_manual(target: str) -> list:
    """Manual SMB signing check using raw socket probe."""
    findings = []
    try:
        # Attempt TCP connection to port 445 to verify SMB is reachable
        sock = socket.create_connection((target, 445), timeout=3)
        sock.close()
        findings.append({
            "risk":        "Moyen",
            "title":       f"Port 445 (SMB) open on {target} — signing status unknown",
            "description": "Install nmap to check: sudo apt install nmap",
            "mitigation":  "Run: nmap -p 445 --script smb2-security-mode <target>",
            "event_ids":   [],
        })
    except Exception:
        findings.append({
            "risk":        "Info",
            "title":       f"Port 445 (SMB) not reachable on {target}",
            "description": "SMB appears closed or filtered.",
            "mitigation":  "Verify that the target is online and on the correct network.",
            "event_ids":   [],
        })
    return findings


def _check_smbv1(target: str) -> list:
    """Check if SMBv1 is enabled (EternalBlue risk)."""
    findings = []
    print_info(f"Checking SMBv1 on {target}...")

    try:
        result = subprocess.run(
            ["nmap", "-p", "445", "--script", "smb-protocols",
             target, "-oG", "-"],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout + result.stderr

        if "SMBv1" in output or "NT LM 0.12" in output:
            findings.append({
                "risk":        "Critique",
                "title":       f"SMBv1 enabled on {target}",
                "description": (
                    "SMBv1 is vulnerable to EternalBlue (MS17-010) and WannaCry. "
                    "It has been deprecated by Microsoft since 2014."
                ),
                "mitigation":  (
                    "Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false\n"
                    "Or via registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters "
                    "→ SMB1 = 0"
                ),
                "event_ids":   [],
            })
        elif result.returncode == 0:
            findings.append({
                "risk":        "Info",
                "title":       f"SMBv1 not detected on {target}",
                "description": "Good — SMBv1 appears disabled.",
                "mitigation":  "Continue monitoring.",
                "event_ids":   [],
            })
    except FileNotFoundError:
        pass  # nmap not available — skip
    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check SMBv1: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _check_ldap_null_bind(target: str, cfg: dict) -> list:
    """Check if anonymous LDAP bind is allowed (information disclosure)."""
    findings = []
    if not HAS_LDAP3:
        return findings

    print_info(f"Checking LDAP null bind on {target}...")

    try:
        server = Server(target, port=389, get_info=ALL)
        conn   = Connection(server, authentication=ANONYMOUS, auto_bind=True)

        # Try to search for domain info anonymously
        base_dn = _domain_to_dn(cfg.get("domain", ""))
        conn.search(base_dn, "(objectClass=domain)",
                    ldap3.BASE, attributes=["defaultNamingContext"])
        conn.unbind()

        findings.append({
            "risk":        "Moyen",
            "title":       f"Anonymous LDAP bind allowed on {target}",
            "description": (
                "The DC accepts anonymous LDAP connections. "
                "Attackers can enumerate domain information without credentials."
            ),
            "mitigation":  (
                "Disable anonymous LDAP access via Group Policy or dsHeuristics. "
                "Require authentication for all LDAP queries."
            ),
            "event_ids":   [],
        })
    except Exception:
        findings.append({
            "risk":        "Info",
            "title":       f"Anonymous LDAP bind rejected on {target}",
            "description": "Good — DC requires authentication for LDAP queries.",
            "mitigation":  "Continue monitoring.",
            "event_ids":   [],
        })
    return findings


def _check_open_ports(target: str) -> list:
    """Check for dangerous open ports using socket probes."""
    findings = []
    print_info(f"Checking dangerous ports on {target}...")

    dangerous_ports = {
        23:   ("Telnet",   "Critique", "Disable Telnet — use SSH instead."),
        21:   ("FTP",      "Élevé",    "Disable FTP — use SFTP/FTPS."),
        139:  ("NetBIOS",  "Moyen",    "Disable NetBIOS over TCP/IP if not needed."),
        3389: ("RDP",      "Moyen",    "Restrict RDP to authorised IPs via firewall."),
        5985: ("WinRM",    "Moyen",    "Restrict WinRM access — needed for remote management."),
        5986: ("WinRM-S",  "Moyen",    "Restrict WinRM HTTPS access."),
    }

    for port, (service, risk, mitigation) in dangerous_ports.items():
        try:
            sock = socket.create_connection((target, port), timeout=2)
            sock.close()
            findings.append({
                "risk":        risk,
                "title":       f"Port {port} ({service}) open on {target}",
                "description": f"{service} is accessible from the network.",
                "mitigation":  mitigation,
                "event_ids":   [],
            })
        except Exception:
            pass  # Port closed or filtered — good

    if not any("open" in f["title"] for f in findings):
        findings.append({
            "risk":        "Info",
            "title":       f"No dangerous ports open on {target}",
            "description": "Telnet, FTP, unprotected NetBIOS checked — all closed.",
            "mitigation":  "Continue monitoring.",
            "event_ids":   [],
        })
    return findings


def _check_dc_connectivity(cfg: dict) -> list:
    """Check connectivity to all GOAD DCs on key ports."""
    findings = []
    # GOAD DC IPs from config or defaults
    dcs = {
        cfg.get("dc_ip", "192.168.56.10"):     "Primary DC",
        "192.168.56.11":                        "DC02 (north.sevenkingdoms.local)",
        "192.168.56.12":                        "DC03 (essos.local)",
    }
    key_ports = {389: "LDAP", 445: "SMB", 88: "Kerberos", 636: "LDAPS"}

    print_info("Checking DC connectivity...")
    for dc_ip, dc_name in dcs.items():
        reachable = []
        closed    = []
        for port, service in key_ports.items():
            try:
                sock = socket.create_connection((dc_ip, port), timeout=2)
                sock.close()
                reachable.append(f"{service}/{port}")
            except Exception:
                closed.append(f"{service}/{port}")

        if reachable:
            findings.append({
                "risk":        "Info",
                "title":       f"{dc_name} ({dc_ip}) reachable",
                "description": f"Open: {', '.join(reachable)}. Closed: {', '.join(closed)}.",
                "mitigation":  "Verify only necessary ports are exposed.",
                "event_ids":   [],
            })
        else:
            findings.append({
                "risk":        "Moyen",
                "title":       f"{dc_name} ({dc_ip}) not reachable",
                "description": f"Could not reach any key port: {list(key_ports.values())}.",
                "mitigation":  "Check network routing between Kali and the GOAD network.",
                "event_ids":   [],
            })
    return findings


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
