"""
Response / SOAR — Network Isolation of Compromised Host
========================================================
Isolates a compromised machine from the rest of the network by creating
firewall rules that block all traffic except management ports.

This allows the security team to:
    - Stop an ongoing attack or lateral movement immediately
    - Preserve the machine's state for forensic investigation
    - Maintain remote access for incident response (RDP/WinRM/SSH)

Isolation methods:
    - Windows: Pushes firewall rules via PowerShell Remoting (WinRM)
      Blocks all traffic except: RDP (3389), WinRM (5985/5986), SSH (22),
      and Wazuh agent communication (1514/1515/55000)
    - Linux  : Creates iptables FORWARD DROP rules on the network gateway,
      whitelisting the analyst's IP for management ports

Rollback:
    Isolation details are recorded in logs/isolation_<IP>.json
    to enable clean rule removal after the investigation.

"""

import subprocess
import socket
import platform
from datetime import datetime

from utils.format_utils import print_info, print_success, print_warning, print_error


# Ports autorisés pendant l'isolation (pour investigation forensique)
MANAGEMENT_PORTS = {
    3389: "RDP",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    22:   "SSH",
}


def run(host: str = None, management_ip: str = None,
        reason: str = "Isolation suite à détection de compromission",
        method: str = "firewall", **kwargs) -> dict:
    """
    Isolate a compromised host:
    1. Block all inbound/outbound traffic via firewall rules
    2. Keep management ports open for the analyst IP
    3. Log isolation event
    method: 'firewall' | 'vlan' (VLAN requires network equipment integration)
    """
    if not host:
        return _error("Paramètre 'host' (IP ou hostname) requis.")

    print_info(f"[RESPONSE] Isolation de la machine : {host}")
    print_warning("⚠  Cette action coupera les connexions actives sur la machine cible !")

    actions  = []
    findings = []
    system   = platform.system().lower()

    # Resolve hostname to IP
    target_ip = _resolve_host(host)
    if not target_ip:
        return _error(f"Impossible de résoudre l'hôte : {host}")

    if method == "firewall":
        # Remote isolation via PowerShell / netsh on target, or local iptables
        if "windows" in system:
            success = _isolate_windows_remote(target_ip, management_ip)
        else:
            success = _isolate_via_iptables(target_ip, management_ip)
    else:
        print_warning("Méthode VLAN non implémentée — utilisation du firewall.")
        success = False

    if success:
        actions.append({
            "action":       "isolate_host",
            "host":         host,
            "ip":           target_ip,
            "method":       method,
            "timestamp":    datetime.now().isoformat(),
            "management_ip": management_ip or "N/A",
            "status":       "success",
        })
        print_success(f"Machine {host} ({target_ip}) isolée.")
        findings.append({
            "risk":  "Info",
            "title": f"Machine isolée : {host} ({target_ip})",
            "description": (
                f"Isolation réseau appliquée. "
                f"Ports de management autorisés : {list(MANAGEMENT_PORTS.values())}. "
                f"IP management autorisée : {management_ip or 'toutes (investigation)'}. "
                f"Raison : {reason}."
            ),
            "mitigation": (
                "Effectuer l'investigation forensique maintenant (mémoire, logs, artefacts). "
                "Ne pas redémarrer la machine avant l'analyse. "
                "Lever l'isolation avec isolate_host.undo() une fois l'investigation terminée."
            ),
            "event_ids": [],
        })

        # Document isolation for rollback
        _document_isolation(host, target_ip, management_ip, reason)

    else:
        # Document failure with manual steps
        findings.append({
            "risk":  "Critique",
            "title": f"Isolation automatique échouée : {host}",
            "description": "L'isolation distante a échoué — intervention manuelle urgente.",
            "mitigation": _manual_isolation_steps(target_ip, management_ip),
            "event_ids": [],
        })

    return {
        "module":    "response.isolate_host",
        "status":    "success" if success else "failed",
        "timestamp": datetime.now().isoformat(),
        "target":    host,
        "target_ip": target_ip,
        "findings":  findings,
        "actions":   actions,
        "summary": {
            "host":        host,
            "ip":          target_ip,
            "isolated":    success,
            "method":      method,
            "rollback_cmd": f"python cli.py --mode response --action undo_isolate --host {host}",
        },
    }


# ── Isolation methods ─────────────────────────────────────────────────────────

def _isolate_windows_remote(target_ip: str, management_ip: str | None) -> bool:
    """
    Push firewall rules to the target via PowerShell remoting (WinRM).
    Blocks all traffic except management ports for the analyst IP.
    """
    mgmt_filter = (
        f"-RemoteAddress {management_ip}" if management_ip
        else "-RemoteAddress Any"
    )

    # Build the remote command
    rules = [
        # Allow management ports IN
        f"New-NetFirewallRule -DisplayName 'SIEM_ISOLATION_ALLOW_MGMT_IN' "
        f"-Direction Inbound -Action Allow -Protocol TCP "
        f"-LocalPort {','.join(str(p) for p in MANAGEMENT_PORTS)} "
        f"{mgmt_filter} -Enabled True | Out-Null",

        # Allow management ports OUT
        f"New-NetFirewallRule -DisplayName 'SIEM_ISOLATION_ALLOW_MGMT_OUT' "
        f"-Direction Outbound -Action Allow -Protocol TCP "
        f"-RemotePort {','.join(str(p) for p in MANAGEMENT_PORTS)} "
        f"{mgmt_filter} -Enabled True | Out-Null",

        # Allow Wazuh agent OUT (keep SIEM reporting during isolation)
        "New-NetFirewallRule -DisplayName 'SIEM_ISOLATION_ALLOW_WAZUH' "
        "-Direction Outbound -Action Allow -Protocol TCP "
        "-RemotePort 1514,1515,55000 -Enabled True | Out-Null",

        # Block all other inbound
        "New-NetFirewallRule -DisplayName 'SIEM_ISOLATION_BLOCK_IN' "
        "-Direction Inbound -Action Block -Enabled True | Out-Null",

        # Block all other outbound
        "New-NetFirewallRule -DisplayName 'SIEM_ISOLATION_BLOCK_OUT' "
        "-Direction Outbound -Action Block -Enabled True | Out-Null",
    ]

    remote_cmd = "; ".join(rules) + "; 'isolated'"

    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"Invoke-Command -ComputerName {target_ip} "
                f"-ScriptBlock {{ {remote_cmd} }}"
            ],
            capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0 and "isolated" in result.stdout
    except Exception:
        return False


def _isolate_via_iptables(target_ip: str, management_ip: str | None) -> bool:
    """
    Block all traffic to/from the target via iptables on a Linux gateway.
    Keep management ports open for the analyst.
    """
    rules = []

    # Allow management ports if analyst IP provided
    if management_ip:
        for port in MANAGEMENT_PORTS:
            rules += [
                ["iptables", "-I", "FORWARD", "-s", management_ip, "-d", target_ip,
                 "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
                ["iptables", "-I", "FORWARD", "-s", target_ip, "-d", management_ip,
                 "-p", "tcp", "--sport", str(port), "-j", "ACCEPT"],
            ]

    # Block everything else
    rules += [
        ["iptables", "-I", "FORWARD", "-d", target_ip, "-j", "DROP"],
        ["iptables", "-I", "FORWARD", "-s", target_ip, "-j", "DROP"],
    ]

    success = True
    for cmd in rules:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                success = False
        except Exception:
            success = False
    return success


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_host(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _document_isolation(host: str, ip: str, mgmt_ip: str | None, reason: str):
    """Write isolation record for rollback."""
    import os, json
    base = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(__file__)))), "logs")
    os.makedirs(base, exist_ok=True)
    record = {
        "host":          host,
        "ip":            ip,
        "management_ip": mgmt_ip,
        "reason":        reason,
        "isolated_at":   datetime.now().isoformat(),
    }
    path = os.path.join(base, f"isolation_{ip.replace('.','_')}.json")
    with open(path, "w") as f:
        json.dump(record, f, indent=2)


def _manual_isolation_steps(target_ip: str, mgmt_ip: str | None) -> str:
    mgmt = mgmt_ip or "<IP_ANALYSTE>"
    return (
        f"Isolation manuelle requise sur {target_ip} :\n"
        f"  1. Couper le câble réseau physique (si accès physique possible)\n"
        f"  2. Ou via switch : désactiver le port (shutdown interface)\n"
        f"  3. Ou PowerShell distant :\n"
        f"     Invoke-Command -ComputerName {target_ip} -ScriptBlock {{\n"
        f"       New-NetFirewallRule -DisplayName 'BLOCK_ALL_IN'  -Direction Inbound  -Action Block\n"
        f"       New-NetFirewallRule -DisplayName 'BLOCK_ALL_OUT' -Direction Outbound -Action Block\n"
        f"     }}"
    )


def _error(msg: str) -> dict:
    print_error(msg)
    return {
        "module":    "response.isolate_host",
        "status":    "error",
        "timestamp": datetime.now().isoformat(),
        "message":   msg,
        "findings":  [],
        "actions":   [],
    }
