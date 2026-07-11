"""
Response / SOAR — Block Malicious IP Address
=============================================
Creates firewall rules to block inbound and/or outbound traffic
from/to a malicious IP address identified during an attack.

Supports two platforms:
    - Windows: Creates Windows Firewall rules via PowerShell New-NetFirewallRule
      or netsh advfirewall (fallback)
    - Linux  : Creates iptables DROP rules for INPUT, OUTPUT, and FORWARD chains

Optional temporary blocking:
    If duration_min > 0, schedules automatic rule removal after N minutes
    using Windows Task Scheduler or Linux 'at' command.

Triggered by SOAR workflows when:
    - A password spray source IP is identified (Event ID 4625 source)
    - A Kerberoasting attempt is detected from a specific host
    - C2 communication is detected

"""

import subprocess
import platform
import socket
from datetime import datetime

from utils.format_utils import print_info, print_success, print_warning, print_error


def run(ip: str = None, direction: str = "both",
        reason: str = "IP bloquée suite à détection SIEM",
        duration_min: int = 0, **kwargs) -> dict:
    """
    Block an IP via Windows Firewall (netsh/PowerShell) or iptables (Linux).
    direction: 'in' | 'out' | 'both'
    duration_min: 0 = permanent
    """
    if not ip:
        return _error("Paramètre 'ip' requis.")

    if not _is_valid_ip(ip):
        return _error(f"Adresse IP invalide : '{ip}'")

    print_info(f"[RESPONSE] Blocage IP : {ip} (direction: {direction})")

    actions  = []
    findings = []
    system   = platform.system().lower()

    if "windows" in system:
        success = _block_windows(ip, direction, reason)
    else:
        success = _block_iptables(ip, direction)

    if success:
        actions.append({
            "action":    "block_ip",
            "ip":        ip,
            "direction": direction,
            "timestamp": datetime.now().isoformat(),
            "permanent": duration_min == 0,
            "status":    "success",
        })
        print_success(f"IP {ip} bloquée ({direction}).")
        findings.append({
            "risk":  "Info",
            "title": f"IP {ip} bloquée avec succès",
            "description": (
                f"Direction : {direction}. "
                f"Raison : {reason}. "
                f"{'Permanent' if duration_min == 0 else f'Durée : {duration_min} min'}."
            ),
            "mitigation": "Documenter le blocage et investiguer l'origine de l'attaque.",
            "event_ids":  [],
        })

        # Schedule unblock if temporary
        if duration_min > 0:
            _schedule_unblock(ip, direction, duration_min, system)
            print_info(f"Déblocage automatique planifié dans {duration_min} min.")
    else:
        print_error(f"Échec du blocage de {ip}.")
        findings.append({
            "risk":  "Élevé",
            "title": f"Échec du blocage IP : {ip}",
            "description": "Intervention manuelle requise pour bloquer l'IP.",
            "mitigation": (
                f"Windows : netsh advfirewall firewall add rule name='BLOCK_{ip}' "
                f"dir=in action=block remoteip={ip}\n"
                f"Linux   : iptables -I INPUT -s {ip} -j DROP"
            ),
            "event_ids": [],
        })

    return {
        "module":    "response.block_ip",
        "status":    "success" if success else "failed",
        "timestamp": datetime.now().isoformat(),
        "target_ip": ip,
        "findings":  findings,
        "actions":   actions,
        "summary": {
            "ip":      ip,
            "blocked": success,
            "method":  "windows_firewall" if "windows" in system else "iptables",
        },
    }


# ── Platform-specific blocking ────────────────────────────────────────────────

def _block_windows(ip: str, direction: str, reason: str) -> bool:
    """Add Windows Firewall rules via PowerShell / netsh."""
    dirs = []
    if direction in ("in", "both"):
        dirs.append(("Inbound", "in"))
    if direction in ("out", "both"):
        dirs.append(("Outbound", "out"))

    success = True
    for dir_label, dir_short in dirs:
        rule_name = f"SIEM_BLOCK_{ip}_{dir_label}"
        cmd = (
            f"New-NetFirewallRule "
            f"-DisplayName '{rule_name}' "
            f"-Direction {dir_label} "
            f"-Action Block "
            f"-RemoteAddress {ip} "
            f"-Description '{reason}' "
            f"-Enabled True | Out-Null; 'ok'"
        )
        out = _ps(cmd)
        if not out or "ok" not in out:
            # Fallback to netsh
            netsh_dir = "in" if dir_label == "Inbound" else "out"
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", f"dir={netsh_dir}",
                 "action=block", f"remoteip={ip}", "enable=yes"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                success = False
    return success


def _block_iptables(ip: str, direction: str) -> bool:
    """Add iptables rules on Linux."""
    commands = []
    if direction in ("in", "both"):
        commands.append(["iptables", "-I", "INPUT",   "-s", ip, "-j", "DROP"])
    if direction in ("out", "both"):
        commands.append(["iptables", "-I", "OUTPUT",  "-d", ip, "-j", "DROP"])
    if direction in ("both",):
        commands.append(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])

    success = True
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                success = False
        except Exception:
            success = False
    return success


def _schedule_unblock(ip: str, direction: str, minutes: int, system: str):
    """Schedule automatic IP unblock using at/schtasks."""
    try:
        if "windows" in system:
            cmd = (
                f"$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes({minutes}); "
                f"$action  = New-ScheduledTaskAction -Execute 'powershell.exe' "
                f"-Argument \"-Command Remove-NetFirewallRule -DisplayName 'SIEM_BLOCK_{ip}*'\"; "
                f"Register-ScheduledTask -TaskName 'SIEM_UNBLOCK_{ip}' "
                f"-Trigger $trigger -Action $action -Force | Out-Null"
            )
            _ps(cmd)
        else:
            subprocess.run(
                ["at", f"now + {minutes} minutes",
                 f"iptables -D INPUT -s {ip} -j DROP"],
                capture_output=True, timeout=10
            )
    except Exception:
        pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_valid_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def _ps(cmd: str) -> str | None:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=15
        )
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    except Exception:
        return None


def _error(msg: str) -> dict:
    print_error(msg)
    return {
        "module":    "response.block_ip",
        "status":    "error",
        "timestamp": datetime.now().isoformat(),
        "message":   msg,
        "findings":  [],
        "actions":   [],
    }
