"""
Response / SOAR — Block Malicious IP (Linux/Kali version)
==========================================================
Bloque une IP via iptables depuis Kali Linux.
"""
import subprocess
import socket
from datetime import datetime
from utils.format_utils import print_info, print_success, print_warning, print_error


def _load_config() -> dict:
    import os, yaml
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "config.yaml")
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def run(ip: str = None, direction: str = "both",
        reason: str = "IP bloquée suite à détection SIEM",
        duration_min: int = 0, **kwargs) -> dict:
    if not ip:
        return _error("Paramètre 'ip' requis.")
    if not _is_valid_ip(ip):
        return _error(f"Adresse IP invalide : '{ip}'")
    print_info(f"[RESPONSE] Blocage IP : {ip} (direction: {direction})")
    actions, findings = [], []
    success = _block_iptables(ip, direction)
    if success:
        actions.append({"action": "block_ip", "ip": ip, "direction": direction,
                        "timestamp": datetime.now().isoformat(), "status": "success"})
        print_success(f"IP {ip} bloquée ({direction}) via iptables.")
        findings.append({"risk": "Info", "title": f"IP {ip} bloquée",
                         "description": f"Direction : {direction}. Raison : {reason}.",
                         "mitigation": "Documenter et investiguer.", "event_ids": []})
    else:
        print_error(f"Échec du blocage de {ip}.")
        findings.append({"risk": "Élevé", "title": f"Échec blocage IP : {ip}",
                         "description": "Intervention manuelle requise.",
                         "mitigation": f"iptables -I INPUT -s {ip} -j DROP", "event_ids": []})
    return {"module": "response.linux.block_ip", "status": "success" if success else "failed",
            "timestamp": datetime.now().isoformat(), "target_ip": ip,
            "findings": findings, "actions": actions,
            "summary": {"ip": ip, "blocked": success, "method": "iptables"}}


def _block_iptables(ip: str, direction: str) -> bool:
    commands = []
    if direction in ("in", "both"):
        commands.append(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    if direction in ("out", "both"):
        commands.append(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
    if direction == "both":
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


def _is_valid_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def _error(msg):
    print_error(msg)
    return {"module": "response.linux.block_ip", "status": "error",
            "timestamp": datetime.now().isoformat(), "message": msg, "findings": [], "actions": []}
