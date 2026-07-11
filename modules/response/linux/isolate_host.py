"""
Response / SOAR — Network Isolation (Linux/Kali version)
=========================================================
Isole une machine compromise via iptables depuis Kali/jumpbox.
"""
import subprocess
import socket
import json
import os
from datetime import datetime
from utils.format_utils import print_info, print_success, print_warning, print_error

MANAGEMENT_PORTS = [3389, 5985, 5986, 22, 1514, 1515]


def run(host: str = None, management_ip: str = None,
        reason: str = "Isolation suite à détection de compromission", **kwargs) -> dict:
    if not host:
        return _error("Paramètre 'host' (IP ou hostname) requis.")
    print_info(f"[RESPONSE] Isolation de la machine : {host}")
    print_warning("Cette action coupera les connexions actives sur la machine cible !")
    target_ip = _resolve_host(host)
    if not target_ip:
        return _error(f"Impossible de résoudre l'hôte : {host}")
    actions, findings = [], []
    success = _isolate_via_iptables(target_ip, management_ip)
    if success:
        actions.append({"action": "isolate_host", "host": host, "ip": target_ip,
                        "timestamp": datetime.now().isoformat(), "status": "success"})
        print_success(f"Machine {host} ({target_ip}) isolée.")
        findings.append({"risk": "Info", "title": f"Machine isolée : {host}",
                         "description": f"Ports management autorisés : {MANAGEMENT_PORTS}. Raison : {reason}.",
                         "mitigation": "Investigation forensique immédiate. Ne pas redémarrer.",
                         "event_ids": []})
        _document_isolation(host, target_ip, management_ip, reason)
    else:
        findings.append({"risk": "Critique", "title": f"Isolation échouée : {host}",
                         "description": "Intervention manuelle urgente.",
                         "mitigation": f"iptables -I FORWARD -d {target_ip} -j DROP",
                         "event_ids": []})
    return {"module": "response.linux.isolate_host", "status": "success" if success else "failed",
            "timestamp": datetime.now().isoformat(), "target": host, "target_ip": target_ip,
            "findings": findings, "actions": actions,
            "summary": {"host": host, "ip": target_ip, "isolated": success}}


def _isolate_via_iptables(target_ip: str, management_ip: str = None) -> bool:
    rules = []
    if management_ip:
        for port in MANAGEMENT_PORTS:
            rules += [
                ["iptables", "-I", "FORWARD", "-s", management_ip, "-d", target_ip, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
                ["iptables", "-I", "FORWARD", "-s", target_ip, "-d", management_ip, "-p", "tcp", "--sport", str(port), "-j", "ACCEPT"],
            ]
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


def _resolve_host(host: str):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _document_isolation(host, ip, mgmt_ip, reason):
    base = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(__file__)))), "logs")
    os.makedirs(base, exist_ok=True)
    record = {"host": host, "ip": ip, "management_ip": mgmt_ip,
              "reason": reason, "isolated_at": datetime.now().isoformat()}
    with open(os.path.join(base, f"isolation_{ip.replace('.','_')}.json"), "w") as f:
        json.dump(record, f, indent=2)


def _error(msg):
    print_error(msg)
    return {"module": "response.linux.isolate_host", "status": "error",
            "timestamp": datetime.now().isoformat(), "message": msg, "findings": [], "actions": []}
