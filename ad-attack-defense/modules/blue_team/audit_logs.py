"""
Blue Team — Log Audit (Linux-compatible, Wazuh API)
=====================================================
Analyzes Windows Security Event Logs via the Wazuh SIEM API.
No PowerShell required — runs from Kali/Linux against the Wazuh server.

Instead of querying Windows Event Log directly (requires local PowerShell),
this module queries the Wazuh REST API which has already collected and
indexed all Windows events from the agents (DC01, SRV02, etc.).

Checks:
    1. Alert volume per critical Event ID (4625, 4769, 4740, 7045, 4662, 1102)
    2. Attack pattern detection (spray, kerberoasting, DCSync, PsExec, log clearing)
    3. Wazuh agent status (are DCs reporting?)
    4. Recent high-severity alerts summary
"""

import os
import yaml
from datetime import datetime, timedelta
from collections import defaultdict

from utils.format_utils import print_info, print_success, print_warning, print_error
from core.wazuh_api import WazuhAPI

# Critical Event IDs and their risk level
CRITICAL_EVENT_IDS = {
    4624: ("Successful logon",                   "Info"),
    4625: ("Failed logon",                       "Élevé"),
    4648: ("Logon with explicit credentials",    "Moyen"),
    4662: ("AD object operation (DCSync?)",      "Critique"),
    4768: ("Kerberos TGT Request",               "Info"),
    4769: ("Kerberos TGS Request (Kerberoast?)", "Moyen"),
    4771: ("Kerberos pre-auth failed",           "Moyen"),
    4720: ("User account created",               "Moyen"),
    4724: ("Password reset",                     "Moyen"),
    4726: ("User account deleted",               "Élevé"),
    4728: ("Member added to global group",       "Moyen"),
    4740: ("Account lockout",                    "Élevé"),
    7045: ("New service installed",              "Critique"),
    4688: ("New process created",                "Info"),
    4697: ("Service installed in system",        "Critique"),
    4698: ("Scheduled task created",             "Élevé"),
    1102: ("Security log cleared",               "Critique"),
}

# Alert thresholds — above these counts, flag as suspicious
THRESHOLDS = {
    4625: 20,   # spray / brute force
    4769: 10,   # kerberoasting
    4740: 3,    # account lockout
    7045: 1,    # any service install
    4698: 2,    # scheduled task creation
    4662: 1,    # any DCSync-related operation
    1102: 1,    # any log clearing
}


def run_audit(hours: int = 24, **kwargs) -> dict:
    """
    Query Wazuh API for Windows Security events and detect attack patterns.

    Args:
        hours (int): Time window to analyse (default: last 24 hours).

    Returns:
        dict: Standardised result with findings and event counts.
    """
    print_info(f"Log audit via Wazuh API (last {hours}h)...")

    api       = WazuhAPI()
    connected = api.authenticate()

    if not connected:
        print_warning("Wazuh unreachable — running in demo mode.")
        return _demo_result(hours)

    # Fetch alerts from the time window
    minutes    = hours * 60
    raw_alerts = api.get_alerts(minutes=minutes, min_level=1)

    if not raw_alerts:
        print_warning("No alerts found in Wazuh for this time window.")

    # Count occurrences of each critical Event ID in the alerts
    event_counts = _count_events(raw_alerts)

    findings = []
    findings += _analyze_thresholds(event_counts, hours)
    findings += _detect_patterns(event_counts)
    findings += _check_agent_status(api)
    findings += _summarize_high_severity(raw_alerts)

    critical = sum(1 for f in findings if f["risk"] in ("Critique", "Élevé"))
    print_success(f"Log audit done — {len(findings)} finding(s), {critical} critical/high.")

    return {
        "module":       "blue_team.audit_logs",
        "status":       "warning" if critical else "success",
        "timestamp":    datetime.now().isoformat(),
        "findings":     findings,
        "event_counts": event_counts,
        "summary":      {
            "total":          len(findings),
            "critical":       critical,
            "alerts_fetched": len(raw_alerts),
            "window_hours":   hours,
        },
    }


# ── Analysis functions ────────────────────────────────────────────────────────

def _count_events(alerts: list) -> dict:
    """
    Extract and count Windows Event IDs from Wazuh alert data.

    Wazuh stores the Windows Event ID in the alert's data field.
    The path is typically: data.win.system.eventID or rule.id mapping.
    """
    counts = defaultdict(int)

    for alert in alerts:
        # Try to extract Windows Event ID from Wazuh alert structure
        event_id = None

        # Path 1: data.win.system.eventID (standard Windows agent)
        data = alert.get("data", {})
        win  = data.get("win", {})
        sys  = win.get("system", {})
        eid  = sys.get("eventID") or sys.get("eventId")
        if eid:
            try:
                event_id = int(eid)
            except (ValueError, TypeError):
                pass

        # Path 2: rule description contains Event ID
        if event_id is None:
            rule_desc = alert.get("rule", {}).get("description", "")
            for cid in CRITICAL_EVENT_IDS:
                if str(cid) in rule_desc:
                    event_id = cid
                    break

        if event_id and event_id in CRITICAL_EVENT_IDS:
            counts[event_id] += 1

    return dict(counts)


def _analyze_thresholds(event_counts: dict, hours: int) -> list:
    """Flag Event IDs that exceed alert thresholds."""
    findings = []

    for eid, threshold in THRESHOLDS.items():
        count        = event_counts.get(eid, 0)
        label, _risk = CRITICAL_EVENT_IDS.get(eid, ("Unknown event", "Info"))

        if count == 0:
            # No events for high-value IDs may indicate audit policy issue
            if eid in (4625, 4769, 7045, 4662):
                findings.append({
                    "risk":        "Info",
                    "title":       f"Event ID {eid} ({label}) — no events in last {hours}h",
                    "description": (
                        "Either nothing happened, or audit policy is not capturing this event. "
                        "Verify Windows Advanced Audit Policy is configured correctly."
                    ),
                    "mitigation":  "Check: auditpol /get /subcategory:* on the DC.",
                    "event_ids":   [eid],
                })
            continue

        if count >= threshold:
            findings.append({
                "risk":        _risk,
                "title":       f"Anomalous volume: {count}× Event ID {eid} ({label}) in {hours}h",
                "description": _describe_eid(eid, count),
                "mitigation":  _mitigation_eid(eid),
                "event_ids":   [eid],
            })

    return findings


def _detect_patterns(event_counts: dict) -> list:
    """Detect multi-event attack signatures by correlating Event ID counts."""
    findings = []

    # Pattern 1: Password Spraying — many 4625, very few 4624
    fails   = event_counts.get(4625, 0)
    success = event_counts.get(4624, 0)
    if fails > 15 and (success == 0 or fails / max(success, 1) > 10):
        findings.append({
            "risk":        "Critique",
            "title":       f"Password Spraying pattern detected ({fails} failures, {success} successes)",
            "description": (
                f"{fails} failed logons (4625) vs only {success} successful (4624). "
                "This ratio is characteristic of password spraying — one password "
                "tried against many accounts."
            ),
            "mitigation":  (
                "1. Identify source IP from Wazuh alert details.\n"
                "2. Block attacker IP immediately.\n"
                "3. Reset passwords of targeted accounts.\n"
                "4. Enable MFA urgently."
            ),
            "event_ids":   [4625, 4624],
        })

    # Pattern 2: Kerberoasting — spike in 4769
    tgs = event_counts.get(4769, 0)
    if tgs >= THRESHOLDS.get(4769, 10):
        findings.append({
            "risk":        "Critique",
            "title":       f"Kerberoasting pattern detected ({tgs}× Event 4769)",
            "description": (
                f"{tgs} Kerberos Service Ticket requests detected. "
                "This volume is characteristic of Kerberoasting — "
                "bulk TGS requests to extract crackable hashes."
            ),
            "mitigation":  (
                "1. Identify the requesting account from Wazuh alert details.\n"
                "2. Check for offline cracking activity.\n"
                "3. Rotate SPN account passwords immediately (25+ chars).\n"
                "4. Migrate service accounts to gMSA."
            ),
            "event_ids":   [4769],
        })

    # Pattern 3: DCSync — any 4662 with replication properties
    if event_counts.get(4662, 0) > 0:
        findings.append({
            "risk":        "Critique",
            "title":       f"Possible DCSync — {event_counts[4662]} AD object operation(s) (Event 4662)",
            "description": (
                "AD object operations detected. DCSync (mimikatz lsadump::dcsync) "
                "generates Event ID 4662 with DRSUAPI replication rights. "
                "This can extract NTLM hashes for all domain accounts including krbtgt."
            ),
            "mitigation":  (
                "1. Identify the account performing the replication in Wazuh.\n"
                "2. Check if it is a legitimate DC or backup tool.\n"
                "3. Revoke DRSUAPI rights if not legitimate.\n"
                "4. Reset krbtgt password twice."
            ),
            "event_ids":   [4662],
        })

    # Pattern 4: PsExec / service-based lateral movement
    if event_counts.get(7045, 0) > 0:
        findings.append({
            "risk":        "Élevé",
            "title":       f"{event_counts[7045]} service(s) installed — possible PsExec/persistence",
            "description": (
                "New service installation (7045) is the fingerprint of PsExec "
                "(creates PSEXESVC service) and service-based backdoors."
            ),
            "mitigation":  (
                "1. Review newly installed services in Wazuh.\n"
                "2. Correlate with network logon events (4624 type 3) at same timestamp.\n"
                "3. Enable AppLocker to block unsigned service binaries."
            ),
            "event_ids":   [7045, 4697],
        })

    # Pattern 5: Log clearing — evidence tampering
    if event_counts.get(1102, 0) > 0:
        findings.append({
            "risk":        "Critique",
            "title":       "Security log cleared (Event ID 1102) — evidence tampering",
            "description": (
                "The Windows Security log was cleared. This is a strong indicator "
                "of a compromise cover-up. Fortunately Wazuh captured events "
                "before they were erased."
            ),
            "mitigation":  (
                "1. Investigate who cleared the log and from where.\n"
                "2. Review Wazuh timeline for events before the clearing.\n"
                "3. Centralise all logs in real-time to Wazuh — "
                "local clearing becomes irrelevant."
            ),
            "event_ids":   [1102, 4719],
        })

    return findings


def _check_agent_status(api: WazuhAPI) -> list:
    """Check that Wazuh agents on all GOAD machines are active."""
    findings = []
    try:
        agents = api.get_agents()
        if not agents:
            findings.append({
                "risk":        "Moyen",
                "title":       "No Wazuh agents found",
                "description": "No agents registered — log collection may not be working.",
                "mitigation":  "Install Wazuh agent on DC01, DC02, DC03, SRV02, SRV03.",
                "event_ids":   [],
            })
            return findings

        active       = [a for a in agents if a.get("status") == "active"]
        disconnected = [a for a in agents if a.get("status") != "active"]

        findings.append({
            "risk":        "Info",
            "title":       f"Wazuh agents: {len(active)} active, {len(disconnected)} disconnected",
            "description": (
                f"Active: {', '.join(a.get('name','?') for a in active[:8])}. "
                + (f"Disconnected: {', '.join(a.get('name','?') for a in disconnected[:5])}."
                   if disconnected else "")
            ),
            "mitigation":  "Reconnect disconnected agents: NET START WazuhSvc on target.",
            "event_ids":   [],
        })

        for agent in disconnected:
            findings.append({
                "risk":        "Élevé",
                "title":       f"Wazuh agent disconnected: {agent.get('name', '?')} ({agent.get('ip', '?')})",
                "description": "This machine is not sending logs to Wazuh — blind spot for detection.",
                "mitigation":  f"Check WazuhSvc on {agent.get('name','?')} and verify network connectivity.",
                "event_ids":   [],
            })

    except Exception as e:
        findings.append({
            "risk":        "Info",
            "title":       f"Cannot check agent status: {e}",
            "description": str(e), "mitigation": "", "event_ids": [],
        })
    return findings


def _summarize_high_severity(alerts: list) -> list:
    """Summarise the most recent high-severity alerts (level >= 10)."""
    findings = []
    high     = [a for a in alerts if a.get("rule", {}).get("level", 0) >= 10]

    if not high:
        return findings

    # Group by rule description
    by_rule = defaultdict(list)
    for alert in high[:50]:  # Limit to 50
        desc = alert.get("rule", {}).get("description", "Unknown")
        by_rule[desc].append(alert)

    for desc, alert_list in sorted(by_rule.items(), key=lambda x: -len(x[1]))[:5]:
        agent_names = list(set(
            a.get("agent", {}).get("name", "?") for a in alert_list
        ))
        findings.append({
            "risk":        "Élevé",
            "title":       f"{len(alert_list)}× high-severity alert: {desc[:60]}",
            "description": f"Agents: {', '.join(agent_names[:5])}.",
            "mitigation":  "Investigate in Wazuh dashboard → Security Events.",
            "event_ids":   [],
        })

    return findings


# ── Demo mode ─────────────────────────────────────────────────────────────────

def _demo_result(hours: int) -> dict:
    """Return a simulated result when Wazuh is unreachable."""
    print_warning("Demo mode — simulated findings (Wazuh not connected)")
    fake_counts = {4625: 45, 4769: 12, 4624: 3, 4662: 1, 7045: 2}
    findings    = _analyze_thresholds(fake_counts, hours)
    findings   += _detect_patterns(fake_counts)
    findings.append({
        "risk":        "Moyen",
        "title":       "Wazuh not connected — results are simulated",
        "description": "Configure wazuh_host and wazuh_password in config.yaml.",
        "mitigation":  "Verify Wazuh is running: systemctl status wazuh-manager",
        "event_ids":   [],
    })
    return {
        "module":       "blue_team.audit_logs",
        "status":       "warning",
        "timestamp":    datetime.now().isoformat(),
        "findings":     findings,
        "event_counts": fake_counts,
        "summary":      {"total": len(findings), "critical": 3, "demo_mode": True},
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _describe_eid(eid: int, count: int) -> str:
    descriptions = {
        4625: f"{count} failed authentication attempts — probable brute force or password spray.",
        4769: f"{count} Kerberos TGS requests — possible Kerberoasting in progress.",
        4740: f"{count} accounts locked out — spray attack likely in progress.",
        7045: f"{count} service(s) installed — check for PsExec or backdoor.",
        4662: f"{count} AD object operation(s) — possible DCSync activity.",
        4698: f"{count} scheduled task(s) created — possible persistence mechanism.",
        1102: "Security log cleared — potential evidence tampering after compromise.",
    }
    return descriptions.get(eid, f"{count} occurrences detected above threshold.")


def _mitigation_eid(eid: int) -> str:
    mitigations = {
        4625: "Enable account lockout policy. Identify source IP. Enable MFA.",
        4769: "Monitor SPN accounts. Enforce strong passwords (25+ chars) on service accounts.",
        4740: "Investigate spray source IP. Alert security team. Check locked accounts.",
        7045: "Audit recently installed services. Correlate with network logons (4624 type 3).",
        4662: "Verify DRSUAPI replication rights. Investigate the requesting account.",
        4698: "Audit scheduled tasks. Remove any non-legitimate tasks.",
        1102: "Centralise logs to Wazuh in real-time. Restrict log-clearing rights.",
    }
    return mitigations.get(eid, "Investigate and correlate with other indicators.")
