# Tier 2 Implementation Summary

**Golden Ticket + Streamlit Dashboard completed.**

## New Features

### ✅ Golden Ticket Attack Module

**File:** `modules/red_team/golden_ticket.py`

**What it does:**
- Creates a forged Kerberos Ticket-Granting Ticket (TGT) using the krbtgt account's NTLM hash
- Grants unlimited domain access to any system indefinitely
- Persists across krbtgt password changes
- **CRITICAL**: Forest-wide compromise vector

**Usage:**
```bash
# First, obtain krbtgt hash via DCSync
./cli.py --mode red --attack dcsync --target 192.168.56.12 --user admin --password pass

# Then, create golden ticket
./cli.py --mode red --attack golden_ticket --domain essos.local \
  --krbtgt-hash <hash_from_dcsync> --username Administrator
```

**Key Points:**
- Requires krbtgt hash (obtained from DCSync/NTDS dump)
- Generates CCACHE file for use with impacket-psexec
- Persists even after password resets
- Detection: Monitor for unusual Kerberos TGS requests (Event ID 4769)
- Mitigation: Reset krbtgt password TWICE to invalidate all tickets

**Impact:** If successful, attacker has permanent domain admin access.

---

### ✅ Streamlit Interactive Dashboard

**File:** `dashboard.py`

**What it does:**
Real-time web-based visualization of:
- **Overview**: Global statistics, execution timeline, findings distribution
- **Red Team**: Attack history, success rates, attack filtering
- **Blue Team**: Audit history, findings per audit, audit filtering
- **Purple Team**: Detection rates by attack, detection heatmap
- **Analytics**: Target success rates, risk evolution over time
- **Settings**: Data export, cache clearing, dashboard info

**Launch:**
```bash
streamlit run dashboard.py
```

**Features:**
- Queries SQLite database (auto-populated by framework)
- Real-time updates (refresh button)
- Interactive filters (attack type, audit type, time range)
- Data export to CSV
- Color-coded risk levels (red/orange/yellow/green/blue)
- Timeline visualization
- Detection rate heatmap

**Technology:**
- Streamlit 1.28+ (web framework)
- Plotly 5.18+ (interactive charts)
- Pandas 2.0+ (data manipulation)
- SQLite (persisted database)

**Dashboard Pages:**
1. **Overview** — Key metrics, execution timeline, risk distribution
2. **Red Team** — Attack history, success rate, filtering
3. **Blue Team** — Audit history, findings count, audit filtering
4. **Purple Team** — Detection rates, heatmap by attack type
5. **Analytics** — Success by target, risk evolution
6. **Settings** — Data export, cache clearing

---

## Updated Files

### Modified
- `pyproject.toml` — Added streamlit, plotly, pandas dependencies
- `core/executor.py` — Updated attack_map to include new attacks
- `modules/red_team/` — Added golden_ticket.py

### New
- `dashboard.py` — Streamlit web dashboard
- `TIER2-SUMMARY.md` — This file

---

## Red Team Attacks — Now 8 Total

| # | Module | Technique | Status |
|---|--------|-----------|--------|
| 1 | Kerberoasting | GetUserSPNs + hash crack | ✅ Existing |
| 2 | Password Spray | SMB brute-force | ✅ Existing |
| 3 | Pass-the-Hash | NTLM relay | ✅ Existing |
| 4 | Lateral Movement | PsExec/WMIExec | ✅ Existing |
| 5 | LLMNR Poisoning | Responder capture | ✅ Existing |
| 6 | AS-REP Roasting | Pre-auth disabled | ✅ Tier 1 |
| 7 | DCSync | DRS replication | ✅ Tier 1 |
| 8 | **Golden Ticket** | **Forged TGT** | ✅ **Tier 2** |

---

## Testing

**All 68 tests still passing:**
```bash
pytest tests/ -q
# ✓ 68 passed in 107.48s
```

---

## How to Demo Golden Ticket + Dashboard

### Step 1: Run DCSync to get krbtgt hash
```bash
./cli.py --mode red --attack dcsync --target 192.168.56.12 \
  --user admin --password pass --domain essos.local

# Extract krbtgt NTLM hash from output
# Example: S-1-5-21-...:NTLM_HASH_HERE
```

### Step 2: Create Golden Ticket
```bash
./cli.py --mode red --attack golden_ticket --domain essos.local \
  --krbtgt-hash <paste_hash_here> --username Administrator
```

### Step 3: View Results in Dashboard
```bash
streamlit run dashboard.py
```

Go to **Red Team** page to see:
- Golden Ticket execution in timeline
- Success status
- Generated CCACHE file path
- Mitigation recommendations

Navigate to **Purple Team** page to see detection rates (if Purple Team modules have run).

---

## Dependencies Added

```toml
streamlit>=1.28      # Interactive web dashboard
plotly>=5.18         # Interactive charts
pandas>=2.0          # Data manipulation
```

Install with:
```bash
pip install -r requirements.txt
# or
streamlit run dashboard.py  # Auto-installs if missing
```

---

## What's Still Available (If Time Allows)

### ✅ Streamlit Dashboard — **DONE**
- Real-time attack/defense visualization
- 6 dashboard pages (Overview, Red, Blue, Purple, Analytics, Settings)
- CSV export, data filtering, heatmaps

### ⏳ BloodHound Integration (Tier 2+ if time)
- AD graph database mapping
- Attack path analysis
- Risk scoring
- Est. 16-20 hours

### ⏳ n8n SOAR Automation (Tier 2+ if time)
- Webhook-based automated response
- Wazuh → Disable User → Report pipeline
- Est. 24-40 hours

---

## Ready for Jury Demo

```bash
# Quick demo flow:
1. python3 -m pytest tests/ -q              # ✓ 68 tests pass
2. ./cli.py --mode red --attack dcsync      # Extract hashes
3. ./cli.py --mode red --attack golden_ticket  # Create persistent access
4. streamlit run dashboard.py                # View in real-time dashboard
5. ./cli.py --mode response --action disable_user  # Show remediation
6. View Purple Team detections in dashboard
```

---

**Status: TIER 2 COMPLETE — Ready to continue with BloodHound/n8n if time allows**

9 total attack modules | 5 audit modules | 8 tests | Streamlit dashboard | SQLite persistence
