# AD Attack & Defense Simulation Framework

**Complete guide for the comprehensive Active Directory red/blue/purple team training platform.**

## Overview

A production-grade framework for simulating realistic AD security scenarios, combining:
- **Red Team**: 7 attack modules (Kerberoasting, Password Spraying, Pass-the-Hash, Lateral Movement, LLMNR Poisoning, AS-REP Roasting, DCSync)
- **Blue Team**: 5 audit modules (passwords, privileges, GPO, network, logs)
- **Purple Team**: correlation & detection validation against Wazuh/OpenSearch
- **Response/SOAR**: automated remediation via LDAP (works from Kali)
- **Hardening**: Ansible playbook for AD remediation

---

## Installation

### Prerequisites

- **OS**: Linux (Kali/Ubuntu) or Windows with WSL
- **Python**: 3.8+
- **Network**: Access to your lab's DC (ping/LDAP/SMB)
- **Tools**: impacket, nmap, netexec, Responder (mostly auto-installed)

### Setup

```bash
# Clone and install
git clone <your-repo> && cd AD---Attack-Defense-Simulation-test
pip install -r requirements.txt

# Create config
cp config.yaml.example config.yaml
# Edit config.yaml with your lab's DC IP, credentials, Wazuh details
```

### Configuration

Edit `config.yaml`:

```yaml
# ── Active Directory ──────────────────────────────────────────────────
domain:          "essos.local"          # Your AD domain
dc_ip:           "192.168.56.12"        # Domain controller
domain_user:     "Administrator"        # Admin account for attacks
domain_password: "MyPassword123!"        # Use env vars for production

# ── Wazuh / Monitoring ────────────────────────────────────────────────
wazuh_host:      "192.168.56.20"
wazuh_port:      55000
wazuh_user:      "admin"
wazuh_password:  "MyWazuhPass!"         # Or use WAZUH_PASSWORD env var

# ── OpenSearch SSH Tunnel (auto-managed) ──────────────────────────────
opensearch_ssh_host:  "192.168.56.20"
opensearch_ssh_user:  "vagrant"
opensearch_ssh_port:  22
```

**For security**: use environment variables for passwords:
```bash
export DOMAIN_PASSWORD="MyPassword123!"
export WAZUH_PASSWORD="MyWazuhPass!"
# Config will fall back to env vars if set
```

---

## Usage

### Interactive Mode

```bash
./cli.py
# Select target DC from menu
# Choose Red/Blue/Purple/Response mode
```

### Command-Line (Non-Interactive)

#### Red Team Attacks

```bash
# Kerberoasting
./cli.py --mode red --attack kerberoasting --target 192.168.56.12

# Password Spraying
./cli.py --mode red --attack password_spray --target 192.168.56.12

# Pass-the-Hash
./cli.py --mode red --attack pth --target 192.168.56.12

# Lateral Movement (PsExec, WMIExec, SMBExec)
./cli.py --mode red --attack lateral_movement --target 192.168.56.12

# LLMNR Poisoning
./cli.py --mode red --attack llmnr_poisoning --target 192.168.56.12

# AS-REP Roasting (new!)
./cli.py --mode red --attack asrep_roasting --target 192.168.56.12

# DCSync (new!)
./cli.py --mode red --attack dcsync --target 192.168.56.12
```

#### Blue Team Audits

```bash
# Audit all
./cli.py --mode blue --audit all --target 192.168.56.12

# Specific audits
./cli.py --mode blue --audit passwords --target 192.168.56.12
./cli.py --mode blue --audit privileges --target 192.168.56.12
./cli.py --mode blue --audit gpo --target 192.168.56.12
./cli.py --mode blue --audit network --target 192.168.56.12
./cli.py --mode blue --audit logs --target 192.168.56.12
```

#### Purple Team (Detection)

```bash
# Validate detection rates
./cli.py --mode purple

# Correlate attacks with SIEM alerts
./cli.py --mode purple --correlate
```

#### Response/SOAR

```bash
# Disable a compromised account (LDAP, works from Kali)
./cli.py --mode response --action disable_user --username jsmith

# Reset password for compromised account (LDAP, force change at next logon)
./cli.py --mode response --action reset_password --username jsmith
```

### Hardening

```bash
# Preview hardening changes (check mode)
ansible-playbook playbooks/hardening.yml -i hosts.ini --check

# Apply hardening
ansible-playbook playbooks/hardening.yml -i hosts.ini

# See playbooks/hardening.yml for details
```

---

## Modules

### Red Team Attacks

| Module | Target | Technique | Success Indicator |
|--------|--------|-----------|-------------------|
| `kerberoasting.py` | DC | GetUserSPNs + hash extraction | TGS hashes obtained |
| `password_spray.py` | DC | SMB auth with common passwords | Valid credentials found |
| `pth.py` | DC | NTLM relay or WMI auth | SYSTEM access obtained |
| `lateral_mouvement.py` | Hosts | PsExec/WMIExec | Command execution on target |
| `llmnr_poisoning.py` | Network | Responder capture | NTLMv2 hashes captured |
| **`asrep_roasting.py`** (NEW) | DC | GetNPUsers for pre-auth disabled | AS-REP hashes obtained |
| **`dcsync.py`** (NEW) | DC | DRS replication | NTDS.dit hashes extracted |

### Blue Team Audits

| Module | Method | Checks |
|--------|--------|--------|
| `audit_passwords.py` | LDAP | Password policy, expiration, never-expires accounts |
| `audit_privileges.py` | LDAP | Domain Admins members, stale logons, Guest account |
| `audit_gpo.py` | LDAP | Unconstrained delegation, krbtgt age, AS-REP roastable |
| `audit_network.py` | nmap + netexec | SMB signing, open shares, Print Spooler |
| `audit_logs.py` | PowerShell | Event ID thresholds, audit policy, log retention |

### Response Modules (NEW — LDAP-based, works from Kali!)

| Module | Action | Method |
|--------|--------|--------|
| **`disable_user.py`** | Disable compromised account | LDAP (set userAccountControl flag) |
| **`reset_password.py`** | Reset password + force change | LDAP (set pwdLastSet to 0) |
| `block_ip.py` | Block IP address | iptables (Linux) |
| `isolate_host.py` | Network isolation | Windows firewall (env-specific) |

---

## Reports

All reports are **PDF-only** (production-ready, jury-friendly):

```bash
# View reports
./cli.py --mode blue --audit all --target 192.168.56.12
# → Generates: reports/blue_team_audit_20260708_123456.pdf

# Browse past reports
./cli.py --list-reports
```

Reports include:
- Cover page (title, timestamp, authors)
- Per-module findings (color-coded by risk level: red/orange/yellow/blue)
- Aggregated summary (total findings, critical count)

---

## Architecture

```
├── core/
│   ├── config.py              # Centralized config loading + env-var override
│   ├── executor.py            # Module orchestration + credential injection
│   ├── loader.py              # Dynamic module loading
│   ├── wazuh_api.py           # Wazuh API + OpenSearch queries
│   ├── ssh_tunnel.py          # Auto-managed persistent SSH tunnel (new!)
│   ├── report_generator.py    # PDF report generation (new!)
│   └── logger.py              # Framework logging
│
├── modules/
│   ├── red_team/              # 7 attack modules
│   ├── blue_team/             # 5 audit modules
│   ├── purple_team/           # Detection correlation
│   └── response/              # SOAR remediation (LDAP-based)
│
├── utils/
│   ├── format_utils.py        # Terminal output formatting
│   └── [others]
│
├── tests/
│   ├── test_core.py           # 48 core tests (68 total, coverage 54%)
│   └── test_modules.py        # 20 module tests
│
├── playbooks/
│   └── hardening.yml          # Ansible AD hardening playbook (new!)
│
├── config.yaml.example        # Lab configuration template
└── cli.py                      # Command-line interface
```

## Testing

### Run All Tests

```bash
pytest tests/ -v
# → 68 tests pass (coverage: core 98%, modules 58%, utils 82%)
```

### Coverage Report

```bash
pytest tests/ --cov=core --cov=modules --cov=utils --cov-report=term-missing
```

---

## Lab Verification Checklist

Before demoing to a jury, verify:

- [ ] **DC reachable**: `ping <dc_ip>`
- [ ] **Credentials work**: `./cli.py --mode blue --audit passwords` should connect to DC
- [ ] **Wazuh running**: Check Wazuh dashboard, agents active
- [ ] **SSH tunnel**: For Purple Team to work, ensure OpenSearch SSH tunnel config is set
- [ ] **All reports generated**: `reports/` folder has recent PDFs
- [ ] **Tests pass**: `pytest tests/ -q` → 68 passed

---

## Common Issues

### "PowerShell not found" (response modules)
**Solution**: Fixed in this version! Response modules now use LDAP instead of PowerShell.
Works from Kali without PowerShell.

### "LDAPException: Invalid credentials"
- Verify `domain_user`, `domain_password` in config.yaml
- Try: `./cli.py --mode blue --audit passwords` (simplest LDAP test)

### "SSH tunnel not working" (Purple Team)
- Check `opensearch_ssh_host`, `opensearch_ssh_user` in config.yaml
- Verify SSH key or password auth works: `ssh user@host` manually first
- Tunnel logs in `.ssh_tunnel_state`

### "Wazuh alerts not found"
- Verify Wazuh API is running: `curl http://wazuh_host:55000`
- Check OpenSearch tunnel: `nc -zv localhost 9200`
- Verify custom rule IDs (60122, 100001, 100002) exist in Wazuh

---

## Authors

**NISSEKONG Georges Owen** | **DIOP Salla**

---

## License

Educational lab framework — use only in authorized environments.

---

## Next Steps

1. **Configure** `config.yaml` with your lab details
2. **Test connectivity** with `./cli.py --mode blue --audit passwords`
3. **Run a simple attack** like `./cli.py --mode red --attack kerberoasting`
4. **Generate a report** and review the PDF
5. **Apply hardening** with `ansible-playbook playbooks/hardening.yml`
6. **Verify detections** with `./cli.py --mode purple`

---

## Support

For issues, check:
- `logs/framework_*.log` for framework errors
- Test logs: `pytest tests/ -v` for unit test failures
- SSH tunnel status: `.ssh_tunnel_state` file
- Wazuh API: `curl -u admin:pass https://wazuh_host:55000/security/me`

Happy learning!
