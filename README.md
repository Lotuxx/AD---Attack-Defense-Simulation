# AD Attacks & Defense Simulation Framework

**Authors:** NISSEKONG Georges Owen — DIOP Salla  
**Year:** 2025-2026

A CLI framework for simulating Active Directory attacks and measuring SIEM detection
coverage using Wazuh. Designed for use in isolated lab environments (GOAD / custom AD).

---

## Architecture

```
ad-attack-defense/
├── cli.py                          # Main entry point
├── config.yaml                     # Lab configuration (IPs, credentials, Wazuh)
├── pyproject.toml                  # Poetry dependency management
├── core/
│   ├── loader.py                   # Dynamic module loader
│   ├── executor.py                 # Module + playbook runner
│   ├── report_generator.py         # TXT / CSV report output
│   ├── wazuh_api.py                # Wazuh REST API client
│   └── logger.py                   # Centralised logging
├── modules/
│   ├── blue_team/                  # Audit modules
│   ├── red_team/                   # Attack simulation modules
│   ├── purple_team/                # Detection validation modules
│   └── response/                   # SOAR remediation modules
├── playbooks/                      # YAML attack/audit chains
├── tests/                          # pytest test suite
├── logs/                           # Runtime logs (auto-created)
└── reports/                        # Generated reports (auto-created)
```

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Lotuxx/AD---Attack-Defense-Simulation
cd AD---Attack-Defense-Simulation

# 2. Install Poetry (if not already installed)
curl -sSL https://install.python-poetry.org | python3 -

# 3. Install dependencies
poetry install

# 4. Activate the virtual environment
poetry shell
```

---

## Configuration

Edit `config.yaml` before running:

```yaml
# GOAD lab example
domain:          "sevenkingdoms.local"
dc_ip:           "192.168.56.10"
domain_user:     "jon.snow"
domain_password: "iknownothing"

wazuh_host:     "192.168.56.20"
wazuh_port:     55000
wazuh_user:     "admin"
wazuh_password: "<wazuh_password>"
verify_ssl:     false
```

---

## Usage

```bash
# Interactive menu
poetry run python cli.py

# Blue Team — full security audit
poetry run python cli.py --mode blue

# Red Team — specific attack
poetry run python cli.py --mode red --attack kerberoasting --target 192.168.56.10

# Red Team — full attack chain playbook
poetry run python cli.py --mode red --playbook full_attack

# Purple Team — detection validation
poetry run python cli.py --mode purple

# Run tests
poetry run pytest

# Run tests with coverage
poetry run pytest --cov=. --cov-report=term-missing
```

---

## Modules

| Team | Module | Description |
|---|---|---|
| Blue | `audit_passwords` | Password policy, weak/expired accounts |
| Blue | `audit_privileges` | Domain Admins, stale admins, Guest account |
| Blue | `audit_gpo` | WDigest, unconstrained delegation, AdminSDHolder |
| Blue | `audit_network` | LLMNR, NBT-NS, SMB Signing, IPv6 |
| Blue | `audit_logs` | Event ID analysis, attack pattern detection |
| Red | `password_spray` | T1110.003 — Password Spraying |
| Red | `kerberoasting` | T1558.003 — Kerberoasting |
| Red | `llmnr_poisoning` | T1557.001 — LLMNR/NBT-NS Poisoning |
| Red | `pth` | T1550.002 — Pass-the-Hash |
| Red | `lateral_mouvement` | T1021.002 / T1047 — PsExec / WMI |
| Purple | `validate_detection` | SIEM detection rate measurement |
| Purple | `fetch_wazuh_alerts` | Wazuh alert retrieval + categorisation |
| Purple | `correlate_attack` | Attack vs alert gap analysis |
| Response | `disable_user` | Disable compromised AD account |
| Response | `block_ip` | Block malicious IP via firewall |
| Response | `reset_password` | Force password reset + ticket invalidation |
| Response | `isolate_host` | Network isolation of compromised machine |

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `pyyaml` | >=6.0 | Config and playbook parsing |
| `impacket` | >=0.12.0 | Kerberoasting, PtH, PsExec, secretsdump |
| `requests` | >=2.31.0 | HTTP client |
| `urllib3` | >=2.0.0 | Wazuh API calls |

**Dev only:** `pytest`, `pytest-cov`, `ruff`

---

## Lab Environment

Tested against **GOAD (Game of Active Directory)** — 5 VMs, 3 domains:

| VM | IP | Domain |
|---|---|---|
| DC01 | 192.168.56.10 | sevenkingdoms.local |
| DC02 | 192.168.56.11 | north.sevenkingdoms.local |
| DC03 | 192.168.56.12 | essos.local |
| SRV02 | 192.168.56.22 | north.sevenkingdoms.local |
| SRV03 | 192.168.56.23 | essos.local |

> ⚠ **This framework must only be used in isolated lab environments.**
> Never run attack modules against production systems or networks you do not own.
