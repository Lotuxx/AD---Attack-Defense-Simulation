#!/usr/bin/env python3
"""
AD Attacks & Defense Simulation Framework — Main CLI Entry Point
================================================================
Authors : NISSEKONG Georges Owen, DIOP Salla
Year    : 2025-2026

This is the main entry point of the framework. It provides both an
interactive menu-driven interface and a non-interactive CLI mode.

Usage:
    python3 cli.py                        # Interactive mode
    python3 cli.py --mode blue            # Full Blue Team audit
    python3 cli.py --mode red --attack kerberoasting
    python3 cli.py --mode purple          # Detection validation
    python3 cli.py --mode red --playbook full_attack
"""

import sys
import os

# ── Ensure project root is always in sys.path ─────────────────────────────────
# This must happen before any local imports so that 'modules.*' and 'core.*'
# can always be resolved regardless of where the script is invoked from.
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import time
from datetime import datetime

# Core framework components
from core.loader import ModuleLoader
from core.executor import Executor
from core.logger import FrameworkLogger
from core.report_generator import ReportGenerator

# Display utilities (colors, banners, menus)
from utils.format_utils import (
    print_banner, print_menu, print_success, print_error,
    print_warning, print_info, print_separator, Colors
)

# Module-level logger instance
logger = FrameworkLogger("CLI")


def parse_args():
    """
    Parse command-line arguments for non-interactive mode.

    Returns:
        argparse.Namespace: Parsed arguments with mode, attack, playbook, etc.
    """
    parser = argparse.ArgumentParser(
        description="AD Attacks & Defense Simulation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py                                   # Interactive mode
  python cli.py --mode blue                       # Full Blue Team audit
  python cli.py --mode red --attack kerberoasting
  python cli.py --mode purple                     # Purple Team validation
  python cli.py --mode red --playbook full_attack
        """
    )
    parser.add_argument("--mode", choices=["blue", "red", "purple", "stats"],
                        help="Execution mode (blue/red/purple)")
    parser.add_argument("--attack",   help="Specific attack to run (red mode)")
    parser.add_argument("--audit",    help="Specific audit to run (blue mode)")
    parser.add_argument("--playbook", help="YAML playbook to execute")
    parser.add_argument("--target",   default="localhost", help="Target IP/hostname")
    parser.add_argument("--domain",   default="domain.local", help="AD domain name")
    parser.add_argument("--output",   choices=["pdf"], default="pdf",
                        help="Report output format (PDF only)")
    parser.add_argument("--no-banner", action="store_true", help="Disable ASCII banner")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return parser.parse_args()


def interactive_mode(executor: Executor, report_gen: ReportGenerator):
    """
    Run the framework in interactive menu mode.
    Loops until the user selects 'Quit'.

    Args:
        executor   : Executor instance to run modules and playbooks.
        report_gen : ReportGenerator instance to produce reports.
    """
    while True:
        # Display main menu options
        print_menu("MAIN MENU", [
            ("1", "Blue Team   — AD Security Audit"),
            ("2", "Red Team    — Attack Simulation"),
            ("3", "Purple Team — Detection Validation"),
            ("4", "Response    — SOAR Remediation Actions"),
            ("5", "Reports     — View Generated Reports"),
            ("6", "Configuration"),
            ("0", "Quit"),
        ])

        choice = input(f"\n{Colors.BOLD}[>] Your choice: {Colors.RESET}").strip()

        # Route user choice to the appropriate sub-menu
        if   choice == "1": blue_team_menu(executor, report_gen)
        elif choice == "2": red_team_menu(executor, report_gen)
        elif choice == "3": purple_team_menu(executor, report_gen)
        elif choice == "4": response_menu(executor, report_gen)
        elif choice == "5": reports_menu(report_gen)
        elif choice == "6": config_menu()
        elif choice == "0":
            print_info("Goodbye!")
            sys.exit(0)
        else:
            print_error("Invalid choice. Please try again.")


def blue_team_menu(executor: Executor, report_gen: ReportGenerator):
    """
    Blue Team sub-menu — AD security audits.
    Each option maps to a specific audit module or playbook.

    Args:
        executor   : Executor instance.
        report_gen : ReportGenerator instance.
    """
    while True:
        print_menu("BLUE TEAM — SECURITY AUDIT", [
            ("1", "Full audit (recommended)"),
            ("2", "Password policy audit"),
            ("3", "Privileged accounts audit"),
            ("4", "AD configuration / GPO audit"),
            ("5", "Network audit (LLMNR, SMB Signing)"),
            ("6", "Log audit (critical Event IDs)"),
            ("7", "Playbook: audit_basic"),
            ("8", "Playbook: audit_advanced"),
            ("0", "Back"),
        ])

        choice = input(f"\n{Colors.BOLD}[>] Your choice: {Colors.RESET}").strip()

        # Map menu choices to module paths and function names
        modules_map = {
            "2": ("blue_team.audit_passwords",  "run_audit"),
            "3": ("blue_team.audit_privileges", "run_audit"),
            "4": ("blue_team.audit_gpo",        "run_audit"),
            "5": ("blue_team.audit_network",    "run_audit"),
            "6": ("blue_team.audit_logs",       "run_audit"),
        }

        if choice == "1":
            run_full_blue_audit(executor, report_gen)
        elif choice in modules_map:
            module_path, func = modules_map[choice]
            results = executor.run_module(module_path, func)
            report_gen.generate(results, "blue_team", output_format="pdf")
        elif choice == "7":
            executor.run_playbook("blue_team/audit_basic.yaml")
        elif choice == "8":
            executor.run_playbook("blue_team/audit_advanced.yaml")
        elif choice == "0":
            break
        else:
            print_error("Invalid choice.")


def run_full_blue_audit(executor: Executor, report_gen: ReportGenerator):
    """
    Execute all Blue Team audit modules sequentially and generate a combined report.

    This function runs every audit module one after another, collects all results
    into a single list, then generates both TXT and CSV reports.

    Args:
        executor   : Executor instance.
        report_gen : ReportGenerator instance.
    """
    # Define all audit modules to run in order
    audits = [
        ("blue_team.audit_passwords",  "Password policy audit"),
        ("blue_team.audit_privileges", "Privileged accounts audit"),
        ("blue_team.audit_gpo",        "GPO / AD configuration audit"),
        ("blue_team.audit_network",    "Network audit"),
        ("blue_team.audit_logs",       "Log audit"),
    ]

    print_separator("FULL BLUE TEAM AUDIT")
    all_results = []

    # Run each audit module and collect results
    for module_path, label in audits:
        print_info(f"Running: {label}...")
        result = executor.run_module(module_path, "run_audit")
        all_results.append(result)
        time.sleep(0.3)  # Small delay for readability

    # Generate combined report from all audit results
    report_gen.generate(all_results, "blue_team_full", output_format="pdf")
    print_success("Full audit complete. Report saved in /reports/")


def red_team_menu(executor: Executor, report_gen: ReportGenerator):
    """
    Red Team sub-menu — attack simulation.
    Each option maps to a specific attack module or playbook.
    Always asks for confirmation before executing an attack.

    Args:
        executor   : Executor instance.
        report_gen : ReportGenerator instance.
    """
    while True:
        print_menu("RED TEAM — ATTACK SIMULATION", [
            ("1", "Full attack chain (full_attack playbook)"),
            ("2", "Password Spraying        [Initial Access]"),
            ("3", "Kerberoasting            [Credential Access]"),
            ("4", "LLMNR/NBT-NS Poisoning   [Credential Access]"),
            ("5", "Pass-the-Hash            [Privilege Escalation]"),
            ("6", "Lateral Movement (PsExec/WMI)"),
            ("7", "Playbook: initial_access"),
            ("8", "Playbook: privesc"),
            ("0", "Back"),
        ])

        print_warning("⚠  Attacks must ONLY be run in the isolated lab environment!")
        choice = input(f"\n{Colors.BOLD}[>] Your choice: {Colors.RESET}").strip()

        # Map choices to (module_path, function, display_label)
        attacks_map = {
            "2": ("red_team.password_spray",    "run_attack", "Password Spraying"),
            "3": ("red_team.kerberoasting",     "run_attack", "Kerberoasting"),
            "4": ("red_team.llmnr_poisoning",   "run_attack", "LLMNR Poisoning"),
            "5": ("red_team.pth",               "run_attack", "Pass-the-Hash"),
            "6": ("red_team.lateral_mouvement", "run_attack", "Lateral Movement"),
        }

        if choice == "1":
            executor.run_playbook("red_team/full_attack.yaml")
        elif choice in attacks_map:
            module_path, func, label = attacks_map[choice]
            # Prompt for target and require explicit confirmation
            target  = input(f"  Target (IP/hostname) [{Colors.CYAN}domain.local{Colors.RESET}]: ").strip() or "domain.local"
            confirm = input(f"{Colors.RED}  Confirm attack '{label}' on {target}? [yes/N]: {Colors.RESET}").strip().lower()
            if confirm == "yes":
                results = executor.run_module(module_path, func, target=target)
                report_gen.generate(results, f"red_team_{label.lower().replace(' ', '_')}", output_format="pdf")
            else:
                print_info("Attack cancelled.")
        elif choice == "7":
            executor.run_playbook("red_team/initial_access.yaml")
        elif choice == "8":
            executor.run_playbook("red_team/privesc.yaml")
        elif choice == "0":
            break
        else:
            print_error("Invalid choice.")


def purple_team_menu(executor: Executor, report_gen: ReportGenerator):
    """
    Purple Team sub-menu — detection validation.
    Fetches Wazuh alerts and correlates them with executed attacks.

    Args:
        executor   : Executor instance.
        report_gen : ReportGenerator instance.
    """
    while True:
        print_menu("PURPLE TEAM — DETECTION VALIDATION", [
            ("1", "Validate detection (all attacks)"),
            ("2", "Fetch Wazuh alerts"),
            ("3", "Correlate attacks / alerts"),
            ("4", "Playbook: detection_validation"),
            ("5", "Playbook: full_purple_chain"),
            ("0", "Back"),
        ])

        choice = input(f"\n{Colors.BOLD}[>] Your choice: {Colors.RESET}").strip()

        # Map choices to purple team modules
        purple_map = {
            "2": ("purple_team.fetch_wazuh_alerts", "run"),
            "3": ("purple_team.correlate_attack",   "run"),
        }

        if choice == "1":
            results = executor.run_module("purple_team.validate_detection", "run")
            report_gen.generate(results, "purple_team_validation", output_format="pdf")
        elif choice in purple_map:
            module_path, func = purple_map[choice]
            results = executor.run_module(module_path, func)
            report_gen.generate(results, "purple_team", output_format="pdf")
        elif choice == "4":
            executor.run_playbook("purple_team/detection_validation.yaml")
        elif choice == "5":
            executor.run_playbook("purple_team/full_purple_chain.yaml")
        elif choice == "0":
            break
        else:
            print_error("Invalid choice.")


def response_menu(executor: Executor, report_gen: ReportGenerator):
    """
    Response / SOAR sub-menu — remediation actions.
    These actions have immediate impact on the environment and require confirmation.

    Args:
        executor   : Executor instance.
        report_gen : ReportGenerator instance.
    """
    while True:
        print_menu("RESPONSE — SOAR REMEDIATION", [
            ("1", "Disable a compromised account"),
            ("2", "Block an IP address"),
            ("3", "Reset a user password"),
            ("4", "Isolate a machine from the network"),
            ("0", "Back"),
        ])
        print_warning("⚠  These actions have immediate impact on the environment!")
        choice = input(f"\n{Colors.BOLD}[>] Your choice: {Colors.RESET}").strip()

        if choice == "1":
            # Collect parameters and confirm before disabling account
            username = input("  Account to disable: ").strip()
            reason   = input("  Reason [Detected compromise]: ").strip() or "Detected compromise"
            confirm  = input(f"{Colors.RED}  Confirm disabling '{username}'? [yes/N]: {Colors.RESET}").strip().lower()
            if confirm == "yes":
                results = executor.run_module("response.disable_user", "run",
                                              username=username, reason=reason)
                report_gen.generate(results, f"response_disable_{username}", output_format="pdf")

        elif choice == "2":
            # Collect IP blocking parameters
            ip        = input("  IP address to block: ").strip()
            direction = input("  Direction [both/in/out]: ").strip() or "both"
            duration  = input("  Duration in minutes (0 = permanent) [0]: ").strip() or "0"
            confirm   = input(f"{Colors.RED}  Confirm blocking {ip}? [yes/N]: {Colors.RESET}").strip().lower()
            if confirm == "yes":
                results = executor.run_module("response.block_ip", "run",
                                              ip=ip, direction=direction,
                                              duration_min=int(duration))
                report_gen.generate(results, f"response_block_{ip.replace('.','_')}", output_format="pdf")

        elif choice == "3":
            # Reset password — new password is shown only to operator, never saved in report
            username = input("  Account to reset password for: ").strip()
            confirm  = input(f"{Colors.RED}  Confirm password reset for '{username}'? [yes/N]: {Colors.RESET}").strip().lower()
            if confirm == "yes":
                results = executor.run_module("response.reset_password", "run", username=username)
                # Display new password to operator via secure channel (not saved in report)
                new_pwd = results.get("new_password", "")
                if new_pwd:
                    print_success(f"New password (transmit securely): {Colors.YELLOW}{new_pwd}{Colors.RESET}")
                # Strip password before saving to report file
                results.pop("new_password", None)
                report_gen.generate(results, f"response_reset_{username}", output_format="pdf")

        elif choice == "4":
            # Isolate host — keeps management ports open for analyst
            host    = input("  IP or hostname of machine to isolate: ").strip()
            mgmt_ip = input("  Analyst IP (allowed during isolation): ").strip() or None
            confirm = input(f"{Colors.RED}  Confirm isolating '{host}'? [yes/N]: {Colors.RESET}").strip().lower()
            if confirm == "yes":
                results = executor.run_module("response.isolate_host", "run",
                                              host=host, management_ip=mgmt_ip)
                report_gen.generate(results, f"response_isolate_{host.replace('.','_')}", output_format="pdf")

        elif choice == "0":
            break
        else:
            print_error("Invalid choice.")


def reports_menu(report_gen: ReportGenerator):
    """
    Display and browse previously generated reports stored in /reports/.

    Args:
        report_gen : ReportGenerator instance (used for path resolution).
    """
    print_separator("AVAILABLE REPORTS")
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")

    # Check if any reports exist
    if not os.path.exists(reports_dir) or not os.listdir(reports_dir):
        print_warning("No reports found. Run an audit or attack first.")
        return

    # List reports sorted by most recent first
    files = sorted(os.listdir(reports_dir), reverse=True)
    for i, f in enumerate(files, 1):
        size = os.path.getsize(os.path.join(reports_dir, f))
        print(f"  {Colors.CYAN}[{i}]{Colors.RESET} {f}  ({size} bytes)")

    choice = input(f"\n{Colors.BOLD}[>] Number to display (0 to go back): {Colors.RESET}").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(files):
        path = os.path.join(reports_dir, files[int(choice) - 1])
        print(f"\n{Colors.CYAN}" + "─" * 60 + Colors.RESET)
        if path.lower().endswith(".pdf"):
            # PDFs are binary — extract text for a terminal-friendly preview
            # instead of dumping raw bytes.
            try:
                import pdfplumber
                with pdfplumber.open(path) as pdf:
                    for page in pdf.pages:
                        text = page.extract_text()
                        if text:
                            print(text)
            except Exception as e:
                print_warning(f"Impossible d'extraire le contenu du PDF pour aperçu : {e}")
            print(f"\n{Colors.CYAN}[i] Fichier complet : {path}{Colors.RESET}")
        else:
            # Legacy .txt/.csv reports from before the PDF-only switch
            with open(path) as f:
                print(f.read())
        print(Colors.CYAN + "─" * 60 + Colors.RESET)


def config_menu():
    """
    Display the current configuration from config.yaml.
    Allows operators to review settings before running modules.
    """
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    print_separator("CONFIGURATION")
    if os.path.exists(config_path):
        with open(config_path) as f:
            print(f.read())
    else:
        print_warning("config.yaml not found.")
    input("\n  [Press Enter to continue]")



def _select_target(skip: bool = False):
    """
    Demande a l utilisateur de choisir la cible.

    Args:
        skip (bool): If True, don't prompt — used when --target was already
                     provided on the command line, or when running in
                     non-interactive mode (--mode), where blocking on input()
                     would hang a scripted/automated invocation.
    """
    if skip:
        return

    import yaml, os
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")

    targets = {
        "1": {"domain": "sevenkingdoms.local", "dc_ip": "192.168.56.10", "domain_user": "administrator", "domain_password": "8dCT-DJjgScp"},
        "2": {"domain": "essos.local",          "dc_ip": "192.168.56.12", "domain_user": "vagrant",        "domain_password": "vagrant"},
        "3": {"domain": "essos.local",          "dc_ip": "192.168.56.22", "domain_user": "vagrant",        "domain_password": "vagrant"},
        "4": {"domain": "essos.local",          "dc_ip": "192.168.56.23", "domain_user": "vagrant",        "domain_password": "vagrant"},
    }

    print(f"\n{Colors.CYAN}{'─'*55}{Colors.RESET}")
    print(f"{Colors.BOLD}  Selectionner la cible :{Colors.RESET}")
    print(f"  [1] DC01  — sevenkingdoms.local  (192.168.56.10)")
    print(f"  [2] DC03  — essos.local          (192.168.56.12)")
    print(f"  [3] SRV02 — MEEREEN essos.local  (192.168.56.22)")
    print(f"  [4] SRV03 — BRAAVOS essos.local  (192.168.56.23)")
    print(f"  [0] Garder la config actuelle")
    print(f"{Colors.CYAN}{'─'*55}{Colors.RESET}")

    choice = input(f"{Colors.BOLD}[>] Votre choix: {Colors.RESET}").strip()

    if choice in targets:
        t = targets[choice]
        with open(config_path) as f:
            cfg = yaml.safe_load(f) or {}
        # Mettre à jour UNIQUEMENT les champs liés à la cible
        cfg["dc_ip"]          = t["dc_ip"]
        cfg["domain"]         = t["domain"]
        cfg["domain_user"]    = t["domain_user"]
        cfg["domain_password"] = t["domain_password"]
        # Garder intact : wazuh, opensearch, kali_ip, etc.
        with open(config_path, "w") as f:
            yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)
        print_success(f"Cible : {t['domain']} ({t['dc_ip']})")
        print_info(f"  User     : {t['domain_user']}")
        print_info(f"  Wazuh    : {cfg.get('wazuh_host', 'N/A')} (inchangé)")
        print_info(f"  Kali IP  : {cfg.get('kali_ip', 'N/A')} (inchangé)")


def _show_stats():
    """Affiche les statistiques globales depuis la base de données."""
    from core.database import DatabaseManager
    db = DatabaseManager()

    print(f"\n{Colors.CYAN}{'═'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  STATISTIQUES GLOBALES — AD Attack & Defense{Colors.RESET}")
    print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}\n")

    stats = db.get_global_stats()
    print(f"{Colors.BOLD}  Exécutions Red Team :{Colors.RESET}")
    print(f"    Total          : {stats['total_executions']}")
    print(f"    Réussies       : {stats['successful_attacks']}")
    print(f"    Taux de succès : {Colors.GREEN}{stats['success_rate']}%{Colors.RESET}\n")

    print(f"{Colors.BOLD}  Findings Blue Team :{Colors.RESET}")
    findings = db.get_findings_summary()
    for level, count in findings.items():
        color = Colors.RED if level in ('Critique', 'Élevé') else Colors.YELLOW if level == 'Moyen' else Colors.GREEN
        print(f"    {level:<12} : {color}{count}{Colors.RESET}")
    print(f"    Total          : {stats['total_findings']}")
    print(f"    Critiques/Élevés: {Colors.RED}{stats['critical_findings']}{Colors.RESET}\n")

    print(f"{Colors.BOLD}  Détection Wazuh :{Colors.RESET}")
    rates = db.get_detection_rate()
    for attack, data in rates.items():
        color = Colors.GREEN if data['rate'] >= 80 else Colors.YELLOW if data['rate'] >= 50 else Colors.RED
        print(f"    {attack:<22} : {color}{data['rate']}%{Colors.RESET} ({data['runs']} run(s))")
    print(f"    Taux global    : {Colors.GREEN}{stats['avg_detection_rate']}%{Colors.RESET}\n")

    print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}\n")


def main():
    """
    Main entry point — parses arguments and launches the appropriate mode.

    In non-interactive mode (--mode flag), executes the requested operation
    directly without showing menus. In interactive mode, starts the main menu loop.
    """
    args = parse_args()

    # Print ASCII banner unless explicitly disabled
    if not args.no_banner:
        print_banner()

    # Selection de la cible — skip the interactive prompt if --target was
    # already given explicitly, or if we're running non-interactively
    # (--mode), where blocking on input() would hang a scripted invocation.
    _select_target(skip=("--target" in sys.argv))

    # Initialise core framework components
    loader     = ModuleLoader()
    executor   = Executor(loader, verbose=args.verbose)
    report_gen = ReportGenerator(
        output_format=args.output,
        secrets=[
            executor.config.domain_password,
            executor.config.wazuh_password,
            executor.config.opensearch_password,
        ],
    )

    # ── Non-interactive mode ──────────────────────────────────────────────────
    if args.mode:
        if args.mode == "blue":
            if args.playbook:
                # Run a specific Blue Team playbook by name
                executor.run_playbook(f"blue_team/{args.playbook}.yaml")
            elif args.audit:
                # Run a single audit module
                results = executor.run_module(f"blue_team.{args.audit}", "run_audit")
                report_gen.generate(results, f"blue_{args.audit}", args.output)
            else:
                # Default: run full Blue Team audit
                run_full_blue_audit(executor, report_gen)

        elif args.mode == "red":
            if args.playbook:
                executor.run_playbook(f"red_team/{args.playbook}.yaml")
            elif args.attack:
                # Run a specific attack module with target and domain
                results = executor.run_module(f"red_team.{args.attack}", "run_attack",
                                              target=args.target, domain=args.domain)
                report_gen.generate(results, f"red_{args.attack}", args.output)
            else:
                print_error("--mode red requires --attack <name> or --playbook <name>")
                sys.exit(1)

        elif args.mode == "purple":
            if args.playbook:
                executor.run_playbook(f"purple_team/{args.playbook}.yaml")
            else:
                # Default: run full detection validation
                results = executor.run_module("purple_team.validate_detection", "run")
                report_gen.generate(results, "purple_validation", args.output)
        elif args.mode == "stats":
            _show_stats()
    else:
        # ── Interactive mode ──────────────────────────────────────────────────
        interactive_mode(executor, report_gen)


if __name__ == "__main__":
    main()
