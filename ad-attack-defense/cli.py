#!/usr/bin/env python3
"""
AD Attacks & Defense Simulation Framework
Authors: NISSEKONG Georges Owen, DIOP Salla
"""

import sys
import os

# Ensure project root is in sys.path regardless of invocation directory
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
import argparse
import time
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.loader import ModuleLoader
from core.executor import Executor
from core.logger import FrameworkLogger
from core.report_generator import ReportGenerator
from utils.format_utils import (
    print_banner, print_menu, print_success, print_error,
    print_warning, print_info, print_separator, Colors
)

logger = FrameworkLogger("CLI")


def parse_args():
    parser = argparse.ArgumentParser(
        description="AD Attacks & Defense Simulation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py                         # Interactive mode
  python cli.py --mode blue             # Blue Team audit
  python cli.py --mode red --attack kerberoasting
  python cli.py --mode purple           # Purple Team validation
  python cli.py --mode red --playbook full_attack
        """
    )
    parser.add_argument("--mode", choices=["blue", "red", "purple"],
                        help="Mode d'exécution (blue/red/purple)")
    parser.add_argument("--attack", help="Attaque spécifique à lancer (mode red)")
    parser.add_argument("--audit", help="Audit spécifique à lancer (mode blue)")
    parser.add_argument("--playbook", help="Playbook YAML à exécuter")
    parser.add_argument("--target", default="localhost", help="IP/hostname cible")
    parser.add_argument("--domain", default="domain.local", help="Domaine AD")
    parser.add_argument("--output", choices=["txt", "csv", "both"], default="both",
                        help="Format de rapport")
    parser.add_argument("--no-banner", action="store_true", help="Désactiver le banner")
    parser.add_argument("--verbose", "-v", action="store_true", help="Mode verbose")
    return parser.parse_args()


def interactive_mode(executor: Executor, report_gen: ReportGenerator):
    """Main interactive loop."""
    while True:
        print_menu("MENU PRINCIPAL", [
            ("1", "Blue Team  — Audit de sécurité AD"),
            ("2", "Red Team   — Simulation d'attaques"),
            ("3", "Purple Team — Validation de détection"),
            ("4", "Response   — Actions de remédiation SOAR"),
            ("5", "Rapports   — Consulter les rapports"),
            ("6", "Configuration"),
            ("0", "Quitter"),
        ])

        choice = input(f"\n{Colors.BOLD}[>] Votre choix : {Colors.RESET}").strip()

        if choice == "1":
            blue_team_menu(executor, report_gen)
        elif choice == "2":
            red_team_menu(executor, report_gen)
        elif choice == "3":
            purple_team_menu(executor, report_gen)
        elif choice == "4":
            response_menu(executor, report_gen)
        elif choice == "5":
            reports_menu(report_gen)
        elif choice == "6":
            config_menu()
        elif choice == "0":
            print_info("Au revoir !")
            sys.exit(0)
        else:
            print_error("Choix invalide. Réessayez.")


def blue_team_menu(executor: Executor, report_gen: ReportGenerator):
    """Blue Team sub-menu."""
    while True:
        print_menu("BLUE TEAM — AUDIT DE SÉCURITÉ", [
            ("1", "Audit complet (recommandé)"),
            ("2", "Audit des mots de passe"),
            ("3", "Audit des comptes à privilèges"),
            ("4", "Audit des configurations AD / GPO"),
            ("5", "Audit réseau (LLMNR, SMB Signing)"),
            ("6", "Audit des logs (Event IDs critiques)"),
            ("7", "Playbook : audit_basic"),
            ("8", "Playbook : audit_advanced"),
            ("0", "Retour"),
        ])

        choice = input(f"\n{Colors.BOLD}[>] Votre choix : {Colors.RESET}").strip()

        modules_map = {
            "2": ("blue_team.audit_passwords", "run_audit"),
            "3": ("blue_team.audit_privileges", "run_audit"),
            "4": ("blue_team.audit_gpo", "run_audit"),
            "5": ("blue_team.audit_network", "run_audit"),
            "6": ("blue_team.audit_logs", "run_audit"),
        }

        if choice == "1":
            run_full_blue_audit(executor, report_gen)
        elif choice in modules_map:
            module_path, func = modules_map[choice]
            results = executor.run_module(module_path, func)
            report_gen.generate(results, "blue_team", output_format="both")
        elif choice == "7":
            executor.run_playbook("blue_team/audit_basic.yaml")
        elif choice == "8":
            executor.run_playbook("blue_team/audit_advanced.yaml")
        elif choice == "0":
            break
        else:
            print_error("Choix invalide.")


def run_full_blue_audit(executor: Executor, report_gen: ReportGenerator):
    """Run all blue team audits sequentially."""
    audits = [
        ("blue_team.audit_passwords",  "Audit des mots de passe"),
        ("blue_team.audit_privileges", "Audit des privilèges"),
        ("blue_team.audit_gpo",        "Audit GPO / config AD"),
        ("blue_team.audit_network",    "Audit réseau"),
        ("blue_team.audit_logs",       "Audit des logs"),
    ]

    print_separator("AUDIT COMPLET BLUE TEAM")
    all_results = []

    for module_path, label in audits:
        print_info(f"Lancement : {label}...")
        result = executor.run_module(module_path, "run_audit")
        all_results.append(result)
        time.sleep(0.3)

    report_gen.generate(all_results, "blue_team_full", output_format="both")
    print_success("Audit complet terminé. Rapport généré dans /reports/")


def red_team_menu(executor: Executor, report_gen: ReportGenerator):
    """Red Team sub-menu."""
    while True:
        print_menu("RED TEAM — SIMULATION D'ATTAQUES", [
            ("1", "Chaîne complète (full_attack)"),
            ("2", "Password Spraying       [Initial Access]"),
            ("3", "Kerberoasting           [Credential Access]"),
            ("4", "LLMNR/NBT-NS Poisoning  [Credential Access]"),
            ("5", "Pass-the-Hash           [Privilege Escalation]"),
            ("6", "Lateral Movement (PsExec/WMI)"),
            ("7", "Playbook : initial_access"),
            ("8", "Playbook : privesc"),
            ("0", "Retour"),
        ])

        print_warning("⚠  Les attaques ne doivent être exécutées que dans le lab isolé !")
        choice = input(f"\n{Colors.BOLD}[>] Votre choix : {Colors.RESET}").strip()

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
            target = input(f"  Cible (IP/hostname) [{Colors.CYAN}domain.local{Colors.RESET}] : ").strip() or "domain.local"
            confirm = input(f"{Colors.RED}  Confirmer l'attaque '{label}' sur {target} ? [oui/N] : {Colors.RESET}").strip().lower()
            if confirm == "oui":
                results = executor.run_module(module_path, func, target=target)
                report_gen.generate(results, f"red_team_{label.lower().replace(' ', '_')}", output_format="both")
            else:
                print_info("Attaque annulée.")
        elif choice == "7":
            executor.run_playbook("red_team/initial_access.yaml")
        elif choice == "8":
            executor.run_playbook("red_team/privesc.yaml")
        elif choice == "0":
            break
        else:
            print_error("Choix invalide.")


def purple_team_menu(executor: Executor, report_gen: ReportGenerator):
    """Purple Team sub-menu."""
    while True:
        print_menu("PURPLE TEAM — VALIDATION DE DÉTECTION", [
            ("1", "Valider la détection (toutes attaques)"),
            ("2", "Récupérer les alertes Wazuh"),
            ("3", "Corréler attaques / alertes"),
            ("4", "Playbook : detection_validation"),
            ("5", "Playbook : full_purple_chain"),
            ("0", "Retour"),
        ])

        choice = input(f"\n{Colors.BOLD}[>] Votre choix : {Colors.RESET}").strip()

        purple_map = {
            "2": ("purple_team.fetch_wazuh_alerts",  "run"),
            "3": ("purple_team.correlate_attack",    "run"),
        }

        if choice == "1":
            results = executor.run_module("purple_team.validate_detection", "run")
            report_gen.generate(results, "purple_team_validation", output_format="both")
        elif choice in purple_map:
            module_path, func = purple_map[choice]
            results = executor.run_module(module_path, func)
            report_gen.generate(results, "purple_team", output_format="both")
        elif choice == "4":
            executor.run_playbook("purple_team/detection_validation.yaml")
        elif choice == "5":
            executor.run_playbook("purple_team/full_purple_chain.yaml")
        elif choice == "0":
            break
        else:
            print_error("Choix invalide.")


def response_menu(executor: Executor, report_gen: ReportGenerator):
    """Response / SOAR sub-menu."""
    while True:
        print_menu("RESPONSE — REMÉDIATION SOAR", [
            ("1", "Désactiver un compte compromis"),
            ("2", "Bloquer une adresse IP"),
            ("3", "Réinitialiser un mot de passe"),
            ("4", "Isoler une machine du réseau"),
            ("0", "Retour"),
        ])
        print_warning("⚠  Ces actions ont un impact immédiat sur l'environnement !")
        choice = input(f"\n{Colors.BOLD}[>] Votre choix : {Colors.RESET}").strip()

        if choice == "1":
            username = input("  Nom du compte à désactiver : ").strip()
            reason   = input("  Raison [Compromission détectée] : ").strip() or "Compromission détectée"
            confirm  = input(f"{Colors.RED}  Confirmer la désactivation de '{username}' ? [oui/N] : {Colors.RESET}").strip().lower()
            if confirm == "oui":
                results = executor.run_module("response.disable_user", "run",
                                              username=username, reason=reason)
                report_gen.generate(results, f"response_disable_{username}", output_format="both")

        elif choice == "2":
            ip        = input("  Adresse IP à bloquer : ").strip()
            direction = input("  Direction [both/in/out] : ").strip() or "both"
            duration  = input("  Durée en minutes (0 = permanent) [0] : ").strip() or "0"
            confirm   = input(f"{Colors.RED}  Confirmer le blocage de {ip} ? [oui/N] : {Colors.RESET}").strip().lower()
            if confirm == "oui":
                results = executor.run_module("response.block_ip", "run",
                                              ip=ip, direction=direction,
                                              duration_min=int(duration))
                report_gen.generate(results, f"response_block_{ip.replace('.','_')}", output_format="both")

        elif choice == "3":
            username = input("  Compte dont réinitialiser le mot de passe : ").strip()
            confirm  = input(f"{Colors.RED}  Confirmer la réinitialisation pour '{username}' ? [oui/N] : {Colors.RESET}").strip().lower()
            if confirm == "oui":
                results = executor.run_module("response.reset_password", "run",
                                              username=username)
                # Print new password to operator (not saved in report)
                new_pwd = results.get("new_password", "")
                if new_pwd:
                    print_success(f"Nouveau mot de passe (à transmettre de façon sécurisée) : {Colors.YELLOW}{new_pwd}{Colors.RESET}")
                # Remove password from result before saving report
                results.pop("new_password", None)
                report_gen.generate(results, f"response_reset_{username}", output_format="both")

        elif choice == "4":
            host    = input("  IP ou hostname de la machine à isoler : ").strip()
            mgmt_ip = input("  IP de l'analyste (autorisée pendant l'isolation) : ").strip() or None
            confirm = input(f"{Colors.RED}  Confirmer l'isolation de '{host}' ? [oui/N] : {Colors.RESET}").strip().lower()
            if confirm == "oui":
                results = executor.run_module("response.isolate_host", "run",
                                              host=host, management_ip=mgmt_ip)
                report_gen.generate(results, f"response_isolate_{host.replace('.','_')}", output_format="both")

        elif choice == "0":
            break
        else:
            print_error("Choix invalide.")


def reports_menu(report_gen: ReportGenerator):
    """View existing reports."""
    print_separator("RAPPORTS DISPONIBLES")
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    if not os.path.exists(reports_dir) or not os.listdir(reports_dir):
        print_warning("Aucun rapport trouvé. Lancez un audit ou une attaque d'abord.")
        return

    files = sorted(os.listdir(reports_dir), reverse=True)
    for i, f in enumerate(files, 1):
        size = os.path.getsize(os.path.join(reports_dir, f))
        print(f"  {Colors.CYAN}[{i}]{Colors.RESET} {f}  ({size} bytes)")

    choice = input(f"\n{Colors.BOLD}[>] Numéro à afficher (0 pour retour) : {Colors.RESET}").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(files):
        path = os.path.join(reports_dir, files[int(choice) - 1])
        with open(path) as f:
            print(f"\n{Colors.CYAN}" + "─" * 60 + Colors.RESET)
            print(f.read())
            print(Colors.CYAN + "─" * 60 + Colors.RESET)


def config_menu():
    """Show/edit configuration."""
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    print_separator("CONFIGURATION")
    if os.path.exists(config_path):
        with open(config_path) as f:
            print(f.read())
    else:
        print_warning("Fichier config.yaml introuvable.")
    input("\n  [Entrée pour continuer]")


def main():
    args = parse_args()

    if not args.no_banner:
        print_banner()

    loader = ModuleLoader()
    executor = Executor(loader, verbose=args.verbose)
    report_gen = ReportGenerator(output_format=args.output)

    # Non-interactive mode
    if args.mode:
        if args.mode == "blue":
            if args.playbook:
                executor.run_playbook(f"blue_team/{args.playbook}.yaml")
            elif args.audit:
                results = executor.run_module(f"blue_team.{args.audit}", "run_audit")
                report_gen.generate(results, f"blue_{args.audit}", args.output)
            else:
                run_full_blue_audit(executor, report_gen)

        elif args.mode == "red":
            if args.playbook:
                executor.run_playbook(f"red_team/{args.playbook}.yaml")
            elif args.attack:
                results = executor.run_module(f"red_team.{args.attack}", "run_attack",
                                              target=args.target, domain=args.domain)
                report_gen.generate(results, f"red_{args.attack}", args.output)
            else:
                print_error("--mode red nécessite --attack <nom> ou --playbook <nom>")
                sys.exit(1)

        elif args.mode == "purple":
            if args.playbook:
                executor.run_playbook(f"purple_team/{args.playbook}.yaml")
            else:
                results = executor.run_module("purple_team.validate_detection", "run")
                report_gen.generate(results, "purple_validation", args.output)
    else:
        # Interactive mode
        interactive_mode(executor, report_gen)


if __name__ == "__main__":
    main()


def reports_menu(report_gen: ReportGenerator):
    """
    Report generation and browsing menu.
    Supports technical and governance PDF reports, plus before/after comparison.
    """
    while True:
        print_menu("REPORTS — PDF GENERATION", [
            ("1", "Generate Technical PDF   (SOC / Pentest)"),
            ("2", "Generate Governance PDF  (CISO / Management)"),
            ("3", "Generate Both PDFs"),
            ("4", "Before / After comparison (requires 2 result files)"),
            ("5", "List generated reports"),
            ("0", "Back"),
        ])
        choice = input(f"\n{Colors.BOLD}[>] Your choice: {Colors.RESET}").strip()

        if choice in ("1", "2", "3"):
            # Load latest results from reports/ for regeneration
            rtype = {"1": "technical", "2": "governance", "3": "both"}[choice]
            results = _load_latest_results()
            if not results:
                print_warning("No results found. Run an audit or attack first.")
                continue
            label = input("  Report label [ad_security_report]: ").strip() or "ad_security_report"
            report_gen.generate(results, label, report_type=rtype)

        elif choice == "4":
            print_info("Before/After comparison — loading two result sets...")
            baseline = _load_results_interactive("baseline (BEFORE)")
            current  = _load_results_interactive("current  (AFTER)")
            if baseline and current:
                label = input("  Report label [comparison]: ").strip() or "comparison"
                report_gen.generate(current, label, report_type="both", baseline=baseline)
            else:
                print_error("Could not load both result sets.")

        elif choice == "5":
            _list_reports()

        elif choice == "0":
            break
        else:
            print_error("Invalid choice.")


def _load_latest_results() -> list:
    """Load results from the most recently generated JSON cache, if any."""
    import json, glob
    cache_dir = os.path.join(os.path.dirname(__file__), "reports", "cache")
    if not os.path.exists(cache_dir):
        return []
    files = sorted(glob.glob(os.path.join(cache_dir, "*.json")), reverse=True)
    if not files:
        return []
    try:
        with open(files[0]) as fh:
            data = json.load(fh)
            return data if isinstance(data, list) else [data]
    except Exception:
        return []


def _load_results_interactive(label: str) -> list:
    """Let the user pick a JSON cache file for before/after comparison."""
    import json, glob
    cache_dir = os.path.join(os.path.dirname(__file__), "reports", "cache")
    if not os.path.exists(cache_dir):
        print_warning(f"No cached results found for {label}.")
        return []
    files = sorted(glob.glob(os.path.join(cache_dir, "*.json")), reverse=True)
    if not files:
        return []
    print_info(f"Available result files for {label}:")
    for i, fp in enumerate(files[:10], 1):
        print(f"  {Colors.CYAN}[{i}]{Colors.RESET} {os.path.basename(fp)}")
    choice = input(f"  Select file number for {label}: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(files):
        try:
            with open(files[int(choice)-1]) as fh:
                data = json.load(fh)
                return data if isinstance(data, list) else [data]
        except Exception as e:
            print_error(f"Cannot load file: {e}")
    return []


def _list_reports():
    """List all generated PDF reports."""
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    if not os.path.exists(reports_dir):
        print_warning("No reports directory found.")
        return
    pdfs = sorted(
        [f for f in os.listdir(reports_dir) if f.endswith(".pdf")],
        reverse=True
    )
    if not pdfs:
        print_warning("No PDF reports found yet.")
        return
    print_separator("GENERATED PDF REPORTS")
    for i, f in enumerate(pdfs, 1):
        size = os.path.getsize(os.path.join(reports_dir, f))
        tag  = (f"{Colors.RED}[TECHNICAL]{Colors.RESET}"
                if "technical" in f else
                f"{Colors.CYAN}[GOVERNANCE]{Colors.RESET}"
                if "governance" in f else "")
        print(f"  {Colors.CYAN}[{i}]{Colors.RESET} {tag} {f}  ({size//1024} KB)")