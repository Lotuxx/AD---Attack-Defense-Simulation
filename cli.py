#!/usr/bin/env python3
"""
AD Attacks & Defense Simulation Framework — Main CLI Entry Point
================================================================
Authors : NISSEKONG Georges Owen, DIOP Salla
Year    : 2025-2026

cli.py
   │
   ├── Interactive menus
   ├── Command-line argument parsing
   ├── Module execution
   ├── Report generation
   └── Configuration management

This module is the main entry point of the framework.

The CLI acts as the central controller of the simulation platform:
- It initializes the framework components.
- It provides an interactive interface for analysts.
- It supports automated execution through command-line arguments.
- It coordinates Red Team simulations, Blue Team audits, Purple Team
  validation workflows, and report generation.

The CLI does not directly implement attack or defense techniques.
Instead, it delegates execution to dedicated modules through the
framework core components (Executor, ModuleLoader, ReportGenerator).

Usage:
    python3 cli.py                        # Interactive mode
    python3 cli.py --mode blue            # Full Blue Team audit
    python3 cli.py --mode red --attack kerberoasting
    python3 cli.py --mode purple          # Detection validation
    python3 cli.py --mode red --playbook full_attack
"""

import sys
import os


# ============================================================================
# Project path initialization
# ============================================================================
# The framework uses internal packages such as:
#   - core.*       -> execution engine, logging, reporting
#   - modules.*    -> attack and defense modules
#   - utils.*      -> interface and display helpers
#
# Python only searches modules located in its import paths.
# Since cli.py can be executed from different directories, the project root
# is manually added to sys.path to guarantee that internal imports work
# correctly regardless of the current working directory.
# ============================================================================

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import time
from datetime import datetime


# ============================================================================
# Core framework components
# ============================================================================
# These components provide the main services required by the CLI:
#
# ModuleLoader:
#   Responsible for discovering and loading simulation modules dynamically.
#
# Executor:
#   Central execution engine used to launch attacks, audits, and playbooks.
#
# FrameworkLogger:
#   Provides centralized logging for framework activities and results.
#
# ReportGenerator:
#   Converts execution results into analyst-readable reports.
# ============================================================================

from core.loader import ModuleLoader
from core.executor import Executor
from core.logger import FrameworkLogger
from core.report_generator import ReportGenerator


# ============================================================================
# User interface utilities
# ============================================================================
# These helper functions are used only for CLI presentation:
# - displaying banners,
# - formatting menus,
# - printing colored status messages.
#
# Keeping interface formatting separated from execution logic improves
# maintainability and allows the framework core to remain independent
# from the CLI interface.
# ============================================================================

from utils.format_utils import (
    print_banner, print_menu, print_success, print_error,
    print_warning, print_info, print_separator, Colors
)


# Global logger dedicated to CLI operations.
# Other framework components have their own responsibilities, while this
# logger tracks user interactions and CLI-level events.

logger = FrameworkLogger("CLI")


# ============================================================================
# Parse command-line arguments
# ============================================================================
def parse_args():
    """
    Parse command-line arguments for automated/non-interactive execution.

    The framework supports two usage modes:
    - Interactive mode: analyst selects actions through menus.
    - CLI mode: actions are directly provided through arguments,
      which is useful for automation, CI/CD pipelines, or repeatable labs.

    Returns:
        argparse.Namespace:
            Parsed command-line parameters including:
            - execution mode (red/blue/purple),
            - selected attack or audit,
            - target information,
            - report options.
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

    # ------------------------------------------------------------------------
    # Execution mode selection
    # ------------------------------------------------------------------------
    # Determines the operational role of the framework:
    #
    # blue:
    #   Runs defensive analysis and security auditing tasks.
    #
    # red:
    #   Executes offensive simulations against the AD environment.
    #
    # purple:
    #   Validates whether defensive controls detect simulated attacks.
    #
    # stats:
    #   Displays framework statistics.
    # ------------------------------------------------------------------------

    parser.add_argument("--mode", 
                        choices=["blue", "red", "purple", "stats"],
                        help="Execution mode (blue/red/purple)")
    
    # Specific attack module to execute in Red Team mode.
    # Example: Kerberoasting simulation against Active Directory services.
    parser.add_argument("--attack",   
                        help="Specific attack to run (red mode)")

    # Specific defensive audit to execute in Blue Team mode.
    parser.add_argument("--audit",    
                        help="Specific audit to run (blue mode)")

    # YAML playbooks allow predefined attack/defense scenarios
    # to be executed consistently.
    parser.add_argument("--playbook", 
                        help="YAML playbook to execute")

    # Target information used by modules during simulation.
    # Defaults correspond to a local training environment.
    parser.add_argument("--target",   
                        default="localhost", 
                        help="Target IP/hostname")

    # Active Directory domain targeted by the simulation.
    # Default value is intended for lab environments.
    parser.add_argument("--domain",   
                        default="domain.local", 
                        help="AD domain name")

    # Report generation format.
    # Currently limited to PDF output.
    parser.add_argument("--output",   
                        choices=["pdf"], 
                        default="pdf",
                        help="Report output format (PDF only)")
    
    # Disable graphical banner for automation or cleaner logs.
    parser.add_argument("--no-banner", 
                        action="store_true", 
                        help="Disable ASCII banner")

    # Enable additional execution details for debugging/troubleshooting.
    parser.add_argument("--verbose", "-v", 
                        action="store_true", 
                        help="Verbose output")
    
    return parser.parse_args()


# ============================================================================
# Interactive mode
# ============================================================================
def interactive_mode(executor: Executor, report_gen: ReportGenerator):
    """
    Run the framework using the interactive menu interface.

    This mode is designed for security analysts who want to manually
    navigate between Red Team, Blue Team, Purple Team, and reporting
    features.

    The function keeps running until the user chooses the exit option.

    Args:
        executor (Executor):
            Main execution engine responsible for launching modules.

        report_gen (ReportGenerator):
            Component responsible for generating and managing reports.
    """

    while True:
        # --------------------------------------------------------------------
        # Main framework navigation menu
        # --------------------------------------------------------------------
        # Provides access to the different security simulation workflows:
        #
        # Blue Team:
        #   Security assessment and defensive analysis.
        #
        # Red Team:
        #   Controlled attack simulations.
        #
        # Purple Team:
        #   Detection engineering and validation.
        #
        # Response:
        #   Automated remediation/SOAR actions.
        #
        # Reports:
        #   Access to generated assessment results.
        # --------------------------------------------------------------------

        print_menu("MAIN MENU", [
            ("1", "Blue Team   — AD Security Audit"),
            ("2", "Red Team    — Attack Simulation"),
            ("3", "Purple Team — Detection Validation"),
            ("4", "Response    — SOAR Remediation Actions"),
            ("5", "Reports     — View Generated Reports"),
            ("6", "Configuration"),
            ("0", "Quit"),
        ])

        choice = input(
            f"\n{Colors.BOLD}[>] Your choice: {Colors.RESET}"
            ).strip()

        # --------------------------------------------------------------------
        # Menu routing
        # --------------------------------------------------------------------
        # Each option redirects the analyst to a dedicated workflow.
        # The CLI only handles navigation; execution logic remains inside
        # specialized components.
        # --------------------------------------------------------------------

        if   choice == "1": 
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
            print_info("Goodbye!")
            sys.exit(0)

        else:
            print_error("Invalid choice. Please try again.")


# ============================================================================
# Blue Team audit menu
# ============================================================================
# This section contains all functions used by the interactive CLI interface.
#
# The interactive mode provides a security analyst-friendly workflow where
# users can manually select:
#
#   - Blue Team operations:
#       AD security audits and posture assessment.
#
#   - Red Team operations:
#       Controlled attack simulations against the AD laboratory.
#
#   - Purple Team operations:
#       Validation of detection capabilities by correlating attacks with
#       SIEM alerts.
#
#   - Response/SOAR operations:
#       Automated remediation actions after detecting a compromise.
#
# The CLI acts only as an orchestrator. Actual attack, audit, detection,
# and response logic is delegated to dedicated modules executed through
# the Executor component.
# ============================================================================
def blue_team_menu(executor: Executor, report_gen: ReportGenerator):
    """
    Display the Blue Team security audit menu.

    This menu provides access to defensive assessment modules designed
    to evaluate the security posture of an Active Directory environment.

    Available audits include:
        - Password policy analysis.
        - Privileged account review.
        - Group Policy Object (GPO) analysis.
        - Network security checks.
        - Security event/log analysis.

    Each audit module is executed independently through the Executor,
    then the results are passed to the ReportGenerator.

    Args:
        executor (Executor):
            Framework execution engine responsible for loading and running
            audit modules.

        report_gen (ReportGenerator):
            Component responsible for generating audit reports.
    """

    while True:
        # --------------------------------------------------------------------
        # Blue Team audit menu
        # --------------------------------------------------------------------
        # Each option corresponds to either:
        #   - a dedicated Python audit module,
        #   - or a predefined YAML playbook.
        #
        # Playbooks allow repeatable security assessments by executing
        # multiple predefined actions in a controlled order.
        # --------------------------------------------------------------------

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

        choice = input(
            f"\n{Colors.BOLD}[>] Your choice: {Colors.RESET}"
            ).strip()

        
        # --------------------------------------------------------------------
        # Audit module registry
        # --------------------------------------------------------------------
        # Maps user selections to their corresponding module path and
        # execution function.
        #
        # This avoids hardcoding multiple execution branches and keeps
        # the menu easily extensible when adding new audit modules.
        # --------------------------------------------------------------------

        modules_map = {
            "2": ("blue_team.audit_passwords",  "run_audit"),
            "3": ("blue_team.audit_privileges", "run_audit"),
            "4": ("blue_team.audit_gpo",        "run_audit"),
            "5": ("blue_team.audit_network",    "run_audit"),
            "6": ("blue_team.audit_logs",       "run_audit"),
        }

        # Execute complete AD security assessment
        if choice == "1":
            run_full_blue_audit(executor, report_gen)
        
        # Execute selected individual audit module
        elif choice in modules_map:
            module_path, func = modules_map[choice]

            # The Executor dynamically loads the selected module and
            # executes its audit function.
            #
            # Returned results are immediately converted into a PDF report
            # for later analysis.
            results = executor.run_module(module_path, func)
            report_gen.generate(results, "blue_team", 
                                output_format="pdf")

        # Execute predefined Blue Team assessment playbooks
        elif choice == "7":
            executor.run_playbook("blue_team/audit_basic.yaml")

        elif choice == "8":
            executor.run_playbook("blue_team/audit_advanced.yaml")

        elif choice == "0":
            break

        else:
            print_error("Invalid choice.")


# ------------------------------------------------------------------------
# Blue Team audit execution chain
# ------------------------------------------------------------------------
# The order of execution is intentional:
#
# 1. Identity security:
#       Password policies and privileged accounts.
#
# 2. AD configuration:
#       GPO and domain security settings.
#
# 3. Infrastructure security:
#       Network exposure and authentication protocols.
#
# 4. Visibility:
#       Verification of security logging capabilities.
#
# This sequence provides a progressive assessment from identity
# controls to detection capabilities.
# ------------------------------------------------------------------------
def run_full_blue_audit(executor: Executor, report_gen: ReportGenerator):
    """
    Execute a complete Blue Team security assessment.

    This function runs all available Blue Team audit modules sequentially.
    The objective is to provide a complete security posture assessment of
    the Active Directory environment.

    The executed audits cover:
        - Password policy weaknesses.
        - Privileged account exposure.
        - Active Directory configuration issues.
        - Network security weaknesses.
        - Security event/log analysis.

    All collected results are aggregated and sent to the report generator.

    Args:
        executor (Executor):
            Framework execution engine used to launch audit modules.

        report_gen (ReportGenerator):
            Component responsible for generating assessment reports.
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

    # Stores every audit result before generating the final report.
    all_results = []

    # Execute each audit module independently
    for module_path, label in audits:
        print_info(f"Running: {label}...")

        # Dynamic module execution allows the framework to load
        # different audit modules without modifying the CLI.
        result = executor.run_module(
            module_path, 
            "run_audit"
            )

        all_results.append(result)

        # Small delay improves readability during interactive execution.
        # It does not affect the audit logic.
        time.sleep(0.3)

    # Generate a single consolidated report containing all findings.
    report_gen.generate(
        all_results, 
        "blue_team_full", 
        output_format="pdf"
        )

    print_success("Full audit complete. Report saved in /reports/")


# ------------------------------------------------------------------------
# Red Team Menu
# ------------------------------------------------------------------------
def red_team_menu(executor: Executor, report_gen: ReportGenerator):
    """
    Display the Red Team attack simulation menu.

    This interface allows authorized operators to execute controlled
    adversary simulations against the isolated Active Directory laboratory.

    Available techniques simulate common AD attack paths:
        - Password spraying.
        - Kerberoasting.
        - LLMNR/NBT-NS poisoning.
        - Pass-the-Hash.
        - Lateral movement.

    Every attack requires explicit confirmation before execution.

    Args:
        executor (Executor):
            Framework execution engine.

        report_gen (ReportGenerator):
            Component responsible for generating attack reports.
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

        # Safety reminder:
        # Offensive modules are designed for controlled environments only.
        # This prevents accidental execution against unauthorized systems.
        print_warning(
            "⚠  Attacks must ONLY be run in the isolated lab environment!"
            )

        choice = input(
            f"\n{Colors.BOLD}[>] Your choice: {Colors.RESET}"
            ).strip()

        # --------------------------------------------------------------------
        # Red Team attack registry
        # --------------------------------------------------------------------
        # Maps menu selections to attack modules.
        #
        # The module/function architecture allows new techniques to be added
        # without rewriting the CLI navigation.
        #
        # ATT&CK examples:
        #   Password Spraying:
        #       T1110.003 - Password Spraying
        #
        #   Kerberoasting:
        #       T1558.003 - Steal or Forge Kerberos Tickets
        #
        #   Pass-the-Hash:
        #       T1550.002 - Use Alternate Authentication Material
        # --------------------------------------------------------------------
        attacks_map = {
            "2": ("red_team.password_spray",    
                  "run_attack", ""
                  "Password Spraying"),

            "3": ("red_team.kerberoasting",     
                  "run_attack", 
                  "Kerberoasting"),

            "4": ("red_team.llmnr_poisoning",   
                  "run_attack", 
                  "LLMNR Poisoning"),

            "5": ("red_team.pth",               
                  "run_attack", 
                  "Pass-the-Hash"),

            "6": ("red_team.lateral_mouvement", 
                  "run_attack", 
                  "Lateral Movement"),
        }

        # Execute complete attack scenario
        if choice == "1":
            executor.run_playbook("red_team/full_attack.yaml")

        elif choice in attacks_map:
            module_path, func, label = attacks_map[choice]
            
            # ----------------------------------------------------------------
            # Attack execution confirmation
            # ----------------------------------------------------------------
            # The operator must manually confirm:
            #
            # - the target,
            # - the selected technique.
            #
            # This additional step reduces accidental execution risks.
            # ----------------------------------------------------------------
            target  = input(
                f"  Target (IP/hostname) [{Colors.CYAN}domain.local{Colors.RESET}]: "
                ).strip() or "domain.local"
            
            confirm = input(
                f"{Colors.RED}  Confirm attack '{label}' on {target}? [yes/N]: {Colors.RESET}"
                ).strip().lower()
            
            if confirm == "yes":
                results = executor.run_module(
                    module_path, 
                    func, 
                    target=target
                    )
                
                report_gen.generate(
                    results, 
                    f"red_team_{label.lower().replace(' ', '_')}", 
                    output_format="pdf"
                    )
                
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


# --------------------------------------------------------------------
# Purple Team validation menu
# --------------------------------------------------------------------
# These options allow analysts to verify detection coverage:
#
# Validate detection:
#   Executes validation workflow against multiple techniques.
#
# Fetch alerts:
#   Retrieves security events collected by Wazuh.
#
# Correlation:
#   Compares simulated attacks with generated detections.
#
# Playbooks:
#   Automates complete Purple Team scenarios.
# --------------------------------------------------------------------
def purple_team_menu(executor: Executor, report_gen: ReportGenerator):
    """
    Display the Purple Team detection validation menu.

    Purple Team activities combine offensive simulations and defensive
    monitoring to evaluate whether security controls correctly detect
    malicious activity.

    The workflow generally follows this process:
        1. Execute or replay an attack technique.
        2. Retrieve generated SIEM alerts.
        3. Correlate attacks with detected events.
        4. Generate validation reports.

    In this framework, Wazuh is used as the detection platform.

    Args:
        executor (Executor):
            Framework execution engine used to execute validation modules.

        report_gen (ReportGenerator):
            Component responsible for generating validation reports.
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

        choice = input(
            f"\n{Colors.BOLD}[>] Your choice: {Colors.RESET}"
            ).strip()

        # Maps menu options to Purple Team modules.
        # These modules focus on detection verification rather than attack
        # execution itself.
        purple_map = {
            "2": (
                "purple_team.fetch_wazuh_alerts", 
                "run"
                ),

            "3": (
                "purple_team.correlate_attack",   
                "run"
                ),
        }

        # Complete detection validation workflow
        if choice == "1":
            results = executor.run_module(
                "purple_team.validate_detection", 
                "run"
                )
            
            report_gen.generate(
                results, 
                "purple_team_validation", 
                output_format="pdf"
                )

        # Execute individual Purple Team component
        elif choice in purple_map:
            module_path, func = purple_map[choice]
            results = executor.run_module(module_path, func)
            report_gen.generate(
                results, "purple_team", 
                output_format="pdf"
                )

        # Execute predefined Purple Team playbooks   
        elif choice == "4":
            executor.run_playbook("purple_team/detection_validation.yaml")

        elif choice == "5":
            executor.run_playbook("purple_team/full_purple_chain.yaml")

        elif choice == "0":
            break

        else:
            print_error("Invalid choice.")


# ============================================================================
# Display Response Menu
# ============================================================================
def response_menu(executor: Executor, report_gen: ReportGenerator):
    """
    Display the Response / SOAR remediation menu.

    This menu provides automated incident response actions that can be
    executed after detecting suspicious activity.

    Available response actions:
        - Disable compromised accounts.
        - Block malicious IP addresses.
        - Reset user credentials.
        - Isolate compromised machines.

    Because these actions directly modify the environment, explicit
    operator confirmation is required before execution.

    Args:
        executor (Executor):
            Framework execution engine.

        report_gen (ReportGenerator):
            Component responsible for storing response reports.
    """

    while True:
        print_menu("RESPONSE — SOAR REMEDIATION", [
            ("1", "Disable a compromised account"),
            ("2", "Block an IP address"),
            ("3", "Reset a user password"),
            ("4", "Isolate a machine from the network"),
            ("0", "Back"),
        ])

        # Response operations can affect availability and access.
        # The warning reminds operators that these actions are not passive
        # analysis but active remediation.
        print_warning("⚠  These actions have immediate impact on the environment!")

        choice = input(
            f"\n{Colors.BOLD}[>] Your choice: {Colors.RESET}"
            ).strip()

        # --------------------------------------------------------------------
        # Disable compromised account
        # --------------------------------------------------------------------
        if choice == "1":
            username = input(
                "  Account to disable: "
                ).strip()

            reason   = input(
                "  Reason [Detected compromise]: "
                ).strip() or "Detected compromise"

            confirm  = input(
                f"{Colors.RED}  Confirm disabling '{username}'? [yes/N]: {Colors.RESET}"
                ).strip().lower()
            
            if confirm == "yes":
                results = executor.run_module(
                    "response.disable_user", 
                    "run",
                    username=username, 
                    reason=reason
                    )
                
                report_gen.generate(
                    results, 
                    f"response_disable_{username}", 
                    output_format="pdf"
                    )

        # --------------------------------------------------------------------
        # Block malicious IP address
        # --------------------------------------------------------------------
        elif choice == "2":
            # Collect IP blocking parameters
            ip        = input(
                "  IP address to block: "
                ).strip()
            
            direction = input(
                "  Direction [both/in/out]: "
                ).strip() or "both"
            
            duration  = input(
                "  Duration in minutes (0 = permanent) [0]: "
                ).strip() or "0"
            
            confirm   = input(
                f"{Colors.RED}  Confirm blocking {ip}? [yes/N]: {Colors.RESET}"
                ).strip().lower()
            
            if confirm == "yes":
                results = executor.run_module(
                    "response.block_ip", 
                    "run",
                    ip=ip, 
                    direction=direction,
                    duration_min=int(duration)
                    )
                
                report_gen.generate(
                    results, 
                    f"response_block_{ip.replace('.','_')}", 
                    output_format="pdf"
                    )

        # --------------------------------------------------------------------
        # Reset compromised password
        # --------------------------------------------------------------------
        elif choice == "3":
            # Reset password — new password is shown only to operator, never saved in report
            username = input(
                "  Account to reset password for: "
                ).strip()
            
            confirm  = input(
                f"{Colors.RED}  Confirm password reset for '{username}'? [yes/N]: {Colors.RESET}"
                ).strip().lower()
            
            if confirm == "yes":
                results = executor.run_module(
                    "response.reset_password", 
                    "run", 
                    username=username
                    )
                
                # Display new password to operator via secure channel (not saved in report)
                new_pwd = results.get(
                    "new_password", 
                    ""
                    )
                
                # The generated password is sensitive information.
                # It is displayed only to the operator and removed before
                # report generation to avoid accidental disclosure.
                if new_pwd:
                    print_success(
                        f"New password (transmit securely): {Colors.YELLOW}{new_pwd}{Colors.RESET}"
                        )
                    
                # Remove credential material before writing reports.
                results.pop(
                    "new_password", 
                    None
                    )
                
                report_gen.generate(
                    results, 
                    f"response_reset_{username}", 
                    output_format="pdf"
                    )

        # --------------------------------------------------------------------
        # Isolate compromised machine
        # --------------------------------------------------------------------
        elif choice == "4":
            # Isolate host — keeps management ports open for analyst
            host    = input(
                "  IP or hostname of machine to isolate: "
                ).strip()
            
            mgmt_ip = input(
                "  Analyst IP (allowed during isolation): "
                ).strip() or None
            
            confirm = input(
                f"{Colors.RED}  Confirm isolating '{host}'? [yes/N]: {Colors.RESET}"
                ).strip().lower()
            
            if confirm == "yes":
                results = executor.run_module(
                    "response.isolate_host", 
                    "run",
                    host=host, 
                    management_ip=mgmt_ip
                    )
                
                report_gen.generate(
                    results, 
                    f"response_isolate_{host.replace('.','_')}", 
                    output_format="pdf"
                    )

        elif choice == "0":
            break
        else:
            print_error("Invalid choice.")


# ============================================================================
# Display Reports Menu
# ============================================================================
def reports_menu(report_gen: ReportGenerator):
    """
    Display and preview previously generated framework reports.

    Reports are stored inside the local /reports/ directory.

    The function supports:
        - Listing available reports.
        - Sorting reports by filename/date.
        - Displaying PDF previews.
        - Reading legacy TXT/CSV reports.

    Args:
        report_gen (ReportGenerator):
            Report generator instance used for framework consistency.
            The current implementation mainly relies on the reports path.
    """

    print_separator("AVAILABLE REPORTS")

    # Reports are stored relative to the project directory.
    reports_dir = os.path.join(
        os.path.dirname(__file__), 
        "reports"
        )

    # Verify that reports exist before displaying the menu.
    if not os.path.exists(reports_dir) or not os.listdir(reports_dir):
        print_warning(
            "No reports found. Run an audit or attack first."
            )
        return

    # Sort reports so recent/generated files appear first.
    files = sorted(
        os.listdir(reports_dir), 
        reverse=True
        )

    # Display available reports with their size.
    for i, f in enumerate(files, 1):
        size = os.path.getsize(os.path.join(reports_dir, f))
        print(f"  {Colors.CYAN}[{i}]{Colors.RESET} {f}  ({size} bytes)")

    choice = input(f"\n{Colors.BOLD}[>] Number to display (0 to go back): {Colors.RESET}").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(files):
        path = os.path.join(reports_dir, files[int(choice) - 1])
        print(f"\n{Colors.CYAN}" + "─" * 60 + Colors.RESET)

        # PDFs contain binary data and cannot be directly printed.
            # pdfplumber extracts readable text for terminal preview.
        if path.lower().endswith(".pdf"):
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
            # Compatibility support for older TXT/CSV reports.
            with open(path) as f:
                print(f.read())
        print(Colors.CYAN + "─" * 60 + Colors.RESET)


# ============================================================================
# Configuration, Statistics & Application Entry Point
# ============================================================================
# This section contains the global framework management functions:
#
# - Configuration display and modification.
# - Active Directory target selection.
# - Global statistics visualization.
# - Main CLI initialization and execution flow.
#
# These functions are responsible for preparing the framework environment
# before executing Red Team, Blue Team, Purple Team or Response workflows.
# ============================================================================

# ============================================================================
# Configuration Menu
# ============================================================================
def config_menu():
    """
    Display the current framework configuration.

    This menu allows operators to review the active configuration loaded
    from config.yaml before launching simulations.

    The configuration file contains important framework parameters such as:
        - Active Directory target information.
        - Wazuh connection settings.
        - OpenSearch/SIEM configuration.
        - Network parameters.

    This function only displays configuration values and does not modify
    them.

    Note:
        Sensitive values should ideally be masked in production environments.

    """

    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    print_separator("CONFIGURATION")

    # Check whether the configuration file exists before reading it.
    if os.path.exists(config_path):
        with open(config_path) as f:
            print(f.read())
    else:
        print_warning("config.yaml not found.")
    input("\n  [Press Enter to continue]")


# ============================================================================
# Selection Target AD
# ============================================================================
def _select_target(skip: bool = False):
    """
    Allow the operator to select the Active Directory laboratory target.

    The framework supports multiple AD environments (GOAD-style labs).
    This function updates only target-related parameters inside config.yaml.

    Target-dependent parameters:
        - Domain name.
        - Domain Controller IP.
        - Domain credentials.

    Parameters unrelated to the target are preserved:
        - Wazuh configuration.
        - OpenSearch configuration.
        - Kali/attacker machine settings.

    Args:
        skip (bool):
            If True, no interactive selection is performed.

            This happens when:
                - the target was already provided through CLI arguments.
                - the framework is running in automated mode.

            This prevents scripted executions from blocking on user input.
    """

    if skip:
        return

    import yaml, os
    config_path = os.path.join(
        os.path.dirname(__file__), 
        "config.yaml"
        )

    # ------------------------------------------------------------------------
    # Available laboratory targets
    # ------------------------------------------------------------------------
    # Each entry represents a possible AD environment component.
    #
    # The operator can switch between domains/controllers without manually
    # editing configuration files.
    #
    # WARNING:
    # Credentials are stored here only because this is a controlled
    # educational laboratory environment.
    #
    # In production:
    #   - credentials should never be hardcoded,
    #   - secrets should be stored in a vault or environment variables.
    # ------------------------------------------------------------------------
    targets = {
        "1": {
            "domain": "sevenkingdoms.local", 
            "dc_ip": "192.168.56.10", 
            "domain_user": "administrator", 
            "domain_password": "8dCT-DJjgScp"
            },

        "2": {
            "domain": "essos.local",          
            "dc_ip": "192.168.56.12", 
            "domain_user": "vagrant",        
            "domain_password": "vagrant"
            },

        "3": {
            "domain": "essos.local",          
            "dc_ip": "192.168.56.22", 
            "domain_user": "vagrant",        
            "domain_password": "vagrant"
            },

        "4": {
            "domain": "essos.local",          
            "dc_ip": "192.168.56.23", 
            "domain_user": "vagrant",        
            "domain_password": "vagrant"
            },
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

        # Load current configuration.
        with open(config_path) as f:
            cfg = yaml.safe_load(f) or {}
        
        # --------------------------------------------------------------------
        # Update only AD target parameters.
        #
        # Other infrastructure settings remain untouched.
        # This prevents accidentally overwriting SIEM or monitoring settings.
        # --------------------------------------------------------------------
        cfg["dc_ip"]          = t["dc_ip"]
        cfg["domain"]         = t["domain"]
        cfg["domain_user"]    = t["domain_user"]
        cfg["domain_password"] = t["domain_password"]

        # Garder intact : wazuh, opensearch, kali_ip, etc.
        with open(config_path, "w") as f:
            yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)

        print_success(
            f"Cible : {t['domain']} ({t['dc_ip']})"
            )
        
        print_info(
            f"  User     : {t['domain_user']}"
            )
        
        print_info(
            f"  Wazuh    : {cfg.get('wazuh_host', 'N/A')} (inchangé)"
            )
        
        print_info(
            f"  Kali IP  : {cfg.get('kali_ip', 'N/A')} (inchangé)"
            )


# ============================================================================
# Show global stats
# ============================================================================
def _show_stats():
    """
    Display global framework statistics.

    Statistics are retrieved from the framework database and provide
    visibility into:

        - Red Team execution history.
        - Successful attacks.
        - Blue Team findings.
        - Detection effectiveness from Wazuh.

    This provides a Purple Team perspective by measuring whether simulated
    attacks are correctly detected.

    """

    from core.database import DatabaseManager
    db = DatabaseManager()

    print(
        f"\n{Colors.CYAN}{'═'*60}{Colors.RESET}"
        )
    
    print(
        f"{Colors.BOLD}  STATISTIQUES GLOBALES — AD Attack & Defense{Colors.RESET}"
        )
    
    print(
        f"{Colors.CYAN}{'═'*60}{Colors.RESET}\n"
        )


    # ------------------------------------------------------------------------
    # Offensive simulation statistics
    # ------------------------------------------------------------------------
    stats = db.get_global_stats()

    print(
        f"{Colors.BOLD}  Exécutions Red Team :{Colors.RESET}"
        )
    
    print(
        f"    Total          : {stats['total_executions']}"
        )
    
    print(
        f"    Réussies       : {stats['successful_attacks']}"
        )
    
    print(
        f"    Taux de succès : {Colors.GREEN}{stats['success_rate']}%{Colors.RESET}\n"
        )


    # ------------------------------------------------------------------------
    # Defensive findings statistics
    # ------------------------------------------------------------------------
    print(
        f"{Colors.BOLD}  Findings Blue Team :{Colors.RESET}"
        )
    
    findings = db.get_findings_summary()

    for level, count in findings.items():
        color = Colors.RED if level in ('Critique', 'Élevé') else Colors.YELLOW if level == 'Moyen' else Colors.GREEN
        print(
            f"    {level:<12} : {color}{count}{Colors.RESET}"
            )

    print(
        f"    Total          : {stats['total_findings']}"
        )
    print(
        f"    Critiques/Élevés: {Colors.RED}{stats['critical_findings']}{Colors.RESET}\n"
        )


    # ------------------------------------------------------------------------
    # Detection effectiveness
    # ------------------------------------------------------------------------
    # Measures whether attacks performed during Red Team exercises
    # generated corresponding SIEM detections.
    # ------------------------------------------------------------------------
    print(
        f"{Colors.BOLD}  Détection Wazuh :{Colors.RESET}"
        )

    rates = db.get_detection_rate()

    for attack, data in rates.items():
        color = Colors.GREEN if data['rate'] >= 80 else Colors.YELLOW if data['rate'] >= 50 else Colors.RED
        print(
            f"    {attack:<22} : {color}{data['rate']}%{Colors.RESET} ({data['runs']} run(s))"
            )
    print(
        f"    Taux global    : {Colors.GREEN}{stats['avg_detection_rate']}%{Colors.RESET}\n"
        )

    print(
        f"{Colors.CYAN}{'═'*60}{Colors.RESET}\n"
        )


# ============================================================================
# Main
# ============================================================================
def main():
    """
    Main application entry point.

    This function initializes the complete AD Attack & Defense Simulation
    framework and decides which execution workflow should be launched.

    Execution flow:

        1. Parse command-line arguments.
        2. Display framework banner.
        3. Select or validate the AD laboratory target.
        4. Initialize core framework components:
            - Module loader.
            - Execution engine.
            - Report generator.
        5. Execute either:
            - Non-interactive CLI mode.
            - Interactive analyst menu mode.

    Supported execution modes:

        Blue Team:
            Runs security audits and posture assessments.

        Red Team:
            Executes controlled attack simulations.

        Purple Team:
            Validates detection capabilities.

        Stats:
            Displays historical framework metrics.

    """

    # =========================================================================
    # Step 1 — Parse CLI arguments
    # =========================================================================
    # argparse handles both:
    #
    # Interactive usage:
    #     python cli.py
    #
    # Automated execution:
    #     python cli.py --mode red --attack kerberoasting
    #
    # This allows the framework to be used both manually by analysts and
    # automatically inside scripts or CI/CD pipelines.
    # =========================================================================
    args = parse_args()


    # =========================================================================
    # Step 2 — Display framework banner
    # =========================================================================
    # The banner improves readability during interactive usage.
    #
    # It can be disabled for automated execution where only logs/results
    # are required.
    # =========================================================================    
    if not args.no_banner:
        print_banner()


    # =========================================================================
    # Step 3 — Select Active Directory target
    # =========================================================================
    # The target selection prompt is skipped when:
    #
    # - A target/domain was already provided through CLI arguments.
    # - Running statistics mode.
    # - Running automated execution.
    #
    # This avoids blocking automated executions waiting for user input.
    # =========================================================================
    _select_target(
        skip=(
            "--target" in sys.argv 
            or "--domain" in sys.argv 
            or args.mode == "stats"
            )
        )


    # =========================================================================
    # Step 4 — Initialize framework core components
    # =========================================================================
    #
    # ModuleLoader:
    #     Dynamically discovers and loads attack/audit modules.
    #
    # Executor:
    #     Executes modules, attacks, audits and playbooks.
    #
    # ReportGenerator:
    #     Produces final reports while removing sensitive information.
    #
    # Secrets are provided to ReportGenerator so credentials/passwords
    # accidentally returned by modules can be filtered before writing
    # reports.
    # =========================================================================
    loader     = ModuleLoader()
    executor   = Executor(
        loader, 
        verbose=args.verbose
        )
    report_gen = ReportGenerator(
        output_format=args.output,
        secrets=[
            executor.config.domain_password,
            executor.config.wazuh_password,
            executor.config.opensearch_password,
        ],
    )


    # =========================================================================
    # Step 5 — Non-interactive execution mode
    # =========================================================================
    # When --mode is provided, the framework directly executes the requested
    # workflow without displaying menus.
    #
    # Example:
    #
    #     python cli.py --mode blue
    #
    # This mode is useful for:
    #     - automation,
    #     - repeatable security tests,
    #     - laboratory demonstrations.
    # =========================================================================
    if args.mode:

        # =====================================================================
        # Blue Team execution
        # =====================================================================
        # Runs defensive security audits.
        #
        # Possible actions:
        #   - Execute a complete audit.
        #   - Run a specific audit module.
        #   - Execute a Blue Team playbook.
        # =====================================================================

        if args.mode == "blue":
            if args.playbook:
                # Run a specific Blue Team playbook by name
                executor.run_playbook(
                    f"blue_team/{args.playbook}.yaml"
                    )

            elif args.audit:
                # Run a single audit module
                results = executor.run_module(
                    f"blue_team.{args.audit}", 
                    "run_audit"
                    )
                
                report_gen.generate(
                    results, 
                    f"blue_{args.audit}", 
                    args.output
                    )

            else:
                # Default behaviour:
                # execute the complete AD security assessment.
                run_full_blue_audit(
                    executor, 
                    report_gen
                    )

        # =====================================================================
        # Red Team execution
        # =====================================================================
        # Executes controlled offensive simulations.
        #
        # The operator must provide:
        #
        #   - an attack technique,
        #   - or a complete attack playbook.
        #
        # Examples:
        #
        #   --attack kerberoasting
        #   --playbook full_attack
        #
        # =====================================================================
        elif args.mode == "red":
            if args.playbook:
                executor.run_playbook(
                    f"red_team/{args.playbook}.yaml"
                    )

            elif args.attack:

                # Execute selected attack module.
                #
                # Target and domain are explicitly provided to the module
                # because offensive techniques require AD context.
                results = executor.run_module(
                    f"red_team.{args.attack}", 
                    "run_attack",
                    target=args.target, 
                    domain=args.domain
                    )
                
                report_gen.generate(
                    results, 
                    f"red_{args.attack}", 
                    args.output
                    )
                
            else:
                # Red Team mode requires an explicit technique.
                print_error(
                    "--mode red requires --attack <name> or --playbook <name>"
                    )
                
                sys.exit(1)


        # =====================================================================
        # Purple Team execution
        # =====================================================================
        # Validates whether security monitoring detects simulated attacks.
        #
        # This combines:
        #
        #   Red Team activity:
        #       Attack execution.
        #
        #   Blue Team capability:
        #       SIEM monitoring and alerting.
        #
        # =====================================================================
        elif args.mode == "purple":
            if args.playbook:
                executor.run_playbook(
                    f"purple_team/{args.playbook}.yaml"
                    )
                
            else:
                # Default:
                # Run complete detection validation workflow.
                results = executor.run_module(
                    "purple_team.validate_detection", 
                    "run"
                    )
                
                report_gen.generate(
                    results, 
                    "purple_validation", 
                    args.output
                    )
                
        # =====================================================================
        # Statistics display
        # =====================================================================
        elif args.mode == "stats":
            _show_stats()

    else:
        # =========================================================================
        # Step 6 — Interactive execution mode
        # =========================================================================
        # If no execution mode was provided, start the analyst menu interface.
        #
        # This is the default mode:
        #
        #     python cli.py
        #
        # The analyst can then navigate between:
        #     - Blue Team.
        #     - Red Team.
        #     - Purple Team.
        #     - Response.
        #     - Reports.
        # =========================================================================
        interactive_mode(
            executor, 
            report_gen
            )


# ============================================================================
# Python execution guard
# ============================================================================
# Ensures that main() is executed only when this file is launched directly.
#
# This allows cli.py to be imported by other Python modules without starting
# the CLI automatically.
# ============================================================================
if __name__ == "__main__":
    main()
