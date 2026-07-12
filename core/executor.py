# ============================================================================
# Core — Executor Engine
# ============================================================================
#
# Responsible for executing framework modules and YAML playbooks.
#
# The Executor is the central execution layer of the AD Attack & Defense
# framework. It connects:
#
#   CLI / Dashboard
#          |
#          v
#      Executor
#          |
#          +--> ModuleLoader (dynamic module loading)
#          |
#          +--> Attack / Audit modules
#          |
#          +--> DatabaseManager (execution tracking)
#          |
#          +--> ReportGenerator (result reporting)
#
# Main responsibilities:
#   - Dynamically load and execute Python modules
#   - Inject centralized configuration values
#   - Execute YAML-based attack/audit workflows
#   - Measure execution time
#   - Normalize module results
#   - Store Red Team and Blue Team activity in SQLite
#
# ============================================================================

"""
Executor
========

Execution engine of the AD Attack & Defense Simulation Framework.

The Executor acts as the bridge between the user interfaces (CLI, dashboard)
and the individual framework modules.

It is responsible for:

    - Dynamic module invocation through ModuleLoader
    - YAML playbook parsing and sequential execution
    - Configuration injection
    - Execution timing and status reporting
    - Result normalization
    - Database logging for Red Team and Blue Team operations

Every attack, audit, or validation module executed by the framework goes
through this component.
"""

import os
import time
import yaml
from datetime import datetime
from typing import Any

from core.config import Config
from core.loader import ModuleLoader
from core.logger import FrameworkLogger
from utils.format_utils import (
    print_info, print_success, print_error, print_warning,
    print_step, print_separator, Colors
)


# Global logger dedicated to executor activity.
# Allows tracking execution flow, errors, and debugging information.
logger = FrameworkLogger("Executor")



# Location of YAML playbooks.
#
# Playbooks are stored outside the core package:
#
# project/
# ├── core/
# │   └── executor.py
# └── playbooks/
#     ├── red_team/
#     ├── blue_team/
#     └── purple_team/
#
PLAYBOOKS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "playbooks")


class Executor:
    """
    Main execution controller for framework modules.

    The Executor receives requests from the CLI or other interfaces,
    loads the required module dynamically, executes it, and returns
    a standardized result.

    Args:
        loader (ModuleLoader):
            Responsible for importing framework modules dynamically.

        verbose (bool):
            Enables additional debug output when required.

    Attributes:
        loader:
            Module loading manager.

        verbose:
            Debug mode flag.

        config:
            Centralized framework configuration loaded from config.yaml
            and environment variables.
    """

    def __init__(self, loader: ModuleLoader, verbose: bool = False):
        """
        Initialize the execution engine.

        The configuration object is loaded once here and reused during
        module execution to avoid duplicated configuration parsing.

        Args:
            loader:
                ModuleLoader instance used to dynamically import modules.

            verbose:
                Enable verbose execution logs.
        """

        self.loader  = loader
        self.verbose = verbose

        # Centralized configuration provider.
        # Handles:
        #   - Active Directory credentials
        #   - Wazuh settings
        #   - OpenSearch configuration
        #   - Network targets
        self.config  = Config()

    def run_module(self, module_path: str, func_name: str, **kwargs) -> dict:
        """
        Execute a framework module dynamically.

        Workflow:

            1. Load the requested Python module.
            2. Retrieve the requested function.
            3. Inject missing configuration values.
            4. Execute the function.
            5. Normalize the returned result.
            6. Store execution information.
            7. Return the final result.

        The executed function must return a dictionary containing at least:

            {
                "status": "...",
                "findings": [...]
            }

        Args:
            module_path (str):
                Module path relative to the modules directory.

                Example:
                    blue_team.audit_passwords

            func_name (str):
                Function name to execute.

                Example:
                    run_audit

            **kwargs:
                Arguments forwarded to the module function.

                Examples:
                    target
                    domain
                    username

        Returns:
            dict:
                Standardized execution result.
        """

        print_info(f"Executing: modules.{module_path}.{func_name}()")
        logger.info(f"run_module: {module_path}.{func_name} kwargs={kwargs}")

        # ------------------------------------------------------------------
        # Dynamic module loading
        # ------------------------------------------------------------------
        #
        # Modules are not imported statically.
        # This allows:
        #   - Easy addition of new attacks/audits
        #   - Playbook-driven execution
        #   - Plugin-like architecture
        #
        mod = self.loader.load(module_path)
        if mod is None:
            return self._error_result(module_path, "Module not found")

        # Retrieve the requested function from the loaded module.
        func = getattr(mod, func_name, None)
        if func is None:
            msg = f"Function '{func_name}' not found in {module_path}"
            print_error(msg)
            logger.error(msg)
            return self._error_result(module_path, msg)

        # ------------------------------------------------------------------
        # Module execution
        # ------------------------------------------------------------------
        start = time.time()

        try:
            # Inject default values:
            #   user
            #   password
            #   domain
            #
            # Values already provided by the caller are preserved.
            kwargs  = self.config.apply_defaults(kwargs)
            result  = func(**kwargs)
            elapsed = round(time.time() - start, 2)

            # Inject standard metadata into the result if not already present
            result.setdefault("module",    module_path)
            result.setdefault("elapsed_s", elapsed)
            result.setdefault("timestamp", datetime.now().isoformat())

            # Report execution status
            status = result.get("status", "unknown")
            if status == "success":
                print_success(f"Module completed in {elapsed}s")
            else:
                print_warning(f"Module completed with status: {status}")

            logger.info(f"Result: status={status} elapsed={elapsed}s")

            # Log automatique dans la base de données
            try:
                from core.database import DatabaseManager
                db = DatabaseManager()
                findings = result.get("findings", [])

                if "red_team" in module_path:
                    # Log exécution Red Team
                    attack_name = module_path.replace("red_team.", "").replace("_", " ").title()
                    attack_map = {
                        "Kerberoasting": "Kerberoasting",
                        "Password Spray": "Password Spraying",
                        "Pth": "Pass-the-Hash",
                        "Lateral Mouvement": "Lateral Movement",
                        "Llmnr Poisoning": "LLMNR Poisoning",
                        "Asrep Roasting": "AS-REP Roasting",
                        "Dcsync": "DCSync",
                        "Golden Ticket": "Golden Ticket",
                    }
                    attack_name = attack_map.get(attack_name, attack_name)
                    db.log_execution(
                        attack_name   = attack_name,
                        target_ip     = kwargs.get("target", ""),
                        target_domain = kwargs.get("domain", ""),
                        status        = status,
                        duration_s    = elapsed,
                        findings      = findings,
                        artifacts     = result.get("artifacts", {}),
                    )

                elif "blue_team" in module_path:
                    # Log findings Blue Team
                    audit_type = module_path.replace("blue_team.", "")
                    db.log_findings(
                        module        = module_path,
                        audit_type    = audit_type,
                        findings      = findings,
                        target_ip     = kwargs.get("dc_ip", ""),
                        target_domain = kwargs.get("domain", ""),
                    )
            except Exception as db_err:
                logger.warning(f"DB logging failed: {db_err}")

            return result

        except Exception as e:
            # Catch any runtime exception from the module
            elapsed = round(time.time() - start, 2)
            logger.error(f"Exception in {module_path}.{func_name}: {e}")
            print_error(f"Execution error: {e}")
            return self._error_result(module_path, str(e), elapsed)

    def run_playbook(self, playbook_name: str) -> list:
        """
        Load and execute a YAML playbook file step by step.

        Playbook format:
            name: "Playbook Name"
            description: "What this playbook does"
            steps:
              - name: "Step label"
                module: "team.module_name"
                function: "run"
                delay_s: 2
                stop_on_fail: false
                params:
                  key: value

        Args:
            playbook_name (str): Path relative to playbooks/ directory,
                                 e.g. 'red_team/full_attack.yaml'

        Returns:
            list[dict]: List of result dicts, one per executed step.
        """
        path = os.path.join(PLAYBOOKS_DIR, playbook_name)
        if not os.path.exists(path):
            print_error(f"Playbook not found: {path}")
            return []

        # Parse the YAML playbook file
        with open(path) as f:
            playbook = yaml.safe_load(f)

        name    = playbook.get("name", playbook_name)
        steps   = playbook.get("steps", [])
        results = []

        print_separator(f"PLAYBOOK: {name}")
        print_info(playbook.get("description", ""))
        print()

        total = len(steps)
        for i, step in enumerate(steps, 1):
            # Extract step configuration
            module_path = step.get("module")
            func_name   = step.get("function", "run")
            params      = step.get("params", {})
            step_name   = step.get("name", module_path)
            delay       = step.get("delay_s", 0)

            # Show progress bar
            print_step(i, total, step_name)

            # Optional delay between steps (e.g. to let logs propagate to SIEM)
            time.sleep(delay)

            # Execute the step
            result = self.run_module(module_path, func_name, **params)
            result["step_name"] = step_name
            results.append(result)

            # Abort playbook early if step failed and stop_on_fail is set
            if step.get("stop_on_fail") and result.get("status") != "success":
                print_warning(f"Stopping playbook on failure at step: {step_name}")
                break

        print_success(f"Playbook '{name}' completed — {len(results)}/{total} steps.")
        return results

    @staticmethod
    def _error_result(module: str, message: str, elapsed: float = 0.0) -> dict:
        """
        Build a standardised error result dict for failed module executions.

        Args:
            module  (str)  : Module path that failed.
            message (str)  : Error message describing the failure.
            elapsed (float): Time elapsed before the error occurred.

        Returns:
            dict: Standardised error result with status='error'.
        """
        return {
            "module":    module,
            "status":    "error",
            "message":   message,
            "elapsed_s": elapsed,
            "timestamp": datetime.now().isoformat(),
            "findings":  [],  # Empty findings list for consistency with success results
        }
