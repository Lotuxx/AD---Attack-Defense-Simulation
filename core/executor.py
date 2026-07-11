"""
Executor
========
Responsible for running framework modules and YAML playbooks.

The Executor acts as the bridge between the CLI layer and the individual
attack/audit modules. It handles:
  - Dynamic module invocation via ModuleLoader
  - YAML playbook parsing and step-by-step execution
  - Timing and status reporting
  - Structured result collection for report generation
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

logger = FrameworkLogger("Executor")

# Playbooks are stored in the playbooks/ directory at project root
PLAYBOOKS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "playbooks")


class Executor:
    """
    Executes framework modules and YAML playbooks.

    Args:
        loader  (ModuleLoader): Instance used to dynamically load Python modules.
        verbose (bool)        : If True, print extra debug information during execution.
    """

    def __init__(self, loader: ModuleLoader, verbose: bool = False):
        self.loader  = loader
        self.verbose = verbose
        self.config  = Config()

    def run_module(self, module_path: str, func_name: str, **kwargs) -> dict:
        """
        Load a module dynamically and call one of its functions.

        The called function is expected to return a standardised result dict
        containing at least: status, findings, timestamp.

        Args:
            module_path (str): Dotted module path relative to modules/,
                               e.g. 'blue_team.audit_passwords'
            func_name   (str): Name of the function to call, e.g. 'run_audit'
            **kwargs         : Optional keyword arguments forwarded to the function
                               (e.g. target, domain, username)

        Returns:
            dict: Standardised result dict with status, findings, elapsed time, etc.
        """
        print_info(f"Executing: modules.{module_path}.{func_name}()")
        logger.info(f"run_module: {module_path}.{func_name} kwargs={kwargs}")

        # Dynamically load the module
        mod = self.loader.load(module_path)
        if mod is None:
            return self._error_result(module_path, "Module not found")

        # Retrieve the target function from the module
        func = getattr(mod, func_name, None)
        if func is None:
            msg = f"Function '{func_name}' not found in {module_path}"
            print_error(msg)
            logger.error(msg)
            return self._error_result(module_path, msg)

        # Execute the function and measure elapsed time
        start = time.time()
        try:
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
