"""
Executor — runs modules and YAML playbooks, collects results.
"""

import os
import time
import yaml
from datetime import datetime
from typing import Any

from core.loader import ModuleLoader
from core.logger import FrameworkLogger
from utils.format_utils import (
    print_info, print_success, print_error, print_warning,
    print_step, print_separator, Colors
)

logger = FrameworkLogger("Executor")

PLAYBOOKS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "playbooks")


class Executor:
    def __init__(self, loader: ModuleLoader, verbose: bool = False):
        self.loader  = loader
        self.verbose = verbose

    def run_module(self, module_path: str, func_name: str, **kwargs) -> dict:
        """
        Dynamically load and call a module function.
        Returns a structured result dict.
        """
        print_info(f"Exécution : modules.{module_path}.{func_name}()")
        logger.info(f"run_module: {module_path}.{func_name} kwargs={kwargs}")

        mod = self.loader.load(module_path)
        if mod is None:
            return self._error_result(module_path, "Module introuvable")

        func = getattr(mod, func_name, None)
        if func is None:
            msg = f"Fonction '{func_name}' introuvable dans {module_path}"
            print_error(msg)
            logger.error(msg)
            return self._error_result(module_path, msg)

        start = time.time()
        try:
            result = func(**kwargs) if kwargs else func()
            elapsed = round(time.time() - start, 2)
            result.setdefault("module", module_path)
            result.setdefault("elapsed_s", elapsed)
            result.setdefault("timestamp", datetime.now().isoformat())

            status = result.get("status", "unknown")
            if status == "success":
                print_success(f"Module terminé en {elapsed}s")
            else:
                print_warning(f"Module terminé avec statut : {status}")

            logger.info(f"Résultat : status={status} elapsed={elapsed}s")
            return result

        except Exception as e:
            elapsed = round(time.time() - start, 2)
            logger.error(f"Exception dans {module_path}.{func_name} : {e}")
            print_error(f"Erreur d'exécution : {e}")
            return self._error_result(module_path, str(e), elapsed)

    def run_playbook(self, playbook_name: str) -> list:
        """
        Load and execute a YAML playbook.
        Returns list of step results.
        """
        path = os.path.join(PLAYBOOKS_DIR, playbook_name)
        if not os.path.exists(path):
            print_error(f"Playbook introuvable : {path}")
            return []

        with open(path) as f:
            playbook = yaml.safe_load(f)

        name   = playbook.get("name", playbook_name)
        steps  = playbook.get("steps", [])
        results = []

        print_separator(f"PLAYBOOK : {name}")
        print_info(playbook.get("description", ""))
        print()

        total = len(steps)
        for i, step in enumerate(steps, 1):
            module_path = step.get("module")
            func_name   = step.get("function", "run")
            params      = step.get("params", {})
            step_name   = step.get("name", module_path)
            delay       = step.get("delay_s", 0)

            print_step(i, total, step_name)
            time.sleep(delay)

            result = self.run_module(module_path, func_name, **params)
            result["step_name"] = step_name
            results.append(result)

            if step.get("stop_on_fail") and result.get("status") != "success":
                print_warning(f"Arrêt du playbook sur échec : {step_name}")
                break

        print_success(f"Playbook '{name}' terminé — {len(results)}/{total} étapes.")
        return results

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _error_result(module: str, message: str, elapsed: float = 0.0) -> dict:
        return {
            "module":    module,
            "status":    "error",
            "message":   message,
            "elapsed_s": elapsed,
            "timestamp": datetime.now().isoformat(),
            "findings":  [],
        }
