"""
Executor (v1.2)
===============
Runs framework modules and YAML playbooks.

New in v1.2:
    - Results are automatically cached as JSON in reports/cache/
      so the PDF generator and before/after comparison can access them later.
"""

import os
import json
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
CACHE_DIR     = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "cache")
os.makedirs(CACHE_DIR, exist_ok=True)


class Executor:
    """
    Executes framework modules and YAML playbooks.
    Caches results to JSON for PDF report generation and before/after comparison.

    Args:
        loader  : ModuleLoader instance.
        verbose : If True, print extra debug info.
    """

    def __init__(self, loader: ModuleLoader, verbose: bool = False):
        self.loader  = loader
        self.verbose = verbose

    def run_module(self, module_path: str, func_name: str, **kwargs) -> dict:
        """
        Load and call a module function.
        Returns a standardised result dict and caches it to JSON.
        """
        print_info(f"Executing: modules.{module_path}.{func_name}()")
        logger.info(f"run_module: {module_path}.{func_name} kwargs={kwargs}")

        mod = self.loader.load(module_path)
        if mod is None:
            return self._error_result(module_path, "Module not found")

        func = getattr(mod, func_name, None)
        if func is None:
            msg = f"Function '{func_name}' not found in {module_path}"
            print_error(msg)
            return self._error_result(module_path, msg)

        start = time.time()
        try:
            result  = func(**kwargs) if kwargs else func()
            elapsed = round(time.time() - start, 2)

            result.setdefault("module",    module_path)
            result.setdefault("elapsed_s", elapsed)
            result.setdefault("timestamp", datetime.now().isoformat())

            status = result.get("status", "unknown")
            if status == "success":
                print_success(f"Module completed in {elapsed}s")
            else:
                print_warning(f"Module completed with status: {status}")

            logger.info(f"Result: status={status} elapsed={elapsed}s")
            return result

        except Exception as e:
            elapsed = round(time.time() - start, 2)
            logger.error(f"Exception in {module_path}.{func_name}: {e}")
            print_error(f"Execution error: {e}")
            return self._error_result(module_path, str(e), elapsed)

    def run_playbook(self, playbook_name: str) -> list:
        """
        Load and execute a YAML playbook step by step.
        Caches the combined results for later PDF generation.
        """
        path = os.path.join(PLAYBOOKS_DIR, playbook_name)
        if not os.path.exists(path):
            print_error(f"Playbook not found: {path}")
            return []

        with open(path) as fh:
            playbook = yaml.safe_load(fh)

        name    = playbook.get("name", playbook_name)
        steps   = playbook.get("steps", [])
        results = []

        print_separator(f"PLAYBOOK: {name}")
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
                print_warning(f"Stopping playbook on failure at: {step_name}")
                break

        # Cache combined results
        self._cache_results(results, playbook_name)
        print_success(f"Playbook '{name}' completed — {len(results)}/{total} steps.")
        return results

    def _cache_results(self, results: list, label: str):
        """
        Save results to JSON cache for later PDF generation and comparison.
        File: reports/cache/<label>_<timestamp>.json
        """
        try:
            ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe     = label.replace("/", "_").replace(".", "_")
            filename = f"{safe}_{ts}.json"
            path     = os.path.join(CACHE_DIR, filename)

            # Sanitise: convert non-serialisable objects to strings
            def _sanitise(obj):
                if isinstance(obj, dict):
                    return {k: _sanitise(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [_sanitise(v) for v in obj]
                try:
                    json.dumps(obj)
                    return obj
                except (TypeError, ValueError):
                    return str(obj)

            with open(path, "w", encoding="utf-8") as fh:
                json.dump(_sanitise(results), fh, indent=2, ensure_ascii=False)
            logger.info(f"Results cached: {path}")
        except Exception as e:
            logger.error(f"Cache write failed: {e}")

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
