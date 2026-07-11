"""
Module Loader
=============
Responsible for dynamically importing framework modules at runtime.

Instead of hardcoding imports, the loader resolves module paths relative
to the project root, making the framework fully modular — new modules can
be dropped into modules/ without touching any other file.
"""

import importlib
import os
import sys

from core.logger import FrameworkLogger
from utils.format_utils import print_error, print_info

logger = FrameworkLogger("Loader")

# ── Path resolution ───────────────────────────────────────────────────────────
# Always resolve paths relative to this file's absolute location.
# This ensures imports work regardless of the current working directory.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
MODULES_DIR  = os.path.join(PROJECT_ROOT, "modules")


class ModuleLoader:
    """
    Dynamically loads Python modules from the modules/ directory.

    Usage:
        loader = ModuleLoader()
        mod = loader.load("blue_team.audit_passwords")
        mod.run_audit()
    """

    def __init__(self):
        """
        Initialise the loader and ensure the project root is in sys.path.
        This allows 'import modules.blue_team.xxx' to resolve correctly.
        """
        if PROJECT_ROOT not in sys.path:
            sys.path.insert(0, PROJECT_ROOT)

    def load(self, module_path: str):
        """
        Dynamically import a module by its dotted path (relative to modules/).

        Args:
            module_path (str): Dotted path, e.g. 'blue_team.audit_passwords'

        Returns:
            module: The imported Python module, or None if import failed.
        """
        full_path = f"modules.{module_path}"
        try:
            # If the module was already imported, reload it to pick up any changes
            if full_path in sys.modules:
                mod = importlib.reload(sys.modules[full_path])
            else:
                mod = importlib.import_module(full_path)

            logger.info(f"Module loaded: {full_path}")
            return mod

        except ModuleNotFoundError as e:
            # Module file does not exist at the expected path
            logger.error(f"Module not found: {full_path} — {e}")
            print_error(f"Module not found: {full_path} — {e}")
            return None

        except Exception as e:
            # Any other import error (syntax error, missing dependency, etc.)
            logger.error(f"Error loading {full_path}: {e}")
            print_error(f"Module load error: {e}")
            return None

    def list_modules(self, team: str) -> list:
        """
        List all available module names for a given team folder.

        Args:
            team (str): Team folder name, e.g. 'blue_team', 'red_team'

        Returns:
            list[str]: List of module filenames without the .py extension.
        """
        team_dir = os.path.join(MODULES_DIR, team)
        if not os.path.isdir(team_dir):
            return []
        # Return all .py files except __init__.py
        return [
            f[:-3] for f in os.listdir(team_dir)
            if f.endswith(".py") and not f.startswith("_")
        ]
