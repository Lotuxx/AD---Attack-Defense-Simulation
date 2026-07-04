"""
Module loader — dynamically imports modules from the modules/ directory.
"""

import importlib
import os
import sys

from core.logger import FrameworkLogger
from utils.format_utils import print_error, print_info

logger = FrameworkLogger("Loader")

MODULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules")


class ModuleLoader:
    def __init__(self):
        # Ensure modules/ is importable
        parent = os.path.dirname(os.path.dirname(__file__))
        if parent not in sys.path:
            sys.path.insert(0, parent)

    def load(self, module_path: str):
        """
        Load a module by dotted path relative to modules/.
        e.g. 'blue_team.audit_passwords'
        """
        full_path = f"modules.{module_path}"
        try:
            mod = importlib.import_module(full_path)
            logger.info(f"Module chargé : {full_path}")
            return mod
        except ModuleNotFoundError:
            logger.error(f"Module introuvable : {full_path}")
            print_error(f"Module introuvable : {full_path}")
            return None
        except Exception as e:
            logger.error(f"Erreur chargement {full_path} : {e}")
            print_error(f"Erreur chargement module : {e}")
            return None

    def list_modules(self, team: str) -> list:
        """List available modules for a given team (blue_team, red_team…)."""
        team_dir = os.path.join(MODULES_DIR, team)
        if not os.path.isdir(team_dir):
            return []
        return [
            f[:-3] for f in os.listdir(team_dir)
            if f.endswith(".py") and not f.startswith("_")
        ]
