"""
Wazuh API — connects to the Wazuh REST API to fetch alerts and agent data.
"""

import json
import os
import urllib.request
import urllib.error
import base64
from datetime import datetime, timedelta

from core.logger import FrameworkLogger
from utils.format_utils import print_info, print_error, print_warning

logger = FrameworkLogger("WazuhAPI")


class WazuhAPI:
    def __init__(self, config: dict = None):
        cfg = config or self._load_config()
        self.host     = cfg.get("wazuh_host", "127.0.0.1")
        self.port     = cfg.get("wazuh_port", 55000)
        self.user     = cfg.get("wazuh_user", "wazuh")
        self.password = cfg.get("wazuh_password", "wazuh")
        self.verify_ssl = cfg.get("verify_ssl", False)
        self._token   = None

    # ── Authentication ────────────────────────────────────────────────────

    def authenticate(self) -> bool:
        """Get JWT token from Wazuh API."""
        url = f"https://{self.host}:{self.port}/security/user/authenticate"
        creds = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
        req.method = "GET"

        try:
            import ssl
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                data = json.loads(resp.read())
                self._token = data["data"]["token"]
                logger.info("Authentification Wazuh réussie")
                return True
        except urllib.error.URLError as e:
            logger.error(f"Connexion Wazuh impossible : {e}")
            print_error(f"Wazuh API inaccessible ({self.host}:{self.port}) : {e}")
            return False
        except Exception as e:
            logger.error(f"Erreur auth Wazuh : {e}")
            print_error(f"Erreur auth Wazuh : {e}")
            return False

    # ── Requests ──────────────────────────────────────────────────────────

    def _get(self, endpoint: str, params: dict = None) -> dict | None:
        if not self._token and not self.authenticate():
            return None

        url = f"https://{self.host}:{self.port}{endpoint}"
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url += f"?{query}"

        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self._token}"})

        try:
            import ssl
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception as e:
            logger.error(f"Erreur requête Wazuh {endpoint} : {e}")
            return None

    # ── Public methods ────────────────────────────────────────────────────

    def get_alerts(self, minutes: int = 60, min_level: int = 5,
                   rule_id: str = None) -> list:
        """
        Fetch recent alerts from Wazuh.
        Returns list of alert dicts.
        """
        since = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")

        params = {
            "limit": 500,
            "sort":  "-timestamp",
            "q":     f"timestamp>{since};rule.level>={min_level}",
        }
        if rule_id:
            params["q"] += f";rule.id={rule_id}"

        data = self._get("/alerts", params)
        if not data:
            return []
        return data.get("data", {}).get("affected_items", [])

    def get_agents(self) -> list:
        """Return list of registered Wazuh agents."""
        data = self._get("/agents", {"limit": 100})
        if not data:
            return []
        return data.get("data", {}).get("affected_items", [])

    def get_rules(self, group: str = None) -> list:
        """List active detection rules."""
        params = {"limit": 500}
        if group:
            params["group"] = group
        data = self._get("/rules", params)
        if not data:
            return []
        return data.get("data", {}).get("affected_items", [])

    def count_alerts_by_rule(self, rule_ids: list, minutes: int = 60) -> dict:
        """
        Returns {rule_id: count} for the specified rule IDs
        over the last N minutes.
        """
        counts = {str(r): 0 for r in rule_ids}
        alerts = self.get_alerts(minutes=minutes, min_level=1)
        for alert in alerts:
            rid = str(alert.get("rule", {}).get("id", ""))
            if rid in counts:
                counts[rid] += 1
        return counts

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _load_config() -> dict:
        base = os.path.dirname(os.path.dirname(__file__))
        cfg_path = os.path.join(base, "config.yaml")
        if not os.path.exists(cfg_path):
            return {}
        try:
            import yaml
            with open(cfg_path) as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}
