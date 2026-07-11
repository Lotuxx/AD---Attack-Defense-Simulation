"""
Wazuh API Client
================
Handles all communication with the Wazuh SIEM REST API.

Wazuh exposes a REST API on port 55000 that allows external tools to:
  - Authenticate and obtain a JWT token
  - Query alerts with filters (time range, severity level, rule ID)
  - List registered agents and their status
  - Retrieve detection rules

This client is used by the Purple Team modules to:
  - Fetch alerts generated during Red Team attacks
  - Count alerts per rule ID to measure detection coverage
  - Validate that Wazuh correctly detected simulated attack techniques

Authentication flow:
    1. POST /security/user/authenticate with Basic Auth (user:password)
    2. Receive a JWT token valid for ~900 seconds
    3. Include token as Bearer in all subsequent requests

All API calls use urllib (no external dependencies) with optional SSL
verification (disabled by default for self-signed certs in lab environments).
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


def connect_or_warn(offline_message: str = "Wazuh inaccessible — mode démo.") -> tuple:
    """
    Instantiate WazuhAPI, authenticate, and print a standard warning if offline.

    Shared by Purple Team modules (correlate_attack.py, validate_detection.py)
    to avoid duplicating the same three lines in each.

    Args:
        offline_message (str): Warning text to print if authentication fails.

    Returns:
        tuple[WazuhAPI, bool]: The API client instance and whether it's connected.
    """
    api = WazuhAPI()
    connected = api.authenticate()
    if not connected:
        print_warning(offline_message)
    return api, connected


class WazuhAPI:
    """
    REST API client for the Wazuh SIEM.

    Reads connection settings from config.yaml if no config dict is provided.
    All HTTPS requests ignore SSL certificate errors by default (suitable for
    lab environments using self-signed certificates).

    Args:
        config (dict, optional): Override connection settings.
                                 Keys: wazuh_host, wazuh_port, wazuh_user,
                                       wazuh_password, verify_ssl

    Usage:
        api = WazuhAPI()
        api.authenticate()
        alerts = api.get_alerts(minutes=60, min_level=5)
    """

    def __init__(self, config: dict = None):
        # Load from config.yaml if no override is provided
        cfg = config or self._load_config()
        self.host       = cfg.get("wazuh_host",     "127.0.0.1")
        self.port       = cfg.get("wazuh_port",     55000)
        self.user       = cfg.get("wazuh_user",     "wazuh")
        self.password   = cfg.get("wazuh_password", "wazuh")
        self.verify_ssl = cfg.get("verify_ssl",     False)
        self._token     = None  # JWT token, populated after authenticate()

        # OpenSearch (direct index queries) may use a different account than
        # the Wazuh API itself; default to the same credentials if not set.
        self.opensearch_user     = cfg.get("opensearch_user",     self.user)
        self.opensearch_password = cfg.get("opensearch_password", self.password)

        # Keep a typed Config view of the same raw dict for the SSH tunnel
        # manager, so we don't need to re-load config.yaml a second time.
        from core.config import Config as _Config
        self._cfg = _Config(raw=cfg)

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self) -> bool:
        """
        Obtain a JWT token from Wazuh via Basic Authentication.

        The token is stored in self._token and automatically included
        in all subsequent API requests.

        Returns:
            bool: True if authentication succeeded, False otherwise.
        """
        url  = f"https://{self.host}:{self.port}/security/user/authenticate"
        # Encode credentials as Base64 for Basic Auth header
        creds = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req   = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
        req.method = "GET"

        try:
            ctx = self._ssl_context()
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                data         = json.loads(resp.read())
                self._token  = data["data"]["token"]  # Store JWT for future requests
                logger.info("Wazuh authentication successful")
                return True

        except urllib.error.URLError as e:
            logger.error(f"Cannot reach Wazuh API at {self.host}:{self.port}: {e}")
            print_error(f"Wazuh API unreachable ({self.host}:{self.port}): {e}")
            return False

        except Exception as e:
            logger.error(f"Wazuh auth error: {e}")
            print_error(f"Wazuh auth error: {e}")
            return False

    # ── API Requests ──────────────────────────────────────────────────────────

    def _get(self, endpoint: str, params: dict = None) -> dict | None:
        """
        Perform an authenticated GET request to the Wazuh API.

        Automatically authenticates if no token is available.

        Args:
            endpoint (str)       : API endpoint path, e.g. '/alerts'
            params   (dict, opt) : Query parameters appended to the URL.

        Returns:
            dict: Parsed JSON response, or None on failure.
        """
        # Auto-authenticate if not yet done
        if not self._token and not self.authenticate():
            return None

        # Build URL with optional query string
        url = f"https://{self.host}:{self.port}{endpoint}"
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url  += f"?{query}"

        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self._token}"})

        try:
            ctx = self._ssl_context()
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception as e:
            logger.error(f"Wazuh GET {endpoint} failed: {e}")
            return None

    # ── Public Methods ────────────────────────────────────────────────────────

    def get_alerts(self, minutes: int = 360, min_level: int = 1,
                   rule_id: str = None) -> list:
        """
        Fetch recent security alerts from Wazuh.

        Args:
            minutes   (int) : Time window in minutes to look back (default: 60).
            min_level (int) : Minimum alert severity level (1-15, default: 5).
            rule_id   (str) : Filter by specific rule ID (optional).

        Returns:
            list[dict]: List of alert objects from the Wazuh API.
        """
        # Wazuh 4.9 — alerts via OpenSearch API
        import json, urllib.request
        since = (datetime.now() - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
        
        query = {
            "size": 500,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": since}}},
                        {"range": {"rule.level": {"gte": min_level}}}
                    ]
                }
            }
        }
        if rule_id:
            query["query"]["bool"]["must"].append({"term": {"rule.id": rule_id}})

        url = f"https://localhost:{self._opensearch_port()}/wazuh-alerts-*/_search"
        import base64
        creds = base64.b64encode(
            f"{self.opensearch_user}:{self.opensearch_password}".encode()
        ).decode()
        req = urllib.request.Request(
            url,
            data=json.dumps(query).encode(),
            headers={"Authorization": f"Basic {creds}", "Content-Type": "application/json"}
        )
        try:
            ctx = self._ssl_context()
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                data = json.loads(resp.read())
                hits = data.get("hits", {}).get("hits", [])
                return [h["_source"] for h in hits]
        except Exception as e:
            logger.error(f"OpenSearch query failed: {e}")
            return []

    def get_agents(self) -> list:
        """
        Retrieve the list of all registered Wazuh agents.

        Returns:
            list[dict]: Agent objects including name, IP, status, OS.
        """
        data = self._get("/agents", {"limit": 100})
        if not data:
            return []
        return data.get("data", {}).get("affected_items", [])

    def get_rules(self, group: str = None) -> list:
        """
        List active Wazuh detection rules.

        Args:
            group (str, optional): Filter rules by group name (e.g. 'ad_attacks').

        Returns:
            list[dict]: Rule objects with ID, description, level, groups.
        """
        params = {"limit": 500}
        if group:
            params["group"] = group
        data = self._get("/rules", params)
        if not data:
            return []
        return data.get("data", {}).get("affected_items", [])

    def count_alerts_by_rule(self, rule_ids: list, minutes: int = 60) -> dict:
        """
        Count alerts per rule ID over a given time window.

        Used by Purple Team modules to measure detection coverage:
        how many alerts were generated for each expected rule ID.

        Args:
            rule_ids (list[int]) : List of Wazuh rule IDs to count.
            minutes  (int)       : Time window in minutes (default: 60).

        Returns:
            dict: {rule_id_str: count} mapping for each requested rule ID.
        """
        # Initialise all counts to 0
        counts = {str(r): 0 for r in rule_ids}
        # Fetch all alerts in the time window
        alerts = self.get_alerts(minutes=minutes, min_level=1)

        # Count occurrences of each requested rule ID
        for alert in alerts:
            rid = str(alert.get("rule", {}).get("id", ""))
            if rid in counts:
                counts[rid] += 1

        return counts

    def _opensearch_port(self) -> int:
        """
        Ensure the OpenSearch SSH tunnel is up (opening/reusing it automatically
        if opensearch_ssh_host/opensearch_ssh_user are configured) and return
        the local port to query.
        """
        from core.ssh_tunnel import ensure_tunnel
        return ensure_tunnel(self._cfg)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _ssl_context(self):
        """
        Create an SSL context for HTTPS connections.

        In lab environments, Wazuh uses a self-signed certificate.
        When verify_ssl=False, certificate verification is disabled.

        Returns:
            ssl.SSLContext: Configured SSL context.
        """
        import ssl
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            # Disable hostname and certificate verification for self-signed certs
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _load_config() -> dict:
        """
        Load connection settings from config.yaml at the project root.

        Delegates to core.config.load_config(), which also applies
        environment-variable overrides for secret fields (e.g. WAZUH_PASSWORD).

        Returns:
            dict: Configuration dictionary, or empty dict if file not found.
        """
        from core.config import load_config
        return load_config()
