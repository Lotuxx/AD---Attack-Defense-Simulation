"""
Centralized Configuration Loader
=================================
Loads config.yaml from the project root and applies environment-variable
overrides for sensitive fields (passwords), so secrets can be kept out of
config.yaml entirely if desired (e.g. in CI, shared lab environments, or
when handing the framework to a teammate).

Env var naming convention: upper-case the config key, e.g.
    domain_password      -> DOMAIN_PASSWORD
    wazuh_password        -> WAZUH_PASSWORD
    opensearch_password  -> OPENSEARCH_PASSWORD

This module is the single source of truth for config loading; every other
module that previously had its own copy of `_load_config()` now delegates
here instead of re-implementing the same file-read logic.
"""

import os
import yaml

# Secret fields that may be overridden via environment variables instead of
# being stored in clear text in config.yaml.
_ENV_OVERRIDABLE_KEYS = (
    "domain_password",
    "wazuh_password",
    "opensearch_password",
)


def load_config(path: str = None) -> dict:
    """
    Load config.yaml and apply environment-variable overrides for secrets.

    Args:
        path (str, optional): Explicit path to config.yaml. Defaults to
                               <project_root>/config.yaml.

    Returns:
        dict: Configuration dictionary. Empty dict if the file doesn't
              exist or fails to parse, so callers can fall back to their
              own defaults.
    """
    if path is None:
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")

    cfg = {}
    if os.path.exists(path):
        try:
            with open(path) as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}

    for key in _ENV_OVERRIDABLE_KEYS:
        env_val = os.environ.get(key.upper())
        if env_val:
            cfg[key] = env_val

    return cfg


class Config:
    """
    Typed, centralized view over config.yaml (+ env var overrides).

    Wraps load_config() and exposes the settings used across the framework
    as named attributes with the same defaults that were previously
    duplicated inline in executor.py and various modules. Avoids scattering
    `cfg.get("some_key", some_default)` calls throughout the codebase.

    Usage:
        config = Config()
        print(config.domain_user)
        kwargs = config.apply_defaults(kwargs)  # fill missing user/password/domain
    """

    def __init__(self, raw: dict = None, path: str = None):
        self._raw = raw if raw is not None else load_config(path)

        # Active Directory
        self.domain          = self._raw.get("domain", "domain.local")
        self.dc_ip           = self._raw.get("dc_ip", "127.0.0.1")
        self.domain_user     = self._raw.get("domain_user")
        self.domain_password = self._raw.get("domain_password")

        # Wazuh / OpenSearch
        self.wazuh_host          = self._raw.get("wazuh_host", "127.0.0.1")
        self.wazuh_port          = self._raw.get("wazuh_port", 55000)
        self.wazuh_user          = self._raw.get("wazuh_user", "wazuh")
        self.wazuh_password      = self._raw.get("wazuh_password", "wazuh")
        self.opensearch_user     = self._raw.get("opensearch_user", self.wazuh_user)
        self.opensearch_password = self._raw.get("opensearch_password", self.wazuh_password)
        self.verify_ssl          = self._raw.get("verify_ssl", False)

        # OpenSearch SSH tunnel (optional — automates what used to be a manual
        # `ssh -L 9200:localhost:9200 ...` run before every Purple Team session)
        self.opensearch_local_port   = self._raw.get("opensearch_local_port", 9200)
        self.opensearch_remote_port  = self._raw.get("opensearch_remote_port", 9200)
        self.opensearch_ssh_host     = self._raw.get("opensearch_ssh_host") or self.wazuh_host
        self.opensearch_ssh_user     = self._raw.get("opensearch_ssh_user")
        self.opensearch_ssh_port     = self._raw.get("opensearch_ssh_port", 22)
        self.opensearch_ssh_key_path = self._raw.get("opensearch_ssh_key_path")

        # Network
        self.kali_ip   = self._raw.get("kali_ip")
        self.target_ip = self._raw.get("target_ip")

        # Reports / attack limits
        self.report_format       = self._raw.get("report_format", "pdf")
        self.max_spray_attempts  = self._raw.get("max_spray_attempts", 3)
        self.spray_delay_s       = self._raw.get("spray_delay_s", 5)

    def get(self, key: str, default=None):
        """Escape hatch for config keys not promoted to a named attribute above."""
        return self._raw.get(key, default)

    def apply_defaults(self, kwargs: dict) -> dict:
        """
        Fill in missing 'user' / 'password' / 'domain' kwargs from config.

        This is the same credential-injection behavior Executor.run_module()
        used to perform inline; centralizing it here means any other caller
        (e.g. future playbook runners) gets identical defaulting for free.

        Args:
            kwargs (dict): Keyword arguments about to be passed to a module function.

        Returns:
            dict: A new dict with 'user'/'password'/'domain' filled in where absent.
                  Does not mutate the input.
        """
        kwargs = dict(kwargs)
        if not kwargs.get('user'):
            kwargs['user'] = self.domain_user
        if not kwargs.get('password'):
            kwargs['password'] = self.domain_password
        # Override the placeholder default domain.local with the real configured domain
        if kwargs.get('domain') in (None, 'domain.local'):
            kwargs['domain'] = self.domain
        return kwargs
