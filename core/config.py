# ============================================================================
# Configuration Management Layer
# ============================================================================
# This module provides the centralized configuration system for the entire
# AD Attack & Defense Simulation Framework.
#
# Responsibilities:
#
#   - Load configuration values from config.yaml.
#   - Override sensitive values using environment variables.
#   - Provide typed access to framework settings.
#   - Inject default execution parameters into modules.
#
# Architecture role:
#
#       config.yaml
#             |
#             v
#       load_config()
#             |
#             v
#          Config()
#             |
#             v
#     Executor / Modules / Reports
#
# Centralizing configuration prevents duplicated configuration-loading logic
# across the framework and ensures all components use the same settings.
#
# Security considerations:
#
#   - Secrets should preferably be provided through environment variables.
#   - Credentials should not be committed into source repositories.
#   - Production deployments should use a secret manager/vault.
# ============================================================================

import os
import yaml


# ============================================================================
# Environment-variable controlled secrets
# ============================================================================
# These configuration keys contain sensitive information.
#
# Instead of storing them directly inside config.yaml, they can be provided
# dynamically through environment variables:
#
# Example:
#
#     domain_password  -> DOMAIN_PASSWORD
#
# This approach is safer for:
#   - shared repositories,
#   - CI/CD pipelines,
#   - collaborative security labs.
#
# Values from environment variables take priority over config.yaml values.
# ============================================================================

_ENV_OVERRIDABLE_KEYS = (
    "domain_password",
    "wazuh_password",
    "opensearch_password",
)


def load_config(path: str = None) -> dict:
    """
    Load framework configuration from YAML and apply secret overrides.

    This function is the single configuration entry point.

    Loading priority:

        1. Environment variables (highest priority).
        2. config.yaml values.
        3. Empty dictionary fallback.

    This ensures sensitive values can be injected securely without modifying
    configuration files.

    Args:
        path (str, optional):
            Custom configuration file path.

            If omitted:
                Uses the project root config.yaml file.

    Returns:
        dict:
            Parsed configuration dictionary.

            Returns an empty dictionary if:
                - the file does not exist,
                - YAML parsing fails.
    """

    if path is None:

        # Default configuration location:
        # project_root/config.yaml
        path = os.path.join(
            os.path.dirname(
                os.path.dirname(__file__)
                ), "config.yaml"
            )

    cfg = {}
    if os.path.exists(path):
        try:

            # safe_load prevents execution of arbitrary YAML objects.
            # This is preferred over yaml.load() when loading configuration.
            with open(path) as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:

            # A broken configuration should not crash the entire framework.
            # Returning an empty configuration allows components to fallback
            # to internal defaults.
            cfg = {}

    # Apply environment variable overrides.
    #
    # Environment values have priority because they are commonly used for
    # secrets management in automated environments.
    for key in _ENV_OVERRIDABLE_KEYS:
        env_val = os.environ.get(key.upper())
        if env_val:
            cfg[key] = env_val

    return cfg



# ============================================================================
# Typed configuration wrapper
# ============================================================================
# The Config class provides a structured interface around raw configuration
# values.
#
# Instead of repeatedly using:
#
#     cfg.get("domain", "domain.local")
#
# throughout the project, modules can access:
#
#     config.domain
#
# Benefits:
#
#   - Better readability.
#   - Centralized defaults.
#   - Easier maintenance.
#   - Reduced configuration inconsistencies.
# ============================================================================
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
        """
    Initialize framework configuration.

    Args:
        raw (dict, optional):
            Existing configuration dictionary.
            Useful for testing or injecting custom settings.

        path (str, optional):
            Custom config.yaml path.
    """
        
        self._raw = raw if raw is not None else load_config(path)


        # ============================================================================
        # Active Directory environment configuration
        # ============================================================================
        # Contains parameters required by:
        #
        #   - Authentication.
        #   - Attack simulations.
        #   - Security audits.
        #   - Domain enumeration.
        #
        # These values are consumed by Red Team and Blue Team modules.
        # ============================================================================

        # Active Directory
        self.domain          = self._raw.get("domain", "domain.local")
        self.dc_ip           = self._raw.get("dc_ip", "127.0.0.1")
        self.domain_user     = self._raw.get("domain_user")
        self.domain_password = self._raw.get("domain_password")


        # ============================================================================
        # SIEM / Detection infrastructure configuration
        # ============================================================================
        # Defines communication parameters for:
        #
        #   - Wazuh API.
        #   - OpenSearch backend.
        #
        # These settings are mainly used by Purple Team components to:
        #
        #   - retrieve alerts,
        #   - validate detection,
        #   - correlate attacks with security events.
        # ============================================================================
        self.wazuh_host          = self._raw.get("wazuh_host", "127.0.0.1")
        self.wazuh_port          = self._raw.get("wazuh_port", 55000)
        self.wazuh_user          = self._raw.get("wazuh_user", "wazuh")
        self.wazuh_password      = self._raw.get("wazuh_password", "wazuh")
        self.opensearch_user     = self._raw.get("opensearch_user", self.wazuh_user)
        self.opensearch_password = self._raw.get("opensearch_password", self.wazuh_password)
        self.verify_ssl          = self._raw.get("verify_ssl", False)


        # ============================================================================
        # OpenSearch SSH tunnel configuration
        # ============================================================================
        # Optional configuration for automatically accessing OpenSearch through an
        # SSH tunnel.
        #
        # This replaces the need for manually running:
        #
        #     ssh -L 9200:localhost:9200 ...
        #
        # before Purple Team detection analysis.
        #
        # Used when OpenSearch is not directly exposed.
        # ============================================================================
        self.opensearch_local_port   = self._raw.get("opensearch_local_port", 9200)
        self.opensearch_remote_port  = self._raw.get("opensearch_remote_port", 9200)
        self.opensearch_ssh_host     = self._raw.get("opensearch_ssh_host") or self.wazuh_host
        self.opensearch_ssh_user     = self._raw.get("opensearch_ssh_user")
        self.opensearch_ssh_port     = self._raw.get("opensearch_ssh_port", 22)
        self.opensearch_ssh_key_path = self._raw.get("opensearch_ssh_key_path")


        # ============================================================================
        # Network configuration
        # ============================================================================
        # Stores addresses used during simulations:
        #
        #   kali_ip:
        #       Attacker machine address.
        #
        #   target_ip:
        #       Target system address.
        #
        # These values are mainly used by attack modules.
        # ============================================================================
        self.kali_ip   = self._raw.get("kali_ip")
        self.target_ip = self._raw.get("target_ip")


        # ============================================================================
        # Execution limits and reporting configuration
        # ============================================================================
        # Controls:
        #
        #   - Generated report format.
        #   - Password spraying limits.
        #   - Delay between authentication attempts.
        #
        # Spray limits help prevent uncontrolled authentication attempts
        # against laboratory environments.
        # ============================================================================
        self.report_format       = self._raw.get("report_format", "pdf")
        self.max_spray_attempts  = self._raw.get("max_spray_attempts", 3)
        self.spray_delay_s       = self._raw.get("spray_delay_s", 5)


    def get(self, key: str, default=None):
        """
        Retrieve a configuration value not exposed as a class attribute.
        """
        return self._raw.get(key, default)


    def apply_defaults(self, kwargs: dict) -> dict:
        """
    Apply default execution parameters to module arguments.

    Some modules require common parameters:
        - username,
        - password,
        - domain.

    Instead of every module implementing its own fallback logic,
    this function injects missing values from the centralized configuration.

    Existing user-provided values always have priority.

    Args:
        kwargs (dict):
            Arguments that will be passed to a module.

    Returns:
        dict:
            New dictionary containing completed parameters.
            The original dictionary is not modified.
    """
        
        # Work on a copy to avoid modifying caller data.
        kwargs = dict(kwargs)

        # Inject configured domain credentials when missing.
        #
        # This allows modules to simply request:
        #
        #     run_attack(target="192.168.56.10")
        #
        # while authentication details are automatically supplied.
        if not kwargs.get('user'):
            kwargs['user'] = self.domain_user
        if not kwargs.get('password'):
            kwargs['password'] = self.domain_password
        
        # Replace the framework placeholder domain with the real configured
        # Active Directory domain.
        if kwargs.get('domain') in (None, 'domain.local'):
            kwargs['domain'] = self.domain
        return kwargs
