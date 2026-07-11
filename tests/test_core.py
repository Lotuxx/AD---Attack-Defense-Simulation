"""
Unit tests — Core framework components
=======================================
Tests the loader, executor, report generator and format utilities
without requiring a live AD or Wazuh connection.
"""

import os
import sys
import json
import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.loader import ModuleLoader
from core.executor import Executor
from core.report_generator import ReportGenerator
from core.config import Config, load_config
from core.wazuh_api import WazuhAPI, connect_or_warn
from core.ssh_tunnel import ensure_tunnel, _port_is_open, _read_state, _write_state
from utils.format_utils import format_table, risk_badge, print_step


# ── ModuleLoader tests ────────────────────────────────────────────────────────

class TestModuleLoader:
    """Tests for the dynamic module loader."""

    def setup_method(self):
        self.loader = ModuleLoader()

    def test_load_valid_module(self):
        """Should successfully load an existing module."""
        mod = self.loader.load("blue_team.audit_passwords")
        assert mod is not None
        assert hasattr(mod, "run_audit"), "Module must expose run_audit()"

    def test_load_invalid_module(self):
        """Should return None for a non-existent module path."""
        mod = self.loader.load("blue_team.does_not_exist")
        assert mod is None

    def test_load_all_blue_team_modules(self):
        """All blue team modules must be importable."""
        modules = [
            "blue_team.audit_passwords",
            "blue_team.audit_privileges",
            "blue_team.audit_gpo",
            "blue_team.audit_network",
            "blue_team.audit_logs",
        ]
        for path in modules:
            mod = self.loader.load(path)
            assert mod is not None, f"Failed to load {path}"
            assert hasattr(mod, "run_audit"), f"{path} missing run_audit()"

    def test_load_all_red_team_modules(self):
        """All red team modules must be importable."""
        modules = [
            "red_team.password_spray",
            "red_team.kerberoasting",
            "red_team.llmnr_poisoning",
            "red_team.pth",
            "red_team.lateral_mouvement",
        ]
        for path in modules:
            mod = self.loader.load(path)
            assert mod is not None, f"Failed to load {path}"
            assert hasattr(mod, "run_attack"), f"{path} missing run_attack()"

    def test_load_all_purple_team_modules(self):
        """All purple team modules must be importable."""
        modules = [
            "purple_team.validate_detection",
            "purple_team.fetch_wazuh_alerts",
            "purple_team.correlate_attack",
        ]
        for path in modules:
            mod = self.loader.load(path)
            assert mod is not None, f"Failed to load {path}"
            assert hasattr(mod, "run"), f"{path} missing run()"

    def test_load_all_response_modules(self):
        """All response modules must be importable."""
        modules = [
            "response.disable_user",
            "response.block_ip",
            "response.reset_password",
            "response.isolate_host",
        ]
        for path in modules:
            mod = self.loader.load(path)
            assert mod is not None, f"Failed to load {path}"
            assert hasattr(mod, "run"), f"{path} missing run()"

    def test_list_modules(self):
        """list_modules() should return non-empty lists for each team."""
        for team in ["blue_team", "red_team", "purple_team", "response"]:
            mods = self.loader.list_modules(team)
            assert len(mods) > 0, f"No modules found in {team}/"

    def test_list_modules_invalid_team(self):
        """list_modules() should return empty list for unknown team."""
        result = self.loader.list_modules("nonexistent_team")
        assert result == []


# ── Executor tests ────────────────────────────────────────────────────────────

class TestExecutor:
    """Tests for the module/playbook executor."""

    def setup_method(self):
        self.loader   = ModuleLoader()
        self.executor = Executor(self.loader)

    def test_run_module_missing_returns_error(self):
        """Running a missing module should return error result, not raise."""
        result = self.executor.run_module("blue_team.nonexistent", "run_audit")
        assert result["status"] == "error"
        assert "findings" in result
        assert result["findings"] == []

    def test_run_module_missing_function(self):
        """Calling a non-existent function on a real module should return error."""
        result = self.executor.run_module("blue_team.audit_passwords", "nonexistent_func")
        assert result["status"] == "error"

    def test_error_result_structure(self):
        """_error_result() should always return a complete standardised dict."""
        err = Executor._error_result("test.module", "Something broke", 1.5)
        assert err["status"]    == "error"
        assert err["module"]    == "test.module"
        assert err["message"]   == "Something broke"
        assert err["elapsed_s"] == 1.5
        assert "timestamp" in err
        assert err["findings"]  == []

    def test_run_nonexistent_playbook(self):
        """Running a missing playbook should return empty list, not raise."""
        result = self.executor.run_playbook("red_team/nonexistent.yaml")
        assert result == []

    def test_run_valid_playbook(self):
        """run_playbook() should execute a valid playbook and return results."""
        # Use a playbook that exists in the repo
        result = self.executor.run_playbook("red_team/full_attack.yaml")
        assert isinstance(result, list)
        # Each result should have the standard structure
        for res in result:
            assert "status" in res
            assert "module" in res

    def test_run_module_with_exception(self):
        """run_module() should catch exceptions and return error result."""
        with patch("core.executor.ModuleLoader.load") as mock_load:
            mock_mod = MagicMock()
            mock_mod.run_attack.side_effect = RuntimeError("Simulated exception")
            mock_load.return_value = mock_mod
            result = self.executor.run_module("red_team.error_test", "run_attack")
            assert result["status"] == "error"
            assert "Simulated exception" in result.get("message", "")

    def test_run_module_passes_kwargs(self):
        """run_module() should pass all kwargs to the module function."""
        with patch("core.executor.ModuleLoader.load") as mock_load:
            mock_mod = MagicMock()
            mock_mod.run_attack.return_value = {"status": "success", "findings": []}
            mock_load.return_value = mock_mod
            self.executor.run_module(
                "red_team.password_spray", "run_attack",
                target="192.168.56.12", domain="test.local"
            )
            # Verify the kwargs were passed (note: Config.apply_defaults fills in defaults)
            call_kwargs = mock_mod.run_attack.call_args[1]
            assert "target" in call_kwargs or call_kwargs.get("target") == "192.168.56.12"


# ── ReportGenerator tests ─────────────────────────────────────────────────────

class TestReportGenerator:
    """Tests for PDF report generation."""

    def setup_method(self):
        self.gen = ReportGenerator()
        # Sample result dict matching module output format
        self.sample_result = {
            "module":    "blue_team.audit_passwords",
            "status":    "warning",
            "elapsed_s": 1.23,
            "timestamp": datetime.now().isoformat(),
            "findings": [
                {
                    "risk":        "Élevé",
                    "title":       "Weak password policy",
                    "description": "MinPasswordLength = 6",
                    "mitigation":  "Set MinPasswordLength to 12+",
                    "event_ids":   [],
                }
            ],
        }

    def test_generate_creates_pdf(self, tmp_path, monkeypatch):
        """generate() should create a single PDF file."""
        # Redirect reports to temp dir
        monkeypatch.setattr(
            "core.report_generator.REPORTS_DIR", str(tmp_path)
        )
        self.gen.generate(self.sample_result, "test_report")
        files = list(tmp_path.iterdir())
        exts  = {f.suffix for f in files}
        assert exts == {".pdf"}, f"Expected only a .pdf report, got {exts}"

    def test_generate_pdf_contains_expected_text(self, tmp_path, monkeypatch):
        """PDF report should contain the finding title and module name."""
        import pdfplumber
        monkeypatch.setattr("core.report_generator.REPORTS_DIR", str(tmp_path))
        self.gen.generate(self.sample_result, "test_report")
        pdf_files = list(tmp_path.glob("*.pdf"))
        assert len(pdf_files) == 1
        with pdfplumber.open(str(pdf_files[0])) as pdf:
            content = "\n".join(page.extract_text() or "" for page in pdf.pages)
        assert "blue_team.audit_passwords" in content
        assert "Weak password policy" in content

    def test_generate_redacts_secrets(self, tmp_path, monkeypatch):
        """generate() should mask any configured secret value found in report text."""
        import pdfplumber
        monkeypatch.setattr("core.report_generator.REPORTS_DIR", str(tmp_path))
        gen = ReportGenerator(secrets=["SuperSecretPass123"])
        result = {
            "module": "red_team.password_spray", "status": "success",
            "elapsed_s": 1, "timestamp": datetime.now().isoformat(),
            "findings": [{
                "risk": "Critique", "title": "leak test",
                "description": "leaked value: SuperSecretPass123",
                "mitigation": "", "event_ids": [],
            }],
        }
        gen.generate(result, "secret_report")
        pdf_files = list(tmp_path.glob("*.pdf"))
        with pdfplumber.open(str(pdf_files[0])) as pdf:
            content = "\n".join(page.extract_text() or "" for page in pdf.pages)
        assert "SuperSecretPass123" not in content

    def test_generate_accepts_list(self, tmp_path, monkeypatch):
        """generate() should accept a list of results (full audit output)."""
        monkeypatch.setattr("core.report_generator.REPORTS_DIR", str(tmp_path))
        results = [self.sample_result, self.sample_result]
        self.gen.generate(results, "multi_report")
        assert len(list(tmp_path.iterdir())) == 1  # still a single combined PDF


# ── Format utilities tests ────────────────────────────────────────────────────

class TestFormatUtils:
    """Tests for display formatting helpers."""

    def test_format_table_basic(self):
        """format_table() should return a non-empty string with headers."""
        result = format_table(["Name", "Status"], [["audit_passwords", "OK"]])
        assert "Name"             in result
        assert "Status"           in result
        assert "audit_passwords"  in result
        assert "OK"               in result

    def test_format_table_auto_width(self):
        """Column widths should expand to fit the longest cell value."""
        long_value = "a" * 50
        result = format_table(["Col"], [[long_value]])
        assert long_value in result

    def test_risk_badge_known_levels(self):
        """risk_badge() should return a non-empty string for known risk levels."""
        for level in ["Critique", "Élevé", "Moyen", "Faible", "Info"]:
            badge = risk_badge(level)
            assert level in badge, f"Level '{level}' not in badge output"
            assert len(badge) > len(level), "Badge should include color codes"

    def test_risk_badge_unknown_level(self):
        """risk_badge() should handle unknown levels gracefully."""
        badge = risk_badge("UnknownLevel")
        assert "UnknownLevel" in badge


# ── Config tests ──────────────────────────────────────────────────────────────

class TestConfig:
    """Tests for the centralized Config class."""

    def test_config_defaults(self):
        """Config should have sensible defaults for all fields."""
        cfg = Config(raw={})
        assert cfg.domain == "domain.local"
        assert cfg.dc_ip == "127.0.0.1"
        assert cfg.wazuh_host == "127.0.0.1"
        assert cfg.wazuh_port == 55000
        assert cfg.wazuh_user == "wazuh"

    def test_config_opensearch_fallback_to_wazuh(self):
        """OpenSearch creds should default to Wazuh creds if not set."""
        cfg = Config(raw={"wazuh_user": "admin", "wazuh_password": "secret123"})
        assert cfg.opensearch_user == "admin"
        assert cfg.opensearch_password == "secret123"

    def test_config_opensearch_override(self):
        """OpenSearch creds should be usable separately."""
        cfg = Config(raw={
            "wazuh_user": "wazuh",
            "wazuh_password": "wazuh",
            "opensearch_user": "es_admin",
            "opensearch_password": "es_secret",
        })
        assert cfg.opensearch_user == "es_admin"
        assert cfg.opensearch_password == "es_secret"

    def test_config_apply_defaults_fills_missing(self):
        """apply_defaults() should fill in user/password/domain from config."""
        cfg = Config(raw={
            "domain_user": "testuser",
            "domain_password": "testpass",
            "domain": "test.local",
        })
        kwargs = {}
        result = cfg.apply_defaults(kwargs)
        assert result["user"] == "testuser"
        assert result["password"] == "testpass"
        assert result["domain"] == "test.local"

    def test_config_apply_defaults_preserves_explicit(self):
        """apply_defaults() should not override explicit kwargs."""
        cfg = Config(raw={"domain_user": "default", "domain": "test.local"})
        kwargs = {"user": "explicit", "domain": "custom.local"}
        result = cfg.apply_defaults(kwargs)
        assert result["user"] == "explicit"
        assert result["domain"] == "custom.local"

    def test_config_apply_defaults_replaces_placeholder_domain(self):
        """apply_defaults() should replace placeholder 'domain.local' with config domain."""
        cfg = Config(raw={"domain": "real.local"})
        kwargs = {"domain": "domain.local"}
        result = cfg.apply_defaults(kwargs)
        assert result["domain"] == "real.local"

    def test_config_get_unknown_key(self):
        """get() should return None for unknown keys by default."""
        cfg = Config(raw={"known": "value"})
        assert cfg.get("known") == "value"
        assert cfg.get("unknown") is None
        assert cfg.get("unknown", "default") == "default"


# ── WazuhAPI tests ────────────────────────────────────────────────────────────

class TestWazuhAPI:
    """Tests for the Wazuh API client."""

    def test_wazuh_api_defaults(self):
        """WazuhAPI should have sensible defaults."""
        api = WazuhAPI(config={})
        assert api.host is not None
        assert api.port == 55000
        assert api.user is not None

    def test_wazuh_api_from_config(self):
        """WazuhAPI should accept raw config dict."""
        api = WazuhAPI(config={
            "wazuh_host": "192.168.1.100",
            "wazuh_port": 55001,
            "wazuh_user": "admin",
        })
        assert api.host == "192.168.1.100"
        assert api.port == 55001
        assert api.user == "admin"

    def test_connect_or_warn_fallback(self):
        """connect_or_warn() should return (api, False) and warn if auth fails."""
        with patch.object(WazuhAPI, "authenticate", return_value=False):
            api, connected = connect_or_warn("Test offline message.")
            assert api is not None
            assert connected is False

    def test_connect_or_warn_success(self):
        """connect_or_warn() should return (api, True) if auth succeeds."""
        with patch.object(WazuhAPI, "authenticate", return_value=True):
            api, connected = connect_or_warn()
            assert api is not None
            assert connected is True


# ── SSHTunnel tests ───────────────────────────────────────────────────────────

class TestSSHTunnel:
    """Tests for SSH tunnel management."""

    def test_port_is_open_when_listening(self):
        """_port_is_open() should return True when a port has a listener."""
        import socket
        import threading
        # Start a listener on a test port
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 19999))
        srv.listen(1)
        def accept_once():
            try:
                srv.accept()
            except:
                pass
        threading.Thread(target=accept_once, daemon=True).start()
        import time
        time.sleep(0.1)
        
        assert _port_is_open("127.0.0.1", 19999) is True
        assert _port_is_open("127.0.0.1", 19998) is False  # Not listening
        srv.close()

    def test_state_file_read_write(self, tmp_path, monkeypatch):
        """_read_state() and _write_state() should round-trip correctly."""
        import core.ssh_tunnel
        state_file = str(tmp_path / "test_state")
        monkeypatch.setattr(core.ssh_tunnel, "_STATE_FILE", state_file)
        
        _write_state(1234, 9200)
        state = _read_state()
        assert state == {"pid": 1234, "local_port": 9200}

    def test_ensure_tunnel_fallback_no_config(self, monkeypatch):
        """ensure_tunnel() should warn and return default port if no SSH config."""
        cfg = Config(raw={})
        port = ensure_tunnel(cfg)
        assert port == 9200  # Default fallback

    def test_ensure_tunnel_reuses_existing_port(self, monkeypatch, tmp_path):
        """ensure_tunnel() should reuse a port already listening."""
        import socket
        import threading
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 19111))
        srv.listen(1)
        def accept_once():
            try:
                srv.accept()
            except:
                pass
        threading.Thread(target=accept_once, daemon=True).start()
        import time
        time.sleep(0.1)
        
        cfg = Config(raw={"opensearch_local_port": 19111})
        port = ensure_tunnel(cfg)
        assert port == 19111
        srv.close()


# ── Extended FormatUtils tests ────────────────────────────────────────────────

class TestFormatUtilsExtended:
    """Additional tests for format_utils edge cases."""

    def test_print_step_inline_progress(self, capsys):
        """print_step() should print a progress bar without permanent newline."""
        for i in range(3):
            print_step(i + 1, 3, f"Step {i + 1}")
        # Capture output (progress bars end with \r, so the output might appear garbled)
        captured = capsys.readouterr()
        assert "Step 1" in captured.out or "Step 2" in captured.out

    def test_format_table_empty_rows(self):
        """format_table() should handle empty row lists."""
        result = format_table(["Header1", "Header2"], [])
        assert "Header1" in result
        assert "Header2" in result

    def test_format_table_single_cell(self):
        """format_table() should handle single-cell tables."""
        result = format_table(["Only"], [["Value"]])
        assert "Only" in result
        assert "Value" in result

    def test_risk_badge_all_language_variants(self):
        """risk_badge() should recognize both French and English risk levels."""
        for level in ["Critique", "Critical", "Élevé", "High", "Moyen", "Medium", "Faible", "Low"]:
            badge = risk_badge(level)
            assert level in badge
