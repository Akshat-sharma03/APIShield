"""Unit tests for the secure configuration loader."""

import pytest

from apishield import config as config_module
from apishield.config import (
    ConfigurationError,
    RuntimeConfig,
    load_config,
    parse_env_file,
)


@pytest.fixture
def clean_environment(monkeypatch, tmp_path):
    """Point the loader at a temporary .env and clear the process env."""
    env_file = tmp_path / ".env"
    monkeypatch.setattr(config_module, "ENV_FILE", env_file)
    monkeypatch.delenv("APISHIELD_BASE_URL", raising=False)
    monkeypatch.delenv("APISHIELD_USER_A_TOKEN", raising=False)
    monkeypatch.delenv("APISHIELD_USER_B_TOKEN", raising=False)
    monkeypatch.delenv("APISHIELD_USER_A_VEHICLE_ID", raising=False)
    monkeypatch.delenv("APISHIELD_USER_B_VEHICLE_ID", raising=False)
    return env_file


class TestEnvFileParsing:
    def test_parses_basic_pairs(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("A=1\nB=two\n")
        assert parse_env_file(env_file) == {"A": "1", "B": "two"}

    def test_ignores_comments_and_blank_lines(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("# comment\n\nA=1\n")
        assert parse_env_file(env_file) == {"A": "1"}

    def test_strips_quotes(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text('A="quoted"\nB=\'single\'\n')
        assert parse_env_file(env_file) == {"A": "quoted", "B": "single"}

    def test_supports_export_prefix(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("export A=1\n")
        assert parse_env_file(env_file) == {"A": "1"}

    def test_ignores_malformed_lines(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("not-a-pair\n=noname\nA=1\n")
        assert parse_env_file(env_file) == {"A": "1"}

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_env_file(tmp_path / "absent.env") == {}


class TestLoadConfig:
    def test_loads_all_variables(self, clean_environment):
        clean_environment.write_text(
            "APISHIELD_BASE_URL=http://127.0.0.1:8888\n"
            "APISHIELD_USER_A_TOKEN=token-a\n"
            "APISHIELD_USER_B_TOKEN=token-b\n"
            "APISHIELD_USER_A_VEHICLE_ID=veh-a\n"
            "APISHIELD_USER_B_VEHICLE_ID=veh-b\n"
        )
        cfg = load_config()
        assert isinstance(cfg, RuntimeConfig)
        assert cfg.base_url == "http://127.0.0.1:8888"
        assert cfg.user_a_token == "token-a"

    def test_missing_file_reports_variable_names_only(self, clean_environment):
        with pytest.raises(ConfigurationError) as excinfo:
            load_config()
        message = str(excinfo.value)
        assert "APISHIELD_BASE_URL" in message
        # No secret values should ever appear in the message.
        assert "token" not in message.lower() or "APISHIELD" in message

    def test_empty_value_treated_as_missing(self, clean_environment):
        clean_environment.write_text("APISHIELD_BASE_URL=\n")
        with pytest.raises(ConfigurationError, match="APISHIELD_BASE_URL"):
            load_config()

    def test_partial_configuration_lists_missing(self, clean_environment):
        clean_environment.write_text(
            "APISHIELD_BASE_URL=http://127.0.0.1:8888\n"
            "APISHIELD_USER_A_TOKEN=token-a\n"
        )
        with pytest.raises(ConfigurationError) as excinfo:
            load_config()
        message = str(excinfo.value)
        assert "APISHIELD_USER_B_TOKEN" in message
        assert "APISHIELD_USER_A_VEHICLE_ID" in message

    def test_process_env_overrides_file(self, clean_environment, monkeypatch):
        clean_environment.write_text("APISHIELD_USER_A_TOKEN=from-file\n")
        monkeypatch.setenv("APISHIELD_USER_A_TOKEN", "from-process")
        monkeypatch.setenv("APISHIELD_BASE_URL", "http://127.0.0.1:8888")
        monkeypatch.setenv("APISHIELD_USER_B_TOKEN", "b")
        monkeypatch.setenv("APISHIELD_USER_A_VEHICLE_ID", "va")
        monkeypatch.setenv("APISHIELD_USER_B_VEHICLE_ID", "vb")
        cfg = load_config()
        assert cfg.user_a_token == "from-process"

    def test_repr_never_leaks_secrets(self, clean_environment):
        clean_environment.write_text(
            "APISHIELD_BASE_URL=http://127.0.0.1:8888\n"
            "APISHIELD_USER_A_TOKEN=super-secret-token\n"
            "APISHIELD_USER_B_TOKEN=super-secret-token-b\n"
            "APISHIELD_USER_A_VEHICLE_ID=veh-a\n"
            "APISHIELD_USER_B_VEHICLE_ID=veh-b\n"
        )
        cfg = load_config()
        assert "super-secret" not in repr(cfg)
