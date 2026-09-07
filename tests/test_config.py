from __future__ import annotations

import pytest

from qualys_qid_vulnerabilities import config as config_module
from qualys_qid_vulnerabilities.config import AppConfig
from qualys_qid_vulnerabilities.errors import ConfigurationValidationError


def test_standalone_environment_overrides_use_project_neutral_names() -> None:
    config = AppConfig.load(
        config_file="/does-not-exist/runtime.toml",
        env_file="/does-not-exist/.env",
        environ={
            "QUALYS_BASE_URL": "https://gateway.example.test",
            "QUALYS_AUTH_MODEL": "basic",
            "QUALYS_USERNAME": "user",
            "QUALYS_PASSWORD": "password",
            "QUALYS_TIMEOUT_SECONDS": "11",
            "QUALYS_VERIFY_SSL": "false",
        },
    )

    assert config.qualys.auth_model == "basic"
    assert config.qualys.timeout_seconds == 11
    assert config.qualys.verify_ssl is False


def test_legacy_asset_gap_environment_names_are_not_consumed() -> None:
    with pytest.raises(
        ConfigurationValidationError,
        match="qualys.base_url must start with",
    ):
        AppConfig.load(
            config_file="/does-not-exist/runtime.toml",
            env_file="/does-not-exist/.env",
            environ={
                "LEGACY_APP_QUALYS_AUTH_MODEL": "basic",
                "LEGACY_APP_QUALYS_TIMEOUT_SECONDS": "11",
            },
        )


def test_defaults_are_not_relative_to_current_directory(tmp_path, monkeypatch) -> None:
    project_root = tmp_path / "project"
    config_path = project_root / "config" / "runtime.toml"
    env_path = project_root / ".env"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        '[qualys]\nbase_url = "https://gateway.example.test"\nauth_model = "basic"\n',
        encoding="utf-8",
    )
    env_path.write_text(
        "QUALYS_USERNAME=user\nQUALYS_PASSWORD=password\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config_module, "DEFAULT_CONFIG_FILE", config_path)
    monkeypatch.setattr(config_module, "DEFAULT_ENV_FILE", env_path)
    (tmp_path / "somewhere").mkdir()
    monkeypatch.chdir(tmp_path / "somewhere")

    config = AppConfig.load()

    assert config.qualys.base_url == "https://gateway.example.test"
    assert config.secrets.username == "user"
