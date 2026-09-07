"""Standalone runtime configuration and secret loading for the QID tool."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import tomllib
from typing import Any, Mapping

from qualys_qid_vulnerabilities.auth_validation import AuthConfigValidator
from qualys_qid_vulnerabilities.errors import (
    ConfigurationFileError,
    ConfigurationValidationError,
)
from qualys_qid_vulnerabilities.qualys_base_url import validate_live_qualys_operation_config


DEFAULT_CONFIG = {
    "schema_version": 1,
    "qualys": {
        # The service region is deployment-specific and must be configured
        # locally; no real endpoint is distributed with the tool.
        "base_url": "",
        "auth_model": "unset",
        "timeout_seconds": 30,
        "retry_attempts": 3,
        "retry_backoff_seconds": 2.0,
        "verify_ssl": True,
    },
}

# The installer sets QID_PROJECT_ROOT in the launcher. This keeps the runtime
# files beside the installed copy even though Python imports the package from
# its private virtual environment.
PROJECT_ROOT = Path(
    os.environ.get("QID_PROJECT_ROOT", Path(__file__).resolve().parents[2])
).expanduser().resolve()
DEFAULT_CONFIG_FILE = PROJECT_ROOT / "config" / "runtime.toml"
DEFAULT_ENV_FILE = PROJECT_ROOT / ".env"


@dataclass(frozen=True, slots=True)
class QualysRuntimeConfig:
    base_url: str
    auth_model: str
    timeout_seconds: int
    retry_attempts: int
    retry_backoff_seconds: float
    verify_ssl: bool

    def validate(self) -> None:
        if not self.base_url.startswith(("http://", "https://")):
            raise ConfigurationValidationError(
                "qualys.base_url must start with http:// or https://"
            )
        if self.auth_model not in AuthConfigValidator.supported_auth_models():
            supported = ", ".join(AuthConfigValidator.supported_auth_models())
            raise ConfigurationValidationError(
                f"qualys.auth_model must be one of: {supported}"
            )
        if self.timeout_seconds <= 0:
            raise ConfigurationValidationError("qualys.timeout_seconds must be positive")
        if self.retry_attempts < 0 or self.retry_backoff_seconds < 0:
            raise ConfigurationValidationError("Qualys retry settings must be non-negative")


@dataclass(frozen=True, slots=True)
class QualysSecrets:
    username: str | None = None
    password: str | None = None
    access_token: str | None = None


@dataclass(frozen=True, slots=True)
class AppConfig:
    qualys: QualysRuntimeConfig
    secrets: QualysSecrets

    @classmethod
    def load(
        cls,
        *,
        config_file: str | Path | None = None,
        env_file: str | Path | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> "AppConfig":
        config_file = config_file or DEFAULT_CONFIG_FILE
        env_file = env_file or DEFAULT_ENV_FILE
        env = dict(environ or os.environ)
        if env_file and Path(env_file).exists():
            env = {**_read_env_file(env_file), **env}
        raw = dict(DEFAULT_CONFIG)
        if config_file and Path(config_file).exists():
            raw = _merge(raw, _read_toml(config_file))
        qualys = _merge(raw["qualys"], _environment_overrides(env))
        runtime = QualysRuntimeConfig(
            base_url=str(qualys.get("base_url", "")).strip(),
            auth_model=str(qualys.get("auth_model", "")).strip().lower(),
            timeout_seconds=int(qualys.get("timeout_seconds", 30)),
            retry_attempts=int(qualys.get("retry_attempts", 3)),
            retry_backoff_seconds=float(qualys.get("retry_backoff_seconds", 2.0)),
            verify_ssl=_parse_bool(qualys.get("verify_ssl", True)),
        )
        config = cls(
            qualys=runtime,
            secrets=QualysSecrets(
                username=_clean(env.get("QUALYS_USERNAME")),
                password=_clean(env.get("QUALYS_PASSWORD")),
                access_token=_clean(env.get("QUALYS_ACCESS_TOKEN")),
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        self.qualys.validate()
        AuthConfigValidator.validate(
            auth_model=self.qualys.auth_model,
            username=self.secrets.username,
            password=self.secrets.password,
            access_token=self.secrets.access_token,
        )
        validate_live_qualys_operation_config(
            base_url=self.qualys.base_url,
            auth_model=self.qualys.auth_model,
        )


def _read_toml(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    try:
        with config_path.open("rb") as handle:
            value = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigurationFileError(f"Config file not found: {config_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigurationFileError(f"Invalid TOML config file: {config_path}") from exc
    return value


def _read_env_file(path: str | Path) -> dict[str, str]:
    env_path = Path(path)
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise ConfigurationFileError(f"Environment file not found: {env_path}") from exc
    values: dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.removeprefix("export ").strip()] = value.strip().strip("\"'")
    return values


def _environment_overrides(env: Mapping[str, str]) -> dict[str, Any]:
    names = {
        "QUALYS_BASE_URL": "base_url",
        "QUALYS_AUTH_MODEL": "auth_model",
        "QUALYS_TIMEOUT_SECONDS": "timeout_seconds",
        "QUALYS_RETRY_ATTEMPTS": "retry_attempts",
        "QUALYS_RETRY_BACKOFF_SECONDS": "retry_backoff_seconds",
        "QUALYS_VERIFY_SSL": "verify_ssl",
    }
    return {field: env[name] for name, field in names.items() if name in env}


def _merge(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(result.get(key), Mapping) and isinstance(value, Mapping):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def _clean(value: str | None) -> str | None:
    value = value.strip() if value else None
    return value or None


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"1", "true", "yes", "on"}:
        return True
    if isinstance(value, str) and value.strip().lower() in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationValidationError("qualys.verify_ssl must be a boolean value")
