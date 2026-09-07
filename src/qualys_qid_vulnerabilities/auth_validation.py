"""Auth-model secret validation isolated from config loading concerns."""

from __future__ import annotations

from dataclasses import dataclass

from qualys_qid_vulnerabilities.errors import (
    ConfigurationValidationError,
    SecretConfigurationError,
)


@dataclass(frozen=True, slots=True)
class SecretFieldDefinition:
    """Metadata for supported secret fields."""

    field_name: str
    env_var: str


SECRET_FIELD_DEFINITIONS: tuple[SecretFieldDefinition, ...] = (
    SecretFieldDefinition(field_name="access_token", env_var="QUALYS_ACCESS_TOKEN"),
    SecretFieldDefinition(field_name="password", env_var="QUALYS_PASSWORD"),
    SecretFieldDefinition(field_name="username", env_var="QUALYS_USERNAME"),
)
SECRET_FIELD_ENV_MAP: dict[str, str] = {
    definition.field_name: definition.env_var for definition in SECRET_FIELD_DEFINITIONS
}
AUTH_SECRET_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "unset": (),
    "basic": ("QUALYS_USERNAME", "QUALYS_PASSWORD"),
    "token": ("QUALYS_ACCESS_TOKEN",),
}


class AuthConfigValidator:
    """Enforce auth-model and secret compatibility."""

    @staticmethod
    def supported_auth_models() -> tuple[str, ...]:
        return tuple(sorted(AUTH_SECRET_REQUIREMENTS))

    @classmethod
    def validate(
        cls,
        *,
        auth_model: str,
        username: str | None,
        password: str | None,
        access_token: str | None,
    ) -> None:
        required_env_keys = AUTH_SECRET_REQUIREMENTS.get(auth_model)
        if required_env_keys is None:
            supported = ", ".join(cls.supported_auth_models())
            raise ConfigurationValidationError(
                f"qualys.auth_model must be one of: {supported}"
            )

        values_by_env_key = {
            "QUALYS_USERNAME": username,
            "QUALYS_PASSWORD": password,
            "QUALYS_ACCESS_TOKEN": access_token,
        }
        missing = [key for key in required_env_keys if not values_by_env_key.get(key)]
        if missing:
            joined = ", ".join(missing)
            raise SecretConfigurationError(
                f"Missing required Qualys secrets for auth_model '{auth_model}': {joined}"
            )

        forbidden = [
            key
            for key, value in values_by_env_key.items()
            if value and key not in required_env_keys
        ]
        if not forbidden:
            return

        joined = ", ".join(forbidden)
        if auth_model == "unset":
            raise SecretConfigurationError(
                f"qualys.auth_model 'unset' does not allow live Qualys secrets: {joined}"
            )
        raise SecretConfigurationError(
            f"qualys.auth_model '{auth_model}' does not allow unrelated Qualys secrets: {joined}"
        )
