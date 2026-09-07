"""Project-specific exception boundary."""

from __future__ import annotations


class ConfigurationError(ValueError):
    """Raised when runtime configuration cannot be loaded safely."""


class ConfigurationFileError(ConfigurationError):
    """Raised when config source files cannot be parsed or validated safely."""


class ConfigurationValidationError(ConfigurationError):
    """Raised when resolved config values are invalid or incompatible."""


class SecretConfigurationError(ConfigurationValidationError):
    """Raised when secret material is missing or invalid for the selected mode."""


class QualysClientError(RuntimeError):
    """Raised when the thin Qualys transport client cannot complete a request safely."""


class QualysHTTPError(QualysClientError):
    """Raised when the Qualys API returns a non-200 HTTP response."""

    def __init__(self, *, status_code: int, reason: str, method: str, url: str) -> None:
        self.status_code = status_code
        self.reason = reason
        self.method = method
        self.url = url
        super().__init__(
            f"Qualys API request failed with status {status_code} for {method} {url}: {reason}"
        )


class QualysAuthenticationError(QualysHTTPError):
    """Raised when the Qualys API rejects the configured credentials."""


class QualysTransportError(QualysClientError):
    """Raised when the client cannot reach the Qualys API endpoint."""


class QualysResponseError(QualysClientError):
    """Raised when the Qualys API response cannot be parsed into the expected contract."""


class SourceInventoryError(ValueError):
    """Raised when the local source inventory cannot be loaded safely."""


class SourceInventoryStructureError(SourceInventoryError):
    """Raised when the source inventory file structure is invalid for this MVP slice."""


class ReportExportError(RuntimeError):
    """Raised when a comparison report cannot be written safely."""


class RunComparisonError(RuntimeError):
    """Raised when run-to-run comparison inputs are invalid or incompatible."""


class InvestigationTriageError(RuntimeError):
    """Raised when local investigate triage cannot complete safely."""


class AssetGroupMapCoverageError(RuntimeError):
    """Raised when local Qualys asset-group MAP coverage enrichment fails."""
