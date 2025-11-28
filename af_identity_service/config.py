# ============================================================
# SPDX-License-Identifier: GPL-3.0-or-later
# This program was generated as part of the AgentFoundry project.
# Copyright (C) 2025  John Brosnihan
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ============================================================
"""Configuration module for the Identity Service.

This module provides Pydantic-based settings validation for all environment
variables required by the Identity Service. It fails fast when required
environment variables are missing.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Identity Service configuration settings.

    All required environment variables must be set before the service boots.
    The service will fail fast with descriptive errors if any required
    variable is missing.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Environment switch - controls which backends are instantiated
    identity_environment: Literal["dev", "prod"] = Field(
        default="dev",
        description="Environment mode: 'dev' uses in-memory stubs, 'prod' uses real backends.",
    )

    # Required secrets - service will not start without these
    identity_jwt_secret: str = Field(
        ...,
        min_length=32,
        description="Secret key for signing JWT tokens. Must be at least 32 characters.",
    )
    github_client_id: str = Field(
        ...,
        min_length=1,
        description="GitHub OAuth App client ID.",
    )
    github_client_secret: str = Field(
        ...,
        min_length=1,
        description="GitHub OAuth App client secret.",
    )

    # Postgres configuration (required in prod, optional in dev)
    postgres_host: str | None = Field(
        default=None,
        description="Postgres host address.",
    )
    postgres_port: int = Field(
        default=5432,
        ge=1,
        le=65535,
        description="Postgres port number.",
    )
    postgres_db: str | None = Field(
        default=None,
        description="Postgres database name.",
    )
    postgres_user: str | None = Field(
        default=None,
        description="Postgres username.",
    )
    postgres_password: SecretStr | None = Field(
        default=None,
        description="Postgres password (sensitive).",
    )
    google_cloud_sql_instance: str | None = Field(
        default=None,
        description="Google Cloud SQL instance connection name (e.g., project:region:instance).",
    )

    # Redis configuration (required in prod, optional in dev)
    redis_host: str | None = Field(
        default=None,
        description="Redis host address.",
    )
    redis_port: int = Field(
        default=6379,
        ge=1,
        le=65535,
        description="Redis port number.",
    )
    redis_db: int = Field(
        default=0,
        ge=0,
        le=15,
        description="Redis database number.",
    )
    redis_tls_enabled: bool = Field(
        default=False,
        description="Enable TLS for Redis connections.",
    )

    # Token encryption configuration (required in prod, optional in dev)
    github_token_enc_key: SecretStr | None = Field(
        default=None,
        description=(
            "256-bit AES key for encrypting GitHub tokens (hex or base64 encoded). "
            "Required in production. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        ),
    )

    # OAuth configuration
    oauth_scopes: str = Field(
        default="read:user,user:email",
        min_length=1,
        description="Comma-separated list of GitHub OAuth scopes to request.",
    )

    # JWT and session configuration
    jwt_expiry_seconds: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="JWT token expiry time in seconds. Default: 1 hour.",
    )
    session_expiry_seconds: int = Field(
        default=86400,
        ge=300,
        le=604800,
        description="Session expiry time in seconds. Default: 24 hours.",
    )

    # Admin configuration
    admin_github_ids: str = Field(
        default="",
        description="Comma-separated list of GitHub user IDs with admin access.",
    )
    admin_tools_enabled: bool = Field(
        default=False,
        description="Enable admin debugging endpoints (session listing).",
    )

    # Logging configuration
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level for the service.",
    )
    log_format: Literal["json", "console"] = Field(
        default="json",
        description="Log output format. Use 'json' for production, 'console' for development.",
    )

    # Service configuration
    service_host: str = Field(
        default="0.0.0.0",
        description="Host to bind the service to.",
    )
    service_port: int = Field(
        default=8080,
        ge=1,
        le=65535,
        description="Port to bind the service to.",
    )

    @field_validator("identity_jwt_secret")
    @classmethod
    def validate_jwt_secret_strength(cls, v: str) -> str:
        """Validate that the JWT secret has sufficient entropy."""
        if len(v) < 32:
            raise ValueError("IDENTITY_JWT_SECRET must be at least 32 characters long")
        return v

    @field_validator("oauth_scopes")
    @classmethod
    def validate_oauth_scopes(cls, v: str) -> str:
        """Validate that OAuth scopes are not empty."""
        scopes = [s.strip() for s in v.split(",") if s.strip()]
        if not scopes:
            raise ValueError(
                "OAUTH_SCOPES must contain at least one valid scope. "
                "Example: 'read:user,user:email'"
            )
        return v

    @property
    def oauth_scopes_list(self) -> list[str]:
        """Return OAuth scopes as a list."""
        return [s.strip() for s in self.oauth_scopes.split(",") if s.strip()]

    @property
    def admin_github_ids_list(self) -> list[str]:
        """Return admin GitHub IDs as a list."""
        if not self.admin_github_ids:
            return []
        return [s.strip() for s in self.admin_github_ids.split(",") if s.strip()]

    @property
    def is_prod(self) -> bool:
        """Check if running in production mode."""
        return self.identity_environment == "prod"

    @property
    def is_dev(self) -> bool:
        """Check if running in development mode."""
        return self.identity_environment == "dev"

    def get_redacted_config_dict(self) -> dict[str, str]:
        """Return a dictionary of configuration for logging with secrets redacted.

        Returns:
            A dictionary with redacted sensitive values.
        """
        return {
            "identity_environment": self.identity_environment,
            "identity_jwt_secret": "(set)" if self.identity_jwt_secret else "(not set)",
            "github_client_id": "(set)" if self.github_client_id else "(not set)",
            "github_client_secret": "(set)" if self.github_client_secret else "(not set)",
            "postgres_host": self.postgres_host or "(not set)",
            "postgres_port": str(self.postgres_port),
            "postgres_db": self.postgres_db or "(not set)",
            "postgres_user": self.postgres_user or "(not set)",
            "postgres_password": "(set)" if self.postgres_password else "(not set)",
            "google_cloud_sql_instance": self.google_cloud_sql_instance or "(not set)",
            "redis_host": self.redis_host or "(not set)",
            "redis_port": str(self.redis_port),
            "redis_db": str(self.redis_db),
            "redis_tls_enabled": str(self.redis_tls_enabled),
            "github_token_enc_key": "(set)" if self.github_token_enc_key else "(not set)",
            "log_level": self.log_level,
            "log_format": self.log_format,
            "service_host": self.service_host,
            "service_port": str(self.service_port),
        }


class ConfigurationError(Exception):
    """Raised when required configuration is missing or invalid."""

    pass


def validate_prod_settings(settings: Settings) -> None:
    """Validate that required production settings are present.

    This function validates that when IDENTITY_ENVIRONMENT is 'prod',
    all required backend configuration is provided.

    For Cloud SQL connections:
    - GOOGLE_CLOUD_SQL_INSTANCE is required
    - POSTGRES_DB is always required
    - POSTGRES_USER and POSTGRES_PASSWORD are required for standard auth
      (not required when using Cloud SQL IAM database authentication)

    For direct Postgres connections:
    - POSTGRES_HOST, POSTGRES_DB, POSTGRES_USER, and POSTGRES_PASSWORD are all required

    Token encryption:
    - GITHUB_TOKEN_ENC_KEY is required for encrypting GitHub tokens at rest

    Args:
        settings: The settings instance to validate.

    Raises:
        ConfigurationError: If required production settings are missing.
    """
    if not settings.is_prod:
        return

    missing = []

    # Check Postgres configuration - either Cloud SQL or explicit host required
    if not settings.google_cloud_sql_instance and not settings.postgres_host:
        missing.append(
            "POSTGRES_HOST or GOOGLE_CLOUD_SQL_INSTANCE (at least one required in prod)"
        )

    # For direct Postgres connections, require all credentials
    if settings.postgres_host:
        if not settings.postgres_db:
            missing.append("POSTGRES_DB")
        if not settings.postgres_user:
            missing.append("POSTGRES_USER")
        if not settings.postgres_password:
            missing.append("POSTGRES_PASSWORD")

    # For Cloud SQL connections, POSTGRES_DB is always required
    # User/password may be optional with IAM auth, but DB name is always needed
    if settings.google_cloud_sql_instance and not settings.postgres_host:
        if not settings.postgres_db:
            missing.append("POSTGRES_DB (required even with Cloud SQL)")

    # Check Redis configuration
    if not settings.redis_host:
        missing.append("REDIS_HOST")

    # Check token encryption key
    if not settings.github_token_enc_key:
        missing.append("GITHUB_TOKEN_ENC_KEY (required for token encryption)")

    if missing:
        raise ConfigurationError(
            f"Production mode requires the following environment variables: {', '.join(missing)}. "
            "Either set these values or use IDENTITY_ENVIRONMENT=dev for development mode."
        )


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance.

    This function is cached to ensure settings are only loaded once.
    It will raise a ConfigurationError with a descriptive message if
    required environment variables are missing.

    Returns:
        Settings: The validated settings instance.

    Raises:
        ConfigurationError: If required environment variables are missing or invalid.
    """
    try:
        settings = Settings()
        # Validate prod-specific requirements
        validate_prod_settings(settings)
        return settings
    except ConfigurationError:
        # ConfigurationError from validate_prod_settings propagates as-is
        raise
    except Exception as e:
        # Provide a clear error message for missing configuration
        error_msg = str(e)
        if "identity_environment" in error_msg.lower():
            raise ConfigurationError(
                "IDENTITY_ENVIRONMENT must be either 'dev' or 'prod'. "
                "Use 'dev' for local development with in-memory stores, "
                "or 'prod' for production with real backends."
            ) from e
        if "identity_jwt_secret" in error_msg.lower():
            raise ConfigurationError(
                "IDENTITY_JWT_SECRET environment variable is required and must be at least "
                "32 characters long. This secret is used to sign JWT tokens."
            ) from e
        if "github_client_id" in error_msg.lower():
            raise ConfigurationError(
                "GITHUB_CLIENT_ID environment variable is required. "
                "Create a GitHub OAuth App at https://github.com/settings/developers"
            ) from e
        if "github_client_secret" in error_msg.lower():
            raise ConfigurationError(
                "GITHUB_CLIENT_SECRET environment variable is required. "
                "This is the client secret from your GitHub OAuth App."
            ) from e
        if "oauth_scopes" in error_msg.lower():
            raise ConfigurationError(
                "OAUTH_SCOPES environment variable must contain at least one valid scope. "
                "Example: 'read:user,user:email'"
            ) from e
        raise ConfigurationError(f"Configuration error: {error_msg}") from e
