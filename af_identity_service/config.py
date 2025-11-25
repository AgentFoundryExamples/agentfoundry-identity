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

from pydantic import Field, field_validator
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


class ConfigurationError(Exception):
    """Raised when required configuration is missing or invalid."""

    pass


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
        return Settings()
    except Exception as e:
        # Provide a clear error message for missing configuration
        error_msg = str(e)
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
