# SPDX-License-Identifier: GPL-3.0-only
"""Configuration module using Pydantic settings for environment-driven configuration."""

from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Required secrets:
        - IDENTITY_JWT_SECRET: Secret key for JWT token signing (required)
        - GITHUB_CLIENT_ID: GitHub OAuth app client ID (required)
        - GITHUB_CLIENT_SECRET: GitHub OAuth app client secret (required)

    Optional configuration:
        - ACCESS_TOKEN_LIFETIME_SECONDS: JWT access token lifetime (default: 3600)
        - REFRESH_TOKEN_LIFETIME_SECONDS: JWT refresh token lifetime (default: 86400)
        - ADMIN_MODE: Enable admin mode for development (default: false)
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # Required secrets
    identity_jwt_secret: str = Field(
        ...,
        min_length=32,
        description="Secret key for JWT token signing. Must be at least 32 characters.",
    )
    github_client_id: str = Field(
        ...,
        min_length=1,
        description="GitHub OAuth application client ID.",
    )
    github_client_secret: str = Field(
        ...,
        min_length=1,
        description="GitHub OAuth application client secret.",
    )

    # Token lifetimes
    access_token_lifetime_seconds: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="Access token lifetime in seconds (1 minute to 24 hours).",
    )
    refresh_token_lifetime_seconds: int = Field(
        default=86400,
        ge=3600,
        le=2592000,
        description="Refresh token lifetime in seconds (1 hour to 30 days).",
    )

    # Optional configuration
    admin_mode: bool = Field(
        default=False,
        description="Enable admin mode for development purposes.",
    )

    @field_validator("access_token_lifetime_seconds", "refresh_token_lifetime_seconds", mode="before")
    @classmethod
    def validate_integer(cls, v: Optional[str]) -> int:
        """Validate that lifetime values are valid integers."""
        if v is None:
            return v
        if isinstance(v, int):
            return v
        try:
            return int(v)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid integer value: {v}") from e


def get_settings() -> Settings:
    """Create and return application settings.

    Raises:
        ValidationError: If required environment variables are missing or invalid.
    """
    return Settings()
