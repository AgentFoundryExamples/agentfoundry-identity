# SPDX-License-Identifier: GPL-3.0-only
"""Tests for configuration loading and validation."""

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from af_identity_service.config import Settings, get_settings


class TestSettingsValidation:
    """Tests for Settings validation."""

    def test_missing_jwt_secret_raises_error(self) -> None:
        """Test that missing JWT secret raises ValidationError."""
        env = {
            "GITHUB_CLIENT_ID": "test-client-id",
            "GITHUB_CLIENT_SECRET": "test-client-secret",
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            errors = exc_info.value.errors()
            assert any("identity_jwt_secret" in str(e["loc"]) for e in errors)

    def test_missing_github_client_id_raises_error(self) -> None:
        """Test that missing GitHub client ID raises ValidationError."""
        env = {
            "IDENTITY_JWT_SECRET": "a" * 32,
            "GITHUB_CLIENT_SECRET": "test-client-secret",
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            errors = exc_info.value.errors()
            assert any("github_client_id" in str(e["loc"]) for e in errors)

    def test_missing_github_client_secret_raises_error(self) -> None:
        """Test that missing GitHub client secret raises ValidationError."""
        env = {
            "IDENTITY_JWT_SECRET": "a" * 32,
            "GITHUB_CLIENT_ID": "test-client-id",
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            errors = exc_info.value.errors()
            assert any("github_client_secret" in str(e["loc"]) for e in errors)

    def test_jwt_secret_too_short_raises_error(self) -> None:
        """Test that JWT secret shorter than 32 chars raises ValidationError."""
        env = {
            "IDENTITY_JWT_SECRET": "short",
            "GITHUB_CLIENT_ID": "test-client-id",
            "GITHUB_CLIENT_SECRET": "test-client-secret",
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            errors = exc_info.value.errors()
            assert any("identity_jwt_secret" in str(e["loc"]) for e in errors)

    def test_empty_jwt_secret_raises_error(self) -> None:
        """Test that empty JWT secret raises ValidationError."""
        env = {
            "IDENTITY_JWT_SECRET": "",
            "GITHUB_CLIENT_ID": "test-client-id",
            "GITHUB_CLIENT_SECRET": "test-client-secret",
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            errors = exc_info.value.errors()
            assert any("identity_jwt_secret" in str(e["loc"]) for e in errors)

    def test_valid_minimal_config(self) -> None:
        """Test that valid minimal configuration loads successfully."""
        env = {
            "IDENTITY_JWT_SECRET": "a" * 32,
            "GITHUB_CLIENT_ID": "test-client-id",
            "GITHUB_CLIENT_SECRET": "test-client-secret",
        }
        with patch.dict(os.environ, env, clear=True):
            settings = Settings()

            assert settings.identity_jwt_secret == "a" * 32
            assert settings.github_client_id == "test-client-id"
            assert settings.github_client_secret == "test-client-secret"
            assert settings.access_token_lifetime_seconds == 3600
            assert settings.refresh_token_lifetime_seconds == 86400
            assert settings.admin_mode is False

    def test_custom_token_lifetimes(self) -> None:
        """Test that custom token lifetimes are loaded correctly."""
        env = {
            "IDENTITY_JWT_SECRET": "a" * 32,
            "GITHUB_CLIENT_ID": "test-client-id",
            "GITHUB_CLIENT_SECRET": "test-client-secret",
            "ACCESS_TOKEN_LIFETIME_SECONDS": "7200",
            "REFRESH_TOKEN_LIFETIME_SECONDS": "172800",
        }
        with patch.dict(os.environ, env, clear=True):
            settings = Settings()

            assert settings.access_token_lifetime_seconds == 7200
            assert settings.refresh_token_lifetime_seconds == 172800

    def test_invalid_access_token_lifetime_non_integer(self) -> None:
        """Test that non-integer access token lifetime raises ValidationError."""
        env = {
            "IDENTITY_JWT_SECRET": "a" * 32,
            "GITHUB_CLIENT_ID": "test-client-id",
            "GITHUB_CLIENT_SECRET": "test-client-secret",
            "ACCESS_TOKEN_LIFETIME_SECONDS": "not-a-number",
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            errors = exc_info.value.errors()
            assert any("access_token_lifetime_seconds" in str(e["loc"]) for e in errors)

    def test_invalid_refresh_token_lifetime_non_integer(self) -> None:
        """Test that non-integer refresh token lifetime raises ValidationError."""
        env = {
            "IDENTITY_JWT_SECRET": "a" * 32,
            "GITHUB_CLIENT_ID": "test-client-id",
            "GITHUB_CLIENT_SECRET": "test-client-secret",
            "REFRESH_TOKEN_LIFETIME_SECONDS": "invalid",
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            errors = exc_info.value.errors()
            assert any("refresh_token_lifetime_seconds" in str(e["loc"]) for e in errors)

    def test_access_token_lifetime_too_low(self) -> None:
        """Test that access token lifetime below minimum raises ValidationError."""
        env = {
            "IDENTITY_JWT_SECRET": "a" * 32,
            "GITHUB_CLIENT_ID": "test-client-id",
            "GITHUB_CLIENT_SECRET": "test-client-secret",
            "ACCESS_TOKEN_LIFETIME_SECONDS": "30",  # Below 60 minimum
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            errors = exc_info.value.errors()
            assert any("access_token_lifetime_seconds" in str(e["loc"]) for e in errors)

    def test_access_token_lifetime_too_high(self) -> None:
        """Test that access token lifetime above maximum raises ValidationError."""
        env = {
            "IDENTITY_JWT_SECRET": "a" * 32,
            "GITHUB_CLIENT_ID": "test-client-id",
            "GITHUB_CLIENT_SECRET": "test-client-secret",
            "ACCESS_TOKEN_LIFETIME_SECONDS": "100000",  # Above 86400 maximum
        }
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                Settings()

            errors = exc_info.value.errors()
            assert any("access_token_lifetime_seconds" in str(e["loc"]) for e in errors)

    def test_admin_mode_enabled(self) -> None:
        """Test that admin mode can be enabled via environment."""
        env = {
            "IDENTITY_JWT_SECRET": "a" * 32,
            "GITHUB_CLIENT_ID": "test-client-id",
            "GITHUB_CLIENT_SECRET": "test-client-secret",
            "ADMIN_MODE": "true",
        }
        with patch.dict(os.environ, env, clear=True):
            settings = Settings()

            assert settings.admin_mode is True


class TestGetSettings:
    """Tests for get_settings function."""

    def test_get_settings_returns_settings_instance(self) -> None:
        """Test that get_settings returns a Settings instance."""
        env = {
            "IDENTITY_JWT_SECRET": "a" * 32,
            "GITHUB_CLIENT_ID": "test-client-id",
            "GITHUB_CLIENT_SECRET": "test-client-secret",
        }
        with patch.dict(os.environ, env, clear=True):
            settings = get_settings()

            assert isinstance(settings, Settings)

    def test_get_settings_raises_on_missing_config(self) -> None:
        """Test that get_settings raises ValidationError on missing config."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValidationError):
                get_settings()
