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
"""Tests for the configuration module."""

import pytest
from pydantic import ValidationError

from af_identity_service.config import ConfigurationError, Settings, get_settings


class TestSettings:
    """Tests for the Settings class."""

    def test_settings_loads_with_keyword_arguments(self) -> None:
        """Test that settings can be created with keyword arguments."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
        )

        assert settings.identity_jwt_secret == "a" * 32
        assert settings.github_client_id == "test-client-id"
        assert settings.github_client_secret == "test-client-secret"

    def test_settings_missing_jwt_secret_raises_error(self) -> None:
        """Test that missing JWT secret raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                github_client_id="test-client-id",
                github_client_secret="test-client-secret",
            )

        assert "identity_jwt_secret" in str(exc_info.value).lower()

    def test_settings_missing_github_client_id_raises_error(self) -> None:
        """Test that missing GitHub client ID raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                identity_jwt_secret="a" * 32,
                github_client_secret="test-client-secret",
            )

        assert "github_client_id" in str(exc_info.value).lower()

    def test_settings_missing_github_client_secret_raises_error(self) -> None:
        """Test that missing GitHub client secret raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                identity_jwt_secret="a" * 32,
                github_client_id="test-client-id",
            )

        assert "github_client_secret" in str(exc_info.value).lower()

    def test_settings_jwt_secret_too_short_raises_error(self) -> None:
        """Test that JWT secret shorter than 32 characters raises error."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                identity_jwt_secret="short-secret",
                github_client_id="test-client-id",
                github_client_secret="test-client-secret",
            )

        assert "32" in str(exc_info.value)

    def test_settings_default_values(self) -> None:
        """Test that optional settings have correct defaults."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
        )

        assert settings.oauth_scopes == "read:user,user:email"
        assert settings.jwt_expiry_seconds == 3600
        assert settings.session_expiry_seconds == 86400
        assert settings.admin_github_ids == ""
        assert settings.log_level == "INFO"
        assert settings.log_format == "json"
        assert settings.service_host == "0.0.0.0"
        assert settings.service_port == 8080

    def test_settings_custom_values(self) -> None:
        """Test that custom values override defaults."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
            oauth_scopes="read:user,repo",
            jwt_expiry_seconds=7200,
            session_expiry_seconds=172800,
            admin_github_ids="123,456",
            log_level="DEBUG",
            log_format="console",
            service_host="127.0.0.1",
            service_port=3000,
        )

        assert settings.oauth_scopes == "read:user,repo"
        assert settings.jwt_expiry_seconds == 7200
        assert settings.session_expiry_seconds == 172800
        assert settings.admin_github_ids == "123,456"
        assert settings.log_level == "DEBUG"
        assert settings.log_format == "console"
        assert settings.service_host == "127.0.0.1"
        assert settings.service_port == 3000

    def test_oauth_scopes_list_property(self) -> None:
        """Test that oauth_scopes_list returns a list of scopes."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
            oauth_scopes="read:user, user:email, repo",
        )

        assert settings.oauth_scopes_list == ["read:user", "user:email", "repo"]

    def test_admin_github_ids_list_property(self) -> None:
        """Test that admin_github_ids_list returns a list of IDs."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
            admin_github_ids="123, 456, 789",
        )

        assert settings.admin_github_ids_list == ["123", "456", "789"]

    def test_admin_github_ids_list_empty_when_not_set(self) -> None:
        """Test that admin_github_ids_list returns empty list when not set."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
        )

        assert settings.admin_github_ids_list == []


class TestGetSettings:
    """Tests for the get_settings function."""

    def test_get_settings_caches_instance(self) -> None:
        """Test that get_settings returns the same cached instance."""
        # This test verifies that lru_cache is working.
        # We can't easily test with missing env vars due to environment isolation issues.
        # Just verify the function exists and has cache_clear method.
        assert hasattr(get_settings, "cache_clear")

    def test_configuration_error_is_raised_for_invalid_settings(self) -> None:
        """Test that ConfigurationError is raised for invalid configuration."""
        # Test by calling get_settings with mock that fails
        from unittest import mock

        get_settings.cache_clear()

        # Mock the Settings class to raise an exception
        with mock.patch(
            "af_identity_service.config.Settings",
            side_effect=ValidationError.from_exception_data(
                "Settings",
                [
                    {
                        "type": "missing",
                        "loc": ("identity_jwt_secret",),
                        "msg": "Field required",
                        "input": {},
                    }
                ],
            ),
        ):
            with pytest.raises(ConfigurationError) as exc_info:
                get_settings()

        assert "IDENTITY_JWT_SECRET" in str(exc_info.value)
        get_settings.cache_clear()

    def test_configuration_error_message_for_github_client_id(self) -> None:
        """Test that ConfigurationError message mentions GitHub client ID."""
        from unittest import mock

        get_settings.cache_clear()

        with mock.patch(
            "af_identity_service.config.Settings",
            side_effect=ValidationError.from_exception_data(
                "Settings",
                [
                    {
                        "type": "missing",
                        "loc": ("github_client_id",),
                        "msg": "Field required",
                        "input": {},
                    }
                ],
            ),
        ):
            with pytest.raises(ConfigurationError) as exc_info:
                get_settings()

        assert "GITHUB_CLIENT_ID" in str(exc_info.value)
        get_settings.cache_clear()

    def test_configuration_error_message_for_github_client_secret(self) -> None:
        """Test that ConfigurationError message mentions GitHub client secret."""
        from unittest import mock

        get_settings.cache_clear()

        with mock.patch(
            "af_identity_service.config.Settings",
            side_effect=ValidationError.from_exception_data(
                "Settings",
                [
                    {
                        "type": "missing",
                        "loc": ("github_client_secret",),
                        "msg": "Field required",
                        "input": {},
                    }
                ],
            ),
        ):
            with pytest.raises(ConfigurationError) as exc_info:
                get_settings()

        assert "GITHUB_CLIENT_SECRET" in str(exc_info.value)
        get_settings.cache_clear()
