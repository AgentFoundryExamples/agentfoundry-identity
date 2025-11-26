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
"""Tests for the dependencies module."""

import pytest

from af_identity_service.config import Settings
from af_identity_service.dependencies import (
    DependencyContainer,
    InMemorySessionStore,
    PlaceholderGitHubDriver,
    get_dependencies,
    reset_dependencies,
)


@pytest.fixture
def valid_settings() -> Settings:
    """Create valid settings for testing."""
    return Settings(
        identity_jwt_secret="a" * 32,
        github_client_id="test-client-id",
        github_client_secret="test-client-secret",
    )


class TestInMemorySessionStore:
    """Tests for the InMemorySessionStore class."""

    @pytest.mark.asyncio
    async def test_set_and_get_session(self) -> None:
        """Test setting and getting a session."""
        store = InMemorySessionStore()
        session_data = {"user_id": "123", "email": "test@example.com"}

        await store.set("session-1", session_data)
        result = await store.get("session-1")

        assert result == session_data

    @pytest.mark.asyncio
    async def test_get_nonexistent_session_returns_none(self) -> None:
        """Test getting a nonexistent session returns None."""
        store = InMemorySessionStore()

        result = await store.get("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_delete_session(self) -> None:
        """Test deleting a session."""
        store = InMemorySessionStore()
        await store.set("session-1", {"user_id": "123"})

        await store.delete("session-1")
        result = await store.get("session-1")

        assert result is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_session_does_not_raise(self) -> None:
        """Test deleting a nonexistent session does not raise."""
        store = InMemorySessionStore()

        # Should not raise
        await store.delete("nonexistent")

    def test_health_check_returns_true(self) -> None:
        """Test health check returns True."""
        store = InMemorySessionStore()

        assert store.health_check() is True


class TestPlaceholderGitHubDriver:
    """Tests for the PlaceholderGitHubDriver class."""

    def test_initialization(self) -> None:
        """Test driver initialization."""
        driver = PlaceholderGitHubDriver(
            client_id="test-id",
            client_secret="test-secret",
            scopes=["read:user", "user:email"],
        )

        assert driver._client_id == "test-id"
        assert driver._client_secret == "test-secret"
        assert driver._scopes == ["read:user", "user:email"]

    @pytest.mark.asyncio
    async def test_exchange_code_raises_not_implemented(self) -> None:
        """Test exchange_code raises NotImplementedError."""
        driver = PlaceholderGitHubDriver(
            client_id="test-id",
            client_secret="test-secret",
            scopes=["read:user"],
        )

        with pytest.raises(NotImplementedError) as exc_info:
            await driver.exchange_code("auth-code")

        assert "PlaceholderGitHubDriver" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_user_raises_not_implemented(self) -> None:
        """Test get_user raises NotImplementedError."""
        driver = PlaceholderGitHubDriver(
            client_id="test-id",
            client_secret="test-secret",
            scopes=["read:user"],
        )

        with pytest.raises(NotImplementedError) as exc_info:
            await driver.get_user("access-token")

        assert "PlaceholderGitHubDriver" in str(exc_info.value)

    def test_health_check_returns_true(self) -> None:
        """Test health check returns True."""
        driver = PlaceholderGitHubDriver(
            client_id="test-id",
            client_secret="test-secret",
            scopes=["read:user"],
        )

        assert driver.health_check() is True


class TestDependencyContainer:
    """Tests for the DependencyContainer class."""

    def test_initialization_with_valid_settings(self, valid_settings: Settings) -> None:
        """Test container initialization with valid settings."""
        container = DependencyContainer(valid_settings)

        assert container.session_store is not None
        assert container.github_driver is not None

    def test_session_store_is_in_memory_store(self, valid_settings: Settings) -> None:
        """Test that session store is InMemorySessionStore."""
        container = DependencyContainer(valid_settings)

        assert isinstance(container.session_store, InMemorySessionStore)

    def test_github_driver_is_placeholder(self, valid_settings: Settings) -> None:
        """Test that GitHub driver is PlaceholderGitHubDriver."""
        container = DependencyContainer(valid_settings)

        assert isinstance(container.github_driver, PlaceholderGitHubDriver)

    def test_health_check_returns_healthy(self, valid_settings: Settings) -> None:
        """Test health check returns healthy status."""
        container = DependencyContainer(valid_settings)

        health = container.health_check()

        assert health["healthy"] is True
        assert health["session_store"] is True
        assert health["github_driver"] is True


class TestGetDependencies:
    """Tests for the get_dependencies function."""

    def test_get_dependencies_returns_container(self, valid_settings: Settings) -> None:
        """Test get_dependencies returns a container."""
        reset_dependencies()

        container = get_dependencies(valid_settings)

        assert isinstance(container, DependencyContainer)
        reset_dependencies()

    def test_get_dependencies_returns_same_instance(
        self, valid_settings: Settings
    ) -> None:
        """Test get_dependencies returns the same instance on subsequent calls."""
        reset_dependencies()

        container1 = get_dependencies(valid_settings)
        container2 = get_dependencies(valid_settings)

        assert container1 is container2
        reset_dependencies()


class TestDependencyContainerEnvironment:
    """Tests for the DependencyContainer environment methods."""

    def test_environment_property_returns_dev_by_default(self) -> None:
        """Test that environment property returns 'dev' by default."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
        )
        container = DependencyContainer(settings)

        assert container.environment == "dev"

    def test_environment_property_returns_prod_when_configured(self) -> None:
        """Test that environment property returns 'prod' when configured."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
            identity_environment="prod",
        )
        container = DependencyContainer(settings)

        assert container.environment == "prod"

    def test_is_dev_returns_true_in_dev_mode(self) -> None:
        """Test that is_dev returns True in dev mode."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
            identity_environment="dev",
        )
        container = DependencyContainer(settings)

        assert container.is_dev is True
        assert container.is_prod is False

    def test_is_prod_returns_true_in_prod_mode(self) -> None:
        """Test that is_prod returns True in prod mode."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
            identity_environment="prod",
        )
        container = DependencyContainer(settings)

        assert container.is_prod is True
        assert container.is_dev is False

    def test_use_stub_helpers_return_true_in_dev_mode(self) -> None:
        """Test that use_stub_* helpers return True in dev mode."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
            identity_environment="dev",
        )
        container = DependencyContainer(settings)

        assert container.use_stub_session_store() is True
        assert container.use_stub_user_repository() is True
        assert container.use_stub_token_store() is True
        assert container.use_stub_github_driver() is True

    def test_use_stub_helpers_return_false_in_prod_mode(self) -> None:
        """Test that use_stub_* helpers return False in prod mode."""
        settings = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
            identity_environment="prod",
        )
        container = DependencyContainer(settings)

        assert container.use_stub_session_store() is False
        assert container.use_stub_user_repository() is False
        assert container.use_stub_token_store() is False
        assert container.use_stub_github_driver() is False
