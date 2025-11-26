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
"""Tests for GitHub OAuth driver."""

from datetime import datetime, timezone

import pytest

from af_identity_service.github.driver import StubGitHubOAuthDriver


class TestStubGitHubOAuthDriver:
    """Tests for StubGitHubOAuthDriver."""

    @pytest.fixture
    def driver(self) -> StubGitHubOAuthDriver:
        """Create a fresh driver for each test."""
        return StubGitHubOAuthDriver(client_id="test-client-id")

    @pytest.mark.asyncio
    async def test_exchange_code_for_tokens(
        self, driver: StubGitHubOAuthDriver
    ) -> None:
        """Test exchanging code for tokens."""
        result = await driver.exchange_code_for_tokens("test_auth_code")

        assert result.access_token.startswith("gho_stub_")
        assert result.refresh_token is not None
        assert result.refresh_token.startswith("ghr_stub_")
        assert result.access_token_expires_at > datetime.now(timezone.utc)
        assert result.refresh_token_expires_at is not None
        assert result.refresh_token_expires_at > result.access_token_expires_at

    @pytest.mark.asyncio
    async def test_refresh_access_token(
        self, driver: StubGitHubOAuthDriver
    ) -> None:
        """Test refreshing access token."""
        result = await driver.refresh_access_token("ghr_old_refresh_token")

        assert result.access_token.startswith("gho_stub_refreshed_")
        assert result.refresh_token is not None
        assert result.refresh_token.startswith("ghr_stub_renewed_")
        assert result.access_token_expires_at > datetime.now(timezone.utc)

    @pytest.mark.asyncio
    async def test_get_user_profile(self, driver: StubGitHubOAuthDriver) -> None:
        """Test getting user profile."""
        profile = await driver.get_user_profile("gho_test_token")

        assert profile.github_user_id > 0
        assert profile.login.startswith("stub_user_")
        assert profile.avatar_url is not None
        assert "avatars.githubusercontent.com" in profile.avatar_url

    @pytest.mark.asyncio
    async def test_get_user_profile_consistent(
        self, driver: StubGitHubOAuthDriver
    ) -> None:
        """Test that same token returns consistent profile."""
        profile1 = await driver.get_user_profile("same_token")
        profile2 = await driver.get_user_profile("same_token")

        assert profile1.github_user_id == profile2.github_user_id
        assert profile1.login == profile2.login

    @pytest.mark.asyncio
    async def test_different_tokens_different_profiles(
        self, driver: StubGitHubOAuthDriver
    ) -> None:
        """Test that different tokens return different profiles."""
        profile1 = await driver.get_user_profile("token_1")
        profile2 = await driver.get_user_profile("token_2")

        # Different tokens should produce different user IDs
        # (though hash collisions are theoretically possible)
        assert profile1.github_user_id != profile2.github_user_id
