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
"""Agent Foundry Identity Stores.

This module exports all store abstractions and in-memory implementations
for the identity service.
"""

from af_identity_service.stores.github_token_store import (
    GitHubTokenStore,
    GitHubTokenStoreError,
    InMemoryGitHubTokenStore,
    RefreshTokenNotFoundError,
)
from af_identity_service.stores.postgres_github_token_store import (
    DatabaseOperationError,
    PostgresGitHubTokenStore,
)
from af_identity_service.stores.redis_session_store import (
    RedisConnectionFailedError,
    RedisSessionStore,
    RedisSessionStoreError,
)
from af_identity_service.stores.session_store import InMemorySessionStore, SessionStore
from af_identity_service.stores.user_store import AFUserRepository, InMemoryUserRepository

__all__ = [
    "AFUserRepository",
    "InMemoryUserRepository",
    "SessionStore",
    "InMemorySessionStore",
    "RedisSessionStore",
    "RedisSessionStoreError",
    "RedisConnectionFailedError",
    "GitHubTokenStore",
    "GitHubTokenStoreError",
    "InMemoryGitHubTokenStore",
    "RefreshTokenNotFoundError",
    "PostgresGitHubTokenStore",
    "DatabaseOperationError",
]
