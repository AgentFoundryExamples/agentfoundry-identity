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
"""OAuth service for GitHub authentication flow.

This module provides the OAuthService class that orchestrates the GitHub
OAuth flow including state management, user upsert, session creation,
and JWT minting.
"""

import secrets
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import structlog

from af_identity_service.github.driver import GitHubOAuthDriver, GitHubOAuthDriverError
from af_identity_service.models.session import Session
from af_identity_service.models.user import AFUser
from af_identity_service.security.jwt import mint_af_jwt
from af_identity_service.stores.github_token_store import GitHubTokenStore
from af_identity_service.stores.session_store import SessionStore
from af_identity_service.stores.user_store import AFUserRepository

logger = structlog.get_logger(__name__)

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"


class OAuthServiceError(Exception):
    """Base exception for OAuth service errors."""

    pass


class InvalidStateError(OAuthServiceError):
    """Raised when OAuth state validation fails."""

    pass


class GitHubDriverError(OAuthServiceError):
    """Raised when GitHub driver operations fail."""

    pass


class StateStore(ABC):
    """Abstract base class for OAuth state storage.

    Implementations should store state tokens for a short duration
    to validate OAuth callbacks and prevent CSRF attacks.
    """

    @abstractmethod
    async def store(self, state: str, redirect_uri: str, ttl_seconds: int = 600) -> None:
        """Store a state token with its associated redirect URI.

        Args:
            state: The state token to store.
            redirect_uri: The redirect URI associated with this state.
            ttl_seconds: Time to live in seconds (default 10 minutes).
        """
        pass

    @abstractmethod
    async def validate_and_consume(self, state: str) -> str | None:
        """Validate and consume a state token.

        Args:
            state: The state token to validate.

        Returns:
            The redirect_uri if valid, None if invalid or expired.
        """
        pass


@dataclass
class _StateEntry:
    """Internal representation of a stored state."""

    redirect_uri: str
    expires_at: datetime


class InMemoryStateStore(StateStore):
    """In-memory implementation of StateStore.

    This implementation is suitable for development and single-instance
    deployments only. For production with multiple instances, use a
    distributed store like Redis.

    The store automatically expires stale entries on access.
    """

    def __init__(self) -> None:
        """Initialize the in-memory state store."""
        self._states: dict[str, _StateEntry] = {}
        self._lock = threading.Lock()
        logger.info("Initialized in-memory state store (dev-only)")

    async def store(self, state: str, redirect_uri: str, ttl_seconds: int = 600) -> None:
        """Store a state token with its associated redirect URI."""
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        with self._lock:
            self._states[state] = _StateEntry(redirect_uri=redirect_uri, expires_at=expires_at)
        logger.debug("Stored OAuth state", state_prefix=state[:8])

    async def validate_and_consume(self, state: str) -> str | None:
        """Validate and consume a state token."""
        now = datetime.now(timezone.utc)
        state_prefix = state[:8] if len(state) >= 8 else state
        with self._lock:
            entry = self._states.pop(state, None)
            if entry is None:
                logger.warning("State not found", state_prefix=state_prefix)
                return None
            if now >= entry.expires_at:
                logger.warning("State expired", state_prefix=state_prefix)
                return None
            logger.debug("State validated and consumed", state_prefix=state_prefix)
            return entry.redirect_uri


@dataclass
class OAuthStartResult:
    """Result of starting OAuth flow."""

    authorization_url: str
    state: str


@dataclass
class OAuthCallbackResult:
    """Result of completing OAuth callback."""

    af_token: str
    user: AFUser
    session: Session
    github_token_available: bool


class OAuthService:
    """Service for orchestrating GitHub OAuth flow.

    This service handles the complete OAuth lifecycle:
    1. Generating authorization URLs with state tokens
    2. Validating callbacks and exchanging codes for tokens
    3. Upserting users and storing tokens
    4. Creating sessions and minting JWTs

    The service ensures GitHub tokens are never exposed to clients
    and handles errors gracefully with appropriate logging.
    """

    def __init__(
        self,
        github_driver: GitHubOAuthDriver,
        user_repository: AFUserRepository,
        session_store: SessionStore,
        token_store: GitHubTokenStore,
        state_store: StateStore,
        client_id: str,
        scopes: list[str],
        jwt_secret: str,
        jwt_expiry_seconds: int,
        session_expiry_seconds: int,
    ) -> None:
        """Initialize the OAuth service.

        Args:
            github_driver: Driver for GitHub OAuth operations.
            user_repository: Repository for user persistence.
            session_store: Store for session management.
            token_store: Store for GitHub token persistence.
            state_store: Store for OAuth state management.
            client_id: GitHub OAuth client ID.
            scopes: OAuth scopes to request.
            jwt_secret: Secret for JWT signing.
            jwt_expiry_seconds: JWT token lifetime in seconds.
            session_expiry_seconds: Session lifetime in seconds.
        """
        self._github_driver = github_driver
        self._user_repository = user_repository
        self._session_store = session_store
        self._token_store = token_store
        self._state_store = state_store
        self._client_id = client_id
        self._scopes = scopes
        self._jwt_secret = jwt_secret
        self._jwt_expiry_seconds = jwt_expiry_seconds
        self._session_expiry_seconds = session_expiry_seconds

    async def start_oauth(self, redirect_uri: str) -> OAuthStartResult:
        """Start the GitHub OAuth flow.

        Generates a secure state token and builds the GitHub authorization URL.

        Args:
            redirect_uri: The URI to redirect to after GitHub authorization.

        Returns:
            OAuthStartResult with authorization URL and state token.
        """
        # Generate secure state token
        state = secrets.token_urlsafe(32)

        # Store state for later validation
        await self._state_store.store(state, redirect_uri)

        # Build authorization URL
        params = {
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self._scopes),
            "state": state,
        }
        authorization_url = f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}"

        logger.info(
            "auth.github.start",
            state_prefix=state[:8],
            redirect_uri=redirect_uri,
        )

        return OAuthStartResult(authorization_url=authorization_url, state=state)

    async def handle_callback(
        self, code: str, state: str
    ) -> OAuthCallbackResult:
        """Handle GitHub OAuth callback.

        Validates state, exchanges code for tokens, upserts user,
        stores tokens, creates session, and mints JWT.

        Args:
            code: The authorization code from GitHub.
            state: The state token from the callback.

        Returns:
            OAuthCallbackResult with AF token and user info.

        Raises:
            InvalidStateError: If state validation fails.
            GitHubDriverError: If GitHub operations fail.
        """
        # Validate state
        redirect_uri = await self._state_store.validate_and_consume(state)
        if redirect_uri is None:
            logger.warning(
                "auth.github.callback.failure",
                reason="invalid_state",
                state_prefix=state[:8] if len(state) >= 8 else state,
            )
            raise InvalidStateError("Invalid or expired state token")

        # Exchange code for tokens
        try:
            tokens = await self._github_driver.exchange_code_for_tokens(code)
        except GitHubOAuthDriverError as e:
            logger.error(
                "auth.github.callback.failure",
                reason="token_exchange_failed",
                error=str(e),
            )
            raise GitHubDriverError(f"Failed to exchange code: {e}") from e

        # Get user profile
        try:
            github_identity = await self._github_driver.get_user_profile(tokens.access_token)
        except GitHubOAuthDriverError as e:
            logger.error(
                "auth.github.callback.failure",
                reason="profile_fetch_failed",
                error=str(e),
            )
            raise GitHubDriverError(f"Failed to fetch user profile: {e}") from e

        # Upsert user
        user = await self._user_repository.upsert_by_github_id(
            github_user_id=github_identity.github_user_id,
            github_login=github_identity.login,
        )

        # Store tokens (never expose to caller)
        await self._token_store.store_tokens(user.id, tokens)
        github_token_available = tokens.refresh_token is not None

        # Create session
        now = datetime.now(timezone.utc)
        session_expires_at = now + timedelta(seconds=self._session_expiry_seconds)
        session = Session(
            user_id=user.id,
            expires_at=session_expires_at,
        )
        await self._session_store.create(session)

        logger.info(
            "session.created",
            af_user_id=str(user.id),
            session_id=str(session.session_id),
            github_user_id=github_identity.github_user_id,
            github_login=github_identity.login,
            expires_at=session_expires_at.isoformat(),
        )

        # Mint JWT
        jwt_expires_at = now + timedelta(seconds=self._jwt_expiry_seconds)
        af_token = mint_af_jwt(
            secret=self._jwt_secret,
            user_id=user.id,
            session_id=session.session_id,
            expires_at=jwt_expires_at,
            issued_at=now,
        )

        logger.info(
            "auth.github.callback.success",
            af_user_id=str(user.id),
            github_user_id=github_identity.github_user_id,
            github_login=github_identity.login,
            github_token_available=github_token_available,
        )

        return OAuthCallbackResult(
            af_token=af_token,
            user=user,
            session=session,
            github_token_available=github_token_available,
        )
