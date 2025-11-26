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
"""Authentication utilities for Agent Foundry Identity Service.

This module provides authentication utilities including:
- Authorization header parsing
- JWT validation with SessionStore verification
- Request dependencies for injecting user/session info
- Structured error responses for auth failures
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID

import structlog

from af_identity_service.models.session import Session
from af_identity_service.models.user import AFUser
from af_identity_service.security.jwt import (
    JWTClaims,
    JWTExpiredError,
    JWTValidationError,
    validate_af_jwt,
)

if TYPE_CHECKING:
    from af_identity_service.stores.session_store import SessionStore
    from af_identity_service.stores.user_store import AFUserRepository

logger = structlog.get_logger(__name__)


class AuthenticationError(Exception):
    """Base exception for authentication errors.

    This exception provides structured error information suitable for
    JSON responses. It does not expose cryptographic or security details.

    Attributes:
        error_code: A machine-readable error code.
        message: A human-readable error message safe for clients.
    """

    def __init__(self, error_code: str, message: str) -> None:
        """Initialize authentication error.

        Args:
            error_code: Machine-readable error code (e.g., 'invalid_token').
            message: Human-readable error message safe for client display.
        """
        super().__init__(message)
        self.error_code = error_code
        self.message = message


class InvalidTokenError(AuthenticationError):
    """Raised when token validation fails."""

    def __init__(self, message: str = "Invalid or expired token") -> None:
        """Initialize invalid token error.

        Args:
            message: Optional custom message.
        """
        super().__init__("invalid_token", message)


class SessionNotFoundError(AuthenticationError):
    """Raised when session is not found or inactive."""

    def __init__(self, message: str = "Session not found") -> None:
        """Initialize session not found error.

        Args:
            message: Optional custom message.
        """
        super().__init__("session_not_found", message)


class MissingAuthorizationError(AuthenticationError):
    """Raised when Authorization header is missing or malformed."""

    def __init__(self, message: str = "Authorization header required") -> None:
        """Initialize missing authorization error.

        Args:
            message: Optional custom message.
        """
        super().__init__("missing_authorization", message)


@dataclass
class AuthenticatedContext:
    """Context for an authenticated request.

    This class holds all information about the authenticated user
    and session for use in request handlers.

    Attributes:
        user: The authenticated AFUser.
        session: The active Session.
        claims: The validated JWT claims.
    """

    user: AFUser
    session: Session
    claims: JWTClaims


def parse_authorization_header(authorization: str | None) -> str:
    """Parse and validate the Authorization header.

    Expects a Bearer token format: "Bearer <token>"

    Args:
        authorization: The Authorization header value.

    Returns:
        The extracted token string.

    Raises:
        MissingAuthorizationError: If header is missing or malformed.
    """
    if not authorization:
        raise MissingAuthorizationError("Authorization header required")

    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        raise MissingAuthorizationError("Invalid authorization header format")

    scheme, token = parts
    if scheme.lower() != "bearer":
        raise MissingAuthorizationError("Invalid authorization scheme")

    if not token or not token.strip():
        raise MissingAuthorizationError("Token is required")

    return token.strip()


async def authenticate_request(
    authorization: str | None,
    jwt_secret: str,
    session_store: "SessionStore",
    user_repository: "AFUserRepository",
    now: datetime | None = None,
) -> AuthenticatedContext:
    """Authenticate a request using JWT and session validation.

    This function:
    1. Parses the Authorization header
    2. Validates the JWT signature and expiration
    3. Verifies the session exists and is active in SessionStore
    4. Retrieves the user information

    Args:
        authorization: The Authorization header value.
        jwt_secret: The secret for JWT signature verification.
        session_store: The session store for session validation.
        user_repository: The user repository for user retrieval.
        now: Optional current time for validation. Defaults to UTC now.

    Returns:
        AuthenticatedContext with user, session, and claims.

    Raises:
        MissingAuthorizationError: If Authorization header is missing/malformed.
        InvalidTokenError: If JWT is invalid or expired.
        SessionNotFoundError: If session is not found, revoked, or expired.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    # Parse Authorization header
    token = parse_authorization_header(authorization)

    # Validate JWT - check expiry first to avoid unnecessary SessionStore queries
    try:
        claims = validate_af_jwt(token, jwt_secret, now)
    except JWTExpiredError:
        logger.debug("auth.token.expired")
        raise InvalidTokenError("Token has expired")
    except JWTValidationError:
        logger.debug("auth.token.invalid")
        raise InvalidTokenError("Invalid or expired token")

    # Verify session exists and is active
    session = await session_store.get(claims.session_id)
    if session is None:
        logger.debug(
            "auth.session.not_found",
            session_id=str(claims.session_id),
        )
        raise SessionNotFoundError("Session not found")

    if session.is_revoked():
        logger.debug(
            "auth.session.revoked",
            session_id=str(claims.session_id),
        )
        raise InvalidTokenError("Session has been revoked")

    if session.is_expired(now):
        logger.debug(
            "auth.session.expired",
            session_id=str(claims.session_id),
        )
        raise InvalidTokenError("Session has expired")

    # Retrieve user
    user = await user_repository.get_by_id(claims.user_id)
    if user is None:
        logger.warning(
            "auth.user.not_found",
            user_id=str(claims.user_id),
            session_id=str(claims.session_id),
        )
        raise InvalidTokenError("Invalid token")

    logger.debug(
        "auth.success",
        af_user_id=str(user.id),
        session_id=str(claims.session_id),
        github_user_id=user.github_user_id,
    )

    return AuthenticatedContext(
        user=user,
        session=session,
        claims=claims,
    )


async def revoke_session(
    session_id: UUID | str,
    current_session_id: UUID,
    session_store: "SessionStore",
) -> tuple[bool, UUID]:
    """Revoke a session.

    Args:
        session_id: The session ID to revoke, or 'current' for current session.
        current_session_id: The ID of the current session (from auth context).
        session_store: The session store for revocation.

    Returns:
        Tuple of (success, resolved_session_id).

    Raises:
        SessionNotFoundError: If the session is not found.
        ValueError: If session_id is invalid.
    """
    # Resolve 'current' to actual session ID
    if session_id == "current":
        resolved_id = current_session_id
    elif isinstance(session_id, str):
        try:
            resolved_id = UUID(session_id)
        except ValueError:
            raise ValueError("Invalid session ID format")
    else:
        resolved_id = session_id

    # Check if session exists
    session = await session_store.get(resolved_id)
    if session is None:
        logger.debug(
            "session.revoke.not_found",
            session_id=str(resolved_id),
        )
        raise SessionNotFoundError("Session not found")

    # Revoke the session (idempotent operation)
    was_revoked = await session_store.revoke(resolved_id)

    if session.is_revoked():
        logger.info(
            "session.revoked.idempotent",
            session_id=str(resolved_id),
        )
    else:
        logger.info(
            "session.revoked",
            session_id=str(resolved_id),
        )

    return was_revoked, resolved_id
