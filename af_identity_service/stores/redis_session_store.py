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
"""Redis-backed session store implementation.

This module provides a Redis implementation of the SessionStore protocol
for production use. Sessions are stored as JSON with TTL-based expiration
and explicit revocation support.

Key Design:
- Session data stored as JSON: {session_id, user_id, created_at, expires_at, revoked}
- Redis TTL used for automatic expiration, with additional buffer for revoked sessions
- Per-user session index (SET) for efficient list_by_user queries
- Thread-safe via Redis atomic operations
"""

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

from af_identity_service.models.session import Session
from af_identity_service.stores.session_store import SessionStore

logger = structlog.get_logger(__name__)

# Key prefix for session data
SESSION_KEY_PREFIX = "session:"
# Key prefix for user-to-sessions index
USER_SESSIONS_KEY_PREFIX = "user_sessions:"
# Extra TTL buffer for revoked sessions (to ensure revoked flag is checked)
# Revoked sessions get extended TTL to prevent resurrection via re-creation
REVOKED_SESSION_TTL_BUFFER_SECONDS = 86400  # 24 hours extra


class RedisSessionStoreError(Exception):
    """Base exception for Redis session store errors."""

    pass


class RedisConnectionFailedError(RedisSessionStoreError):
    """Raised when Redis connection fails."""

    pass


def _redact_host(host: str | None) -> str:
    """Redact host info for logging.

    Args:
        host: The host string to redact.

    Returns:
        Redacted host string showing only first 3 chars.
    """
    if not host:
        return "(not set)"
    if len(host) <= 3:
        return "***"
    return f"{host[:3]}***"


def _session_to_dict(session: Session) -> dict[str, Any]:
    """Convert Session model to dictionary for JSON storage.

    Args:
        session: The Session model instance.

    Returns:
        Dictionary representation with ISO format datetimes.
    """
    return {
        "session_id": str(session.session_id),
        "user_id": str(session.user_id),
        "created_at": session.created_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
        "revoked": session.revoked,
    }


def _dict_to_session(data: dict[str, Any]) -> Session:
    """Convert dictionary to Session model.

    Args:
        data: Dictionary representation from JSON storage.

    Returns:
        Session model instance.
    """
    return Session(
        session_id=UUID(data["session_id"]),
        user_id=UUID(data["user_id"]),
        created_at=datetime.fromisoformat(data["created_at"]),
        expires_at=datetime.fromisoformat(data["expires_at"]),
        revoked=data["revoked"],
    )


class RedisSessionStore(SessionStore):
    """Redis-backed implementation of SessionStore.

    This implementation is suitable for production deployments with
    multiple service instances. Sessions are stored as JSON with
    Redis TTL for automatic expiration.

    Key Features:
    - Session data includes session_id, user_id, created_at, expires_at, revoked
    - Redis TTL auto-expires sessions; revoked sessions retain extended TTL
    - Per-user session index (SET) enables efficient list_by_user queries
    - Connection errors are logged with redacted host information

    Thread Safety:
    - All operations are atomic via Redis commands
    - Safe for concurrent access from multiple workers

    Attributes:
        _client: Redis client instance.
        _host: Redacted host for logging.
    """

    def __init__(
        self,
        host: str,
        port: int = 6379,
        db: int = 0,
        ssl: bool = False,
    ) -> None:
        """Initialize the Redis session store.

        Connection is established lazily on first operation to avoid
        blocking during service startup.

        Args:
            host: Redis host address.
            port: Redis port number (default: 6379).
            db: Redis database number (default: 0).
            ssl: Whether to use TLS (default: False).

        Raises:
            ValueError: If host is empty or None.
        """
        if not host:
            raise ValueError("Redis host is required")

        self._host_redacted = _redact_host(host)
        self._client = Redis(
            host=host,
            port=port,
            db=db,
            ssl=ssl,
            decode_responses=True,  # Return strings instead of bytes
            socket_connect_timeout=5.0,  # 5 second connection timeout
            socket_timeout=5.0,  # 5 second operation timeout
        )

        logger.info(
            "Initialized Redis session store",
            host=self._host_redacted,
            port=port,
            db=db,
            ssl=ssl,
        )

    def _session_key(self, session_id: UUID) -> str:
        """Generate Redis key for a session.

        Args:
            session_id: The session UUID.

        Returns:
            Redis key string.
        """
        return f"{SESSION_KEY_PREFIX}{session_id}"

    def _user_sessions_key(self, user_id: UUID) -> str:
        """Generate Redis key for user's session index.

        Args:
            user_id: The user UUID.

        Returns:
            Redis key string.
        """
        return f"{USER_SESSIONS_KEY_PREFIX}{user_id}"

    def _calculate_ttl_seconds(self, expires_at: datetime, revoked: bool = False) -> int:
        """Calculate TTL in seconds from expiration time.

        For revoked sessions, adds extra buffer to ensure the revoked
        flag is retained and checked.

        Args:
            expires_at: Session expiration datetime (must be timezone-aware).
            revoked: Whether the session is revoked.

        Returns:
            TTL in seconds (minimum 1 second).
        """
        now = datetime.now(timezone.utc)
        ttl = int((expires_at - now).total_seconds())

        if revoked:
            # Add buffer for revoked sessions to prevent resurrection
            ttl += REVOKED_SESSION_TTL_BUFFER_SECONDS

        # Ensure minimum TTL of 1 second
        return max(1, ttl)

    async def create(self, session: Session) -> Session:
        """Create and store a new session.

        Stores session data as JSON with TTL based on expires_at.
        Also adds session_id to user's session index set.

        Args:
            session: The session to store.

        Returns:
            The stored session.

        Raises:
            RedisConnectionFailedError: If Redis connection fails.
        """
        try:
            session_key = self._session_key(session.session_id)
            user_sessions_key = self._user_sessions_key(session.user_id)
            session_data = json.dumps(_session_to_dict(session))
            ttl = self._calculate_ttl_seconds(session.expires_at)

            # Use pipeline for atomic operation
            pipe = self._client.pipeline()
            pipe.setex(session_key, ttl, session_data)
            pipe.sadd(user_sessions_key, str(session.session_id))
            # Set expiry on user sessions set (extend if needed)
            # Use the session's TTL plus buffer to ensure cleanup
            pipe.expire(user_sessions_key, ttl + REVOKED_SESSION_TTL_BUFFER_SECONDS)
            pipe.execute()

            logger.info(
                "Session created in Redis",
                session_id=str(session.session_id),
                user_id=str(session.user_id),
                expires_at=session.expires_at.isoformat(),
                ttl_seconds=ttl,
            )
            return session

        except RedisConnectionError as e:
            logger.error(
                "Redis connection failed during session creation",
                host=self._host_redacted,
                error=str(e),
            )
            raise RedisConnectionFailedError(
                f"Failed to connect to Redis at {self._host_redacted}"
            ) from e
        except RedisError as e:
            logger.error(
                "Redis operation failed during session creation",
                host=self._host_redacted,
                error=str(e),
            )
            raise RedisSessionStoreError(f"Redis operation failed: {e}") from e

    async def get(self, session_id: UUID) -> Session | None:
        """Retrieve a session by ID.

        Returns None if session not found (including TTL-expired sessions).
        Expired sessions that still exist are returned with is_expired() == True.

        Args:
            session_id: The session's UUID.

        Returns:
            The Session if found, None otherwise.

        Raises:
            ValueError: If session_id is not a valid UUID.
            RedisConnectionFailedError: If Redis connection fails.
        """
        if not isinstance(session_id, UUID):
            raise ValueError(f"session_id must be a UUID, got {type(session_id).__name__}")

        try:
            session_key = self._session_key(session_id)
            session_data = self._client.get(session_key)

            if session_data is None:
                logger.debug("Session not found in Redis", session_id=str(session_id))
                return None

            session = _dict_to_session(json.loads(session_data))
            logger.debug(
                "Session found in Redis",
                session_id=str(session_id),
                is_active=session.is_active(),
            )
            return session

        except RedisConnectionError as e:
            logger.error(
                "Redis connection failed during session retrieval",
                host=self._host_redacted,
                session_id=str(session_id),
                error=str(e),
            )
            raise RedisConnectionFailedError(
                f"Failed to connect to Redis at {self._host_redacted}"
            ) from e
        except RedisError as e:
            logger.error(
                "Redis operation failed during session retrieval",
                host=self._host_redacted,
                session_id=str(session_id),
                error=str(e),
            )
            raise RedisSessionStoreError(f"Redis operation failed: {e}") from e

    async def revoke(self, session_id: UUID) -> bool:
        """Revoke a session.

        Sets the revoked flag to True and extends TTL to ensure the
        revoked state is persisted for revocation checks.

        Args:
            session_id: The session's UUID.

        Returns:
            True if the session was found and revoked, False if not found.

        Raises:
            ValueError: If session_id is not a valid UUID.
            RedisConnectionFailedError: If Redis connection fails.
        """
        if not isinstance(session_id, UUID):
            raise ValueError(f"session_id must be a UUID, got {type(session_id).__name__}")

        try:
            session_key = self._session_key(session_id)
            session_data = self._client.get(session_key)

            if session_data is None:
                logger.debug("Session not found for revocation", session_id=str(session_id))
                return False

            # Parse, update revoked flag, and save back
            session_dict = json.loads(session_data)
            session_dict["revoked"] = True
            updated_data = json.dumps(session_dict)

            # Calculate new TTL with buffer for revoked sessions
            expires_at = datetime.fromisoformat(session_dict["expires_at"])
            ttl = self._calculate_ttl_seconds(expires_at, revoked=True)

            self._client.setex(session_key, ttl, updated_data)

            logger.info("Session revoked in Redis", session_id=str(session_id), new_ttl=ttl)
            return True

        except RedisConnectionError as e:
            logger.error(
                "Redis connection failed during session revocation",
                host=self._host_redacted,
                session_id=str(session_id),
                error=str(e),
            )
            raise RedisConnectionFailedError(
                f"Failed to connect to Redis at {self._host_redacted}"
            ) from e
        except RedisError as e:
            logger.error(
                "Redis operation failed during session revocation",
                host=self._host_redacted,
                session_id=str(session_id),
                error=str(e),
            )
            raise RedisSessionStoreError(f"Redis operation failed: {e}") from e

    async def list_by_user(
        self, user_id: UUID, include_inactive: bool = False
    ) -> list[Session]:
        """List all sessions for a user.

        Uses per-user session index (SET) for efficient lookup without
        full key scans. Cleans up stale entries from the index.

        Args:
            user_id: The user's UUID.
            include_inactive: If True, includes expired and revoked sessions.
                             If False (default), only returns active sessions.

        Returns:
            A list of sessions for the user.

        Raises:
            ValueError: If user_id is not a valid UUID.
            RedisConnectionFailedError: If Redis connection fails.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        try:
            user_sessions_key = self._user_sessions_key(user_id)
            session_ids = self._client.smembers(user_sessions_key)

            if not session_ids:
                logger.debug(
                    "No sessions found for user in Redis",
                    user_id=str(user_id),
                    include_inactive=include_inactive,
                )
                return []

            sessions: list[Session] = []
            stale_ids: list[str] = []
            now = datetime.now(timezone.utc)

            # Batch get all session data
            session_keys = [f"{SESSION_KEY_PREFIX}{sid}" for sid in session_ids]
            session_data_list = self._client.mget(session_keys)

            for sid, session_data in zip(session_ids, session_data_list):
                if session_data is None:
                    # Session expired via TTL, mark for cleanup
                    stale_ids.append(sid)
                    continue

                session = _dict_to_session(json.loads(session_data))

                if include_inactive or session.is_active(now):
                    sessions.append(session)

            # Clean up stale session IDs from the index
            if stale_ids:
                self._client.srem(user_sessions_key, *stale_ids)
                logger.debug(
                    "Cleaned up stale session IDs from user index",
                    user_id=str(user_id),
                    stale_count=len(stale_ids),
                )

            logger.debug(
                "Listed sessions for user in Redis",
                user_id=str(user_id),
                count=len(sessions),
                include_inactive=include_inactive,
            )
            return sessions

        except RedisConnectionError as e:
            logger.error(
                "Redis connection failed during session listing",
                host=self._host_redacted,
                user_id=str(user_id),
                error=str(e),
            )
            raise RedisConnectionFailedError(
                f"Failed to connect to Redis at {self._host_redacted}"
            ) from e
        except RedisError as e:
            logger.error(
                "Redis operation failed during session listing",
                host=self._host_redacted,
                user_id=str(user_id),
                error=str(e),
            )
            raise RedisSessionStoreError(f"Redis operation failed: {e}") from e
