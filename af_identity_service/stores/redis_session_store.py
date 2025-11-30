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

This module provides a Redis-backed implementation of the SessionStore ABC
for production use. Sessions are stored with JSON serialization and use
Redis TTL for automatic expiration. A secondary index (set per user) enables
efficient listing of sessions by user.

Key patterns:
- Session data: session:{session_id} -> JSON payload
- User index: user_sessions:{user_id} -> set of session_ids

The revoked flag is stored in the JSON payload and persisted independently
of TTL to ensure sessions remain revoked even if TTL extends beyond revocation.
"""

import json
from datetime import datetime, timezone
from uuid import UUID

import redis.asyncio as redis
import structlog

from af_identity_service.models.session import Session
from af_identity_service.stores.session_store import SessionStore

logger = structlog.get_logger(__name__)


class RedisSessionStoreError(Exception):
    """Base exception for Redis session store errors."""

    pass


class RedisConnectionError(RedisSessionStoreError):
    """Raised when Redis connection fails."""

    pass


class RedisSessionStore(SessionStore):
    """Redis-backed implementation of SessionStore.

    This implementation stores sessions as JSON in Redis with:
    - Automatic TTL-based expiration aligned with session expires_at
    - A secondary set index per user for efficient list_by_user queries
    - Support for TLS connections when configured

    Thread Safety: Redis operations are atomic; the async client handles
    concurrent access.

    Key Patterns:
    - session:{session_id} - JSON payload with session data
    - user_sessions:{user_id} - Set of session_ids belonging to user

    Attributes:
        _client: The async Redis client instance.
        _key_prefix: Prefix for all Redis keys (default: "af:session:").
    """

    SESSION_KEY_PREFIX = "af:session:"
    USER_SESSIONS_KEY_PREFIX = "af:user_sessions:"

    def __init__(
        self,
        host: str,
        port: int = 6379,
        db: int = 0,
        tls_enabled: bool = False,
    ) -> None:
        """Initialize the Redis session store.

        Does not perform network I/O during initialization. Connection is
        established lazily on first operation.

        Args:
            host: Redis server hostname.
            port: Redis server port (default: 6379).
            db: Redis database number (default: 0).
            tls_enabled: Whether to use TLS for connections (default: False).
        """
        self._host = host
        self._port = port
        self._db = db
        self._tls_enabled = tls_enabled
        self._client: redis.Redis | None = None

        # Log initialization with redacted host info
        redacted_host = self._redact_host(host)
        logger.info(
            "Initialized Redis session store",
            host=redacted_host,
            port=port,
            db=db,
            tls_enabled=tls_enabled,
        )

    def _redact_host(self, host: str) -> str:
        """Redact host information for logging.

        Keeps only the first and last characters, replacing the middle with *.

        Args:
            host: The hostname to redact.

        Returns:
            Redacted hostname string.
        """
        if len(host) <= 4:
            return "*" * len(host)
        return f"{host[0]}{'*' * (len(host) - 2)}{host[-1]}"

    async def _get_client(self) -> redis.Redis:
        """Get or create the Redis client.

        Returns:
            The Redis async client instance.

        Raises:
            RedisConnectionError: If connection to Redis fails.
        """
        if self._client is None:
            try:
                # Build connection URL
                scheme = "rediss" if self._tls_enabled else "redis"
                url = f"{scheme}://{self._host}:{self._port}/{self._db}"

                self._client = redis.from_url(
                    url,
                    decode_responses=True,
                    socket_timeout=5.0,
                    socket_connect_timeout=5.0,
                )

                # Test connection
                await self._client.ping()

                logger.info(
                    "Redis connection established",
                    host=self._redact_host(self._host),
                    port=self._port,
                    db=self._db,
                )
            except redis.RedisError as e:
                logger.error(
                    "Failed to connect to Redis",
                    host=self._redact_host(self._host),
                    port=self._port,
                    error=str(e),
                )
                raise RedisConnectionError(
                    f"Failed to connect to Redis at {self._redact_host(self._host)}:{self._port}"
                ) from e

        return self._client

    def _session_key(self, session_id: UUID) -> str:
        """Generate the Redis key for a session.

        Args:
            session_id: The session UUID.

        Returns:
            The Redis key string.
        """
        return f"{self.SESSION_KEY_PREFIX}{session_id}"

    def _user_sessions_key(self, user_id: UUID) -> str:
        """Generate the Redis key for a user's session set.

        Args:
            user_id: The user UUID.

        Returns:
            The Redis key string.
        """
        return f"{self.USER_SESSIONS_KEY_PREFIX}{user_id}"

    def _serialize_session(self, session: Session) -> str:
        """Serialize a Session to JSON string.

        Args:
            session: The session to serialize.

        Returns:
            JSON string representation.
        """
        return json.dumps({
            "session_id": str(session.session_id),
            "user_id": str(session.user_id),
            "created_at": session.created_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "revoked": session.revoked,
        })

    def _deserialize_session(self, data: str) -> Session:
        """Deserialize a JSON string to a Session.

        Args:
            data: JSON string representation.

        Returns:
            The deserialized Session instance.
        """
        payload = json.loads(data)
        return Session(
            session_id=UUID(payload["session_id"]),
            user_id=UUID(payload["user_id"]),
            created_at=datetime.fromisoformat(payload["created_at"]),
            expires_at=datetime.fromisoformat(payload["expires_at"]),
            revoked=payload["revoked"],
        )

    def _calculate_ttl_seconds(self, expires_at: datetime) -> int:
        """Calculate TTL in seconds from expires_at timestamp.

        Args:
            expires_at: The session expiration timestamp.

        Returns:
            TTL in seconds, minimum 1 second.
        """
        now = datetime.now(timezone.utc)
        ttl = int((expires_at - now).total_seconds())
        return max(ttl, 1)  # Minimum 1 second TTL

    async def create(self, session: Session) -> Session:
        """Create and store a new session.

        Stores the session in Redis with TTL and adds to the user's session set.

        Args:
            session: The session to store.

        Returns:
            The stored session.

        Raises:
            RedisConnectionError: If Redis connection fails.
        """
        try:
            client = await self._get_client()

            session_key = self._session_key(session.session_id)
            user_sessions_key = self._user_sessions_key(session.user_id)
            ttl_seconds = self._calculate_ttl_seconds(session.expires_at)
            session_data = self._serialize_session(session)

            # Use pipeline for atomic operations
            async with client.pipeline() as pipe:
                # Store session with TTL
                pipe.setex(session_key, ttl_seconds, session_data)
                # Add to user's session set
                pipe.sadd(user_sessions_key, str(session.session_id))
                # Set TTL on user sessions set (cleanup when no sessions remain)
                # Use max TTL since the set should persist as long as any session exists
                pipe.expire(user_sessions_key, ttl_seconds)
                await pipe.execute()

            logger.info(
                "Session created in Redis",
                session_id=str(session.session_id),
                user_id=str(session.user_id),
                expires_at=session.expires_at.isoformat(),
                ttl_seconds=ttl_seconds,
            )

            return session

        except redis.RedisError as e:
            logger.error(
                "Failed to create session in Redis",
                session_id=str(session.session_id),
                error=str(e),
            )
            raise RedisConnectionError(f"Failed to create session: {e}") from e

    async def get(self, session_id: UUID) -> Session | None:
        """Retrieve a session by ID.

        Returns None if the session is not found (including if expired by TTL).
        Expired sessions are still returned if they exist but will have
        is_expired() == True.

        Args:
            session_id: The session's UUID.

        Returns:
            The Session if found, None otherwise.

        Raises:
            ValueError: If session_id is not a valid UUID.
            RedisConnectionError: If Redis connection fails.
        """
        if not isinstance(session_id, UUID):
            raise ValueError(f"session_id must be a UUID, got {type(session_id).__name__}")

        try:
            client = await self._get_client()
            session_key = self._session_key(session_id)

            data = await client.get(session_key)

            if data is None:
                logger.debug("Session not found in Redis", session_id=str(session_id))
                return None

            session = self._deserialize_session(data)
            logger.debug(
                "Session found in Redis",
                session_id=str(session_id),
                is_active=session.is_active(),
            )
            return session

        except redis.RedisError as e:
            logger.error(
                "Failed to get session from Redis",
                session_id=str(session_id),
                error=str(e),
            )
            raise RedisConnectionError(f"Failed to get session: {e}") from e

    async def revoke(self, session_id: UUID) -> bool:
        """Revoke a session.

        Updates the revoked flag in the session data while preserving TTL.
        The session remains in Redis until TTL expires but is marked as revoked.

        Args:
            session_id: The session's UUID.

        Returns:
            True if the session was found and revoked, False if not found.

        Raises:
            ValueError: If session_id is not a valid UUID.
            RedisConnectionError: If Redis connection fails.
        """
        if not isinstance(session_id, UUID):
            raise ValueError(f"session_id must be a UUID, got {type(session_id).__name__}")

        try:
            client = await self._get_client()
            session_key = self._session_key(session_id)

            # Get current session data
            data = await client.get(session_key)
            if data is None:
                logger.debug("Session not found for revocation", session_id=str(session_id))
                return False

            # Parse, update revoked flag, and save
            session = self._deserialize_session(data)
            revoked_session = session.model_copy(update={"revoked": True})

            # Get remaining TTL
            ttl = await client.ttl(session_key)
            if ttl < 0:
                # Key exists but has no TTL, or doesn't exist
                ttl = 1

            # Store updated session with remaining TTL
            updated_data = self._serialize_session(revoked_session)
            await client.setex(session_key, ttl, updated_data)

            logger.info("Session revoked in Redis", session_id=str(session_id))
            return True

        except redis.RedisError as e:
            logger.error(
                "Failed to revoke session in Redis",
                session_id=str(session_id),
                error=str(e),
            )
            raise RedisConnectionError(f"Failed to revoke session: {e}") from e

    async def list_by_user(
        self, user_id: UUID, include_inactive: bool = False
    ) -> list[Session]:
        """List all sessions for a user.

        Uses the secondary index (user_sessions set) for efficient lookup.
        Cleans up stale session references from the set.

        Args:
            user_id: The user's UUID.
            include_inactive: If True, includes expired and revoked sessions.
                             If False (default), only returns active sessions.

        Returns:
            A list of sessions for the user.

        Raises:
            ValueError: If user_id is not a valid UUID.
            RedisConnectionError: If Redis connection fails.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        try:
            client = await self._get_client()
            user_sessions_key = self._user_sessions_key(user_id)

            # Get all session IDs from the user's set
            session_ids = await client.smembers(user_sessions_key)

            if not session_ids:
                logger.debug(
                    "No sessions found for user in Redis",
                    user_id=str(user_id),
                )
                return []

            # Fetch all sessions in a pipeline
            sessions: list[Session] = []
            stale_ids: list[str] = []

            async with client.pipeline() as pipe:
                for sid in session_ids:
                    pipe.get(f"{self.SESSION_KEY_PREFIX}{sid}")
                results = await pipe.execute()

            now = datetime.now(timezone.utc)

            for sid, data in zip(session_ids, results, strict=False):
                if data is None:
                    # Session expired by TTL, mark for cleanup
                    stale_ids.append(sid)
                    continue

                session = self._deserialize_session(data)

                if include_inactive or session.is_active(now):
                    sessions.append(session)

            # Clean up stale session references
            if stale_ids:
                await client.srem(user_sessions_key, *stale_ids)
                logger.debug(
                    "Cleaned up stale session references",
                    user_id=str(user_id),
                    count=len(stale_ids),
                )

            logger.debug(
                "Listed sessions for user from Redis",
                user_id=str(user_id),
                count=len(sessions),
                include_inactive=include_inactive,
            )

            return sessions

        except redis.RedisError as e:
            logger.error(
                "Failed to list sessions from Redis",
                user_id=str(user_id),
                error=str(e),
            )
            raise RedisConnectionError(f"Failed to list sessions: {e}") from e

    async def close(self) -> None:
        """Close the Redis connection.

        Should be called when shutting down the application.
        """
        if self._client is not None:
            await self._client.close()
            self._client = None
            logger.info("Redis connection closed")
