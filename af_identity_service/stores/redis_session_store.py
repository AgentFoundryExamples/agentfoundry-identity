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
- Session data: af:session:{session_id} -> JSON payload
- User index: af:user_sessions:{user_id} -> set of session_ids

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
                # Create client using explicit parameters to avoid credential exposure
                # in URL strings that could leak to logs or error messages
                self._client = redis.Redis(
                    host=self._host,
                    port=self._port,
                    db=self._db,
                    ssl=self._tls_enabled,
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

    # Lua script for atomic create operation to avoid TTL race conditions
    # Ensures user sessions set TTL is always the maximum of existing and new TTL
    # KEYS[1] = session_key, KEYS[2] = user_sessions_key
    # ARGV[1] = session_data, ARGV[2] = session_ttl, ARGV[3] = session_id
    _CREATE_SCRIPT = """
    local session_key = KEYS[1]
    local user_sessions_key = KEYS[2]
    local session_data = ARGV[1]
    local session_ttl = tonumber(ARGV[2])
    local session_id = ARGV[3]

    -- Store session with TTL
    redis.call('SETEX', session_key, session_ttl, session_data)

    -- Add to user's session set
    redis.call('SADD', user_sessions_key, session_id)

    -- Get current TTL atomically and set max
    local current_ttl = redis.call('TTL', user_sessions_key)
    local new_ttl = session_ttl
    if current_ttl > 0 and current_ttl > session_ttl then
        new_ttl = current_ttl
    end
    redis.call('EXPIRE', user_sessions_key, new_ttl)

    return 1
    """

    async def create(self, session: Session) -> Session:
        """Create and store a new session.

        Stores the session in Redis with TTL and adds to the user's session set.
        Uses a Lua script for atomic operations to ensure the user sessions index
        TTL is always the maximum of existing and new TTL, avoiding race conditions.

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

            # Use Lua script for atomic create to avoid TTL race conditions
            await client.eval(
                self._CREATE_SCRIPT,
                2,  # number of keys
                session_key,
                user_sessions_key,
                session_data,
                ttl_seconds,
                str(session.session_id),
            )

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

    # Lua script for atomic revoke operation to avoid race conditions
    # Returns: 1 if revoked successfully, 0 if session not found, -1 if JSON error
    # The script atomically: GET session -> check exists -> GET TTL -> update revoked -> SETEX
    _REVOKE_SCRIPT = """
    local data = redis.call('GET', KEYS[1])
    if not data then
        return 0
    end
    local ttl = redis.call('TTL', KEYS[1])
    if ttl < 1 then
        -- TTL -2 means key doesn't exist (race condition, already expired)
        -- TTL -1 means no expiration set (shouldn't happen but handle gracefully)
        -- In both cases, use a minimum TTL to preserve the revoked state briefly
        ttl = 1
    end
    -- Use pcall to safely handle JSON decode/encode errors
    local ok, session = pcall(cjson.decode, data)
    if not ok then
        return -1
    end
    session['revoked'] = true
    local ok2, updated = pcall(cjson.encode, session)
    if not ok2 then
        return -1
    end
    redis.call('SETEX', KEYS[1], ttl, updated)
    return 1
    """

    async def revoke(self, session_id: UUID) -> bool:
        """Revoke a session.

        Updates the revoked flag in the session data while preserving TTL.
        Uses a Lua script for atomic get-update-set to avoid race conditions.
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

            # Use Lua script for atomic revoke to avoid race condition
            # between GET, TTL, and SETEX operations
            result = await client.eval(self._REVOKE_SCRIPT, 1, session_key)

            if result == 0:
                logger.debug("Session not found for revocation", session_id=str(session_id))
                return False

            if result == -1:
                logger.error(
                    "JSON parsing error during session revocation",
                    session_id=str(session_id),
                )
                raise RedisConnectionError(
                    f"Failed to revoke session {session_id}: JSON parsing error"
                )

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

            # Fetch all sessions using MGET for better performance
            sessions: list[Session] = []
            stale_ids: list[str] = []

            # Convert to list to maintain order for zip
            session_ids_list = list(session_ids)
            session_keys = [f"{self.SESSION_KEY_PREFIX}{sid}" for sid in session_ids_list]
            results = await client.mget(session_keys)

            now = datetime.now(timezone.utc)

            for sid, data in zip(session_ids_list, results):
                if data is None:
                    # Session expired by TTL, mark for cleanup
                    stale_ids.append(sid)
                    continue

                session = self._deserialize_session(data)

                if include_inactive or session.is_active(now):
                    sessions.append(session)

            # Clean up stale session references in chunks to avoid blocking
            if stale_ids:
                chunk_size = 1000
                for i in range(0, len(stale_ids), chunk_size):
                    chunk = stale_ids[i:i + chunk_size]
                    await client.srem(user_sessions_key, *chunk)

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

    async def health_check(self) -> bool:
        """Check Redis connectivity with a PING command.

        This is a lightweight health check that verifies the Redis
        connection is alive without exhausting the connection pool.

        Returns:
            True if Redis is healthy and responsive, False otherwise.
        """
        try:
            client = await self._get_client()
            await client.ping()
            return True
        except Exception as e:
            logger.debug("Redis health check failed", error_type=type(e).__name__)
            return False

    async def close(self) -> None:
        """Close the Redis connection.

        Should be called when shutting down the application.
        """
        if self._client is not None:
            await self._client.close()
            self._client = None
            logger.info("Redis connection closed")
