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
"""Tests for Redis session store."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
import redis.asyncio as redis

from af_identity_service.models.session import Session
from af_identity_service.stores.redis_session_store import (
    RedisConnectionError,
    RedisSessionStore,
)


class TestRedisSessionStoreInit:
    """Tests for RedisSessionStore initialization."""

    def test_init_stores_config(self) -> None:
        """Test that initialization stores configuration without connecting."""
        store = RedisSessionStore(
            host="redis.example.com",
            port=6380,
            db=2,
            tls_enabled=True,
        )

        assert store._host == "redis.example.com"
        assert store._port == 6380
        assert store._db == 2
        assert store._tls_enabled is True
        assert store._client is None  # Not connected yet

    def test_init_uses_defaults(self) -> None:
        """Test that initialization uses default values."""
        store = RedisSessionStore(host="localhost")

        assert store._host == "localhost"
        assert store._port == 6379
        assert store._db == 0
        assert store._tls_enabled is False

    def test_redact_host_short(self) -> None:
        """Test host redaction for short hostnames."""
        store = RedisSessionStore(host="abc")
        assert store._redact_host("abc") == "***"
        assert store._redact_host("ab") == "**"

    def test_redact_host_long(self) -> None:
        """Test host redaction for longer hostnames."""
        store = RedisSessionStore(host="redis.example.com")
        redacted = store._redact_host("redis.example.com")
        assert redacted.startswith("r")
        assert redacted.endswith("m")
        assert "*" in redacted


class TestRedisSessionStoreOperations:
    """Tests for RedisSessionStore CRUD operations with mocked Redis."""

    @pytest.fixture
    def mock_redis_client(self) -> AsyncMock:
        """Create a mock Redis async client."""
        client = AsyncMock()
        client.ping = AsyncMock()
        client.get = AsyncMock(return_value=None)
        client.setex = AsyncMock()
        client.sadd = AsyncMock()
        client.srem = AsyncMock()
        client.smembers = AsyncMock(return_value=set())
        client.expire = AsyncMock()
        client.ttl = AsyncMock(return_value=3600)
        client.close = AsyncMock()
        client.eval = AsyncMock(return_value=1)  # Mock Lua script execution
        client.mget = AsyncMock(return_value=[])  # Mock MGET

        return client

    @pytest.fixture
    def store_with_mock(self, mock_redis_client: AsyncMock) -> RedisSessionStore:
        """Create a RedisSessionStore with a mocked client."""
        store = RedisSessionStore(host="localhost")
        store._client = mock_redis_client
        return store

    @pytest.mark.asyncio
    async def test_create_session(self, store_with_mock: RedisSessionStore) -> None:
        """Test creating a session stores data in Redis."""
        user_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user_id, expires_at=expires_at)

        result = await store_with_mock.create(session)

        assert result.session_id == session.session_id
        assert result.user_id == user_id

        # Verify Lua script was called for atomic create
        store_with_mock._client.eval.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_session_found(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test getting an existing session."""
        user_id = uuid4()
        session_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        # Mock stored session data
        session_data = json.dumps({
            "session_id": str(session_id),
            "user_id": str(user_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
            "revoked": False,
        })
        mock_redis_client.get.return_value = session_data

        result = await store_with_mock.get(session_id)

        assert result is not None
        assert result.session_id == session_id
        assert result.user_id == user_id
        assert result.revoked is False

    @pytest.mark.asyncio
    async def test_get_session_not_found(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test getting a non-existent session returns None."""
        mock_redis_client.get.return_value = None

        result = await store_with_mock.get(uuid4())

        assert result is None

    @pytest.mark.asyncio
    async def test_get_session_invalid_type(
        self, store_with_mock: RedisSessionStore
    ) -> None:
        """Test that invalid UUID type raises ValueError."""
        with pytest.raises(ValueError):
            await store_with_mock.get("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_revoke_session_success(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test revoking an existing session."""
        session_id = uuid4()

        # Mock Lua script returns 1 for success
        mock_redis_client.eval.return_value = 1

        result = await store_with_mock.revoke(session_id)

        assert result is True
        mock_redis_client.eval.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_session_not_found(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test revoking a non-existent session returns False."""
        # Mock Lua script returns 0 for not found
        mock_redis_client.eval.return_value = 0

        result = await store_with_mock.revoke(uuid4())

        assert result is False

    @pytest.mark.asyncio
    async def test_revoke_session_invalid_type(
        self, store_with_mock: RedisSessionStore
    ) -> None:
        """Test that invalid UUID type raises ValueError."""
        with pytest.raises(ValueError):
            await store_with_mock.revoke("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_list_by_user_empty(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test listing sessions for a user with no sessions."""
        mock_redis_client.smembers.return_value = set()

        result = await store_with_mock.list_by_user(uuid4())

        assert result == []

    @pytest.mark.asyncio
    async def test_list_by_user_with_sessions(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test listing sessions for a user with active sessions."""
        user_id = uuid4()
        session_id_1 = uuid4()
        session_id_2 = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        # Mock user's session set
        mock_redis_client.smembers.return_value = {
            str(session_id_1),
            str(session_id_2),
        }

        # Mock MGET results for session data
        session_data_1 = json.dumps({
            "session_id": str(session_id_1),
            "user_id": str(user_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
            "revoked": False,
        })
        session_data_2 = json.dumps({
            "session_id": str(session_id_2),
            "user_id": str(user_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
            "revoked": False,
        })

        mock_redis_client.mget.return_value = [session_data_1, session_data_2]

        result = await store_with_mock.list_by_user(user_id)

        assert len(result) == 2
        session_ids = {s.session_id for s in result}
        assert session_id_1 in session_ids
        assert session_id_2 in session_ids

    @pytest.mark.asyncio
    async def test_list_by_user_filters_inactive(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test that list_by_user filters inactive sessions by default."""
        user_id = uuid4()
        active_session_id = uuid4()
        revoked_session_id = uuid4()
        future = datetime.now(timezone.utc) + timedelta(hours=24)

        mock_redis_client.smembers.return_value = {
            str(active_session_id),
            str(revoked_session_id),
        }

        active_data = json.dumps({
            "session_id": str(active_session_id),
            "user_id": str(user_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": future.isoformat(),
            "revoked": False,
        })
        revoked_data = json.dumps({
            "session_id": str(revoked_session_id),
            "user_id": str(user_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": future.isoformat(),
            "revoked": True,
        })

        mock_redis_client.mget.return_value = [active_data, revoked_data]

        result = await store_with_mock.list_by_user(user_id, include_inactive=False)

        assert len(result) == 1
        assert result[0].session_id == active_session_id

    @pytest.mark.asyncio
    async def test_list_by_user_includes_inactive(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test that list_by_user includes inactive sessions when requested."""
        user_id = uuid4()
        active_session_id = uuid4()
        revoked_session_id = uuid4()
        future = datetime.now(timezone.utc) + timedelta(hours=24)

        mock_redis_client.smembers.return_value = {
            str(active_session_id),
            str(revoked_session_id),
        }

        active_data = json.dumps({
            "session_id": str(active_session_id),
            "user_id": str(user_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": future.isoformat(),
            "revoked": False,
        })
        revoked_data = json.dumps({
            "session_id": str(revoked_session_id),
            "user_id": str(user_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": future.isoformat(),
            "revoked": True,
        })

        mock_redis_client.mget.return_value = [active_data, revoked_data]

        result = await store_with_mock.list_by_user(user_id, include_inactive=True)

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_list_by_user_invalid_type(
        self, store_with_mock: RedisSessionStore
    ) -> None:
        """Test that invalid UUID type raises ValueError."""
        with pytest.raises(ValueError):
            await store_with_mock.list_by_user("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_list_by_user_cleans_stale_refs(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test that stale session references are cleaned up."""
        user_id = uuid4()
        active_session_id = uuid4()
        stale_session_id = uuid4()
        future = datetime.now(timezone.utc) + timedelta(hours=24)

        mock_redis_client.smembers.return_value = {
            str(active_session_id),
            str(stale_session_id),
        }

        active_data = json.dumps({
            "session_id": str(active_session_id),
            "user_id": str(user_id),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": future.isoformat(),
            "revoked": False,
        })

        # First result is active, second is None (stale/expired)
        mock_redis_client.mget.return_value = [active_data, None]

        result = await store_with_mock.list_by_user(user_id)

        assert len(result) == 1
        # Verify srem was called to clean up stale reference
        mock_redis_client.srem.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_returns_true_when_healthy(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test health_check returns True when Redis is healthy."""
        mock_redis_client.ping.return_value = True

        result = await store_with_mock.health_check()

        assert result is True
        mock_redis_client.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_returns_false_on_error(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test health_check returns False when Redis ping fails."""
        mock_redis_client.ping.side_effect = redis.RedisError("Connection lost")

        result = await store_with_mock.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_close(
        self, store_with_mock: RedisSessionStore, mock_redis_client: AsyncMock
    ) -> None:
        """Test closing the Redis connection."""
        await store_with_mock.close()

        mock_redis_client.close.assert_called_once()
        assert store_with_mock._client is None


class TestRedisSessionStoreConnectionErrors:
    """Tests for Redis connection error handling."""

    @pytest.mark.asyncio
    async def test_get_client_connection_failure(self) -> None:
        """Test that connection failures raise RedisConnectionError."""
        store = RedisSessionStore(host="invalid-host")

        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_client = AsyncMock()
            mock_client.ping.side_effect = redis.RedisError("Connection refused")
            mock_from_url.return_value = mock_client

            with pytest.raises(RedisConnectionError) as exc_info:
                await store._get_client()

            assert "Failed to connect to Redis" in str(exc_info.value)
            # Verify host is redacted in error message
            assert "invalid-host" not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_redis_error(self) -> None:
        """Test that Redis errors during create raise RedisConnectionError."""
        store = RedisSessionStore(host="localhost")
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock()
        mock_client.eval = AsyncMock(side_effect=redis.RedisError("Write error"))

        store._client = mock_client

        user_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user_id, expires_at=expires_at)

        with pytest.raises(RedisConnectionError) as exc_info:
            await store.create(session)

        assert "Failed to create session" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_redis_error(self) -> None:
        """Test that Redis errors during get raise RedisConnectionError."""
        store = RedisSessionStore(host="localhost")
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=redis.RedisError("Read error"))
        store._client = mock_client

        with pytest.raises(RedisConnectionError) as exc_info:
            await store.get(uuid4())

        assert "Failed to get session" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_revoke_redis_error(self) -> None:
        """Test that Redis errors during revoke raise RedisConnectionError."""
        store = RedisSessionStore(host="localhost")
        mock_client = AsyncMock()
        mock_client.eval = AsyncMock(side_effect=redis.RedisError("Script error"))
        store._client = mock_client

        with pytest.raises(RedisConnectionError) as exc_info:
            await store.revoke(uuid4())

        assert "Failed to revoke session" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_list_by_user_redis_error(self) -> None:
        """Test that Redis errors during list raise RedisConnectionError."""
        store = RedisSessionStore(host="localhost")
        mock_client = AsyncMock()
        mock_client.smembers = AsyncMock(side_effect=redis.RedisError("Read error"))
        store._client = mock_client

        with pytest.raises(RedisConnectionError) as exc_info:
            await store.list_by_user(uuid4())

        assert "Failed to list sessions" in str(exc_info.value)


class TestRedisSessionStoreSerialization:
    """Tests for session serialization/deserialization."""

    def test_serialize_session(self) -> None:
        """Test that session serialization produces valid JSON."""
        store = RedisSessionStore(host="localhost")
        user_id = uuid4()
        session_id = uuid4()
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(hours=24)

        session = Session(
            session_id=session_id,
            user_id=user_id,
            created_at=created_at,
            expires_at=expires_at,
            revoked=True,
        )

        serialized = store._serialize_session(session)
        data = json.loads(serialized)

        assert data["session_id"] == str(session_id)
        assert data["user_id"] == str(user_id)
        assert data["revoked"] is True
        assert "created_at" in data
        assert "expires_at" in data

    def test_deserialize_session(self) -> None:
        """Test that session deserialization works correctly."""
        store = RedisSessionStore(host="localhost")
        user_id = uuid4()
        session_id = uuid4()
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(hours=24)

        data = json.dumps({
            "session_id": str(session_id),
            "user_id": str(user_id),
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "revoked": False,
        })

        session = store._deserialize_session(data)

        assert session.session_id == session_id
        assert session.user_id == user_id
        assert session.revoked is False

    def test_calculate_ttl_future_expiry(self) -> None:
        """Test TTL calculation for future expiry."""
        store = RedisSessionStore(host="localhost")
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        ttl = store._calculate_ttl_seconds(expires_at)

        # Should be approximately 3600 seconds (1 hour)
        assert 3500 <= ttl <= 3700

    def test_calculate_ttl_past_expiry(self) -> None:
        """Test TTL calculation for past expiry returns minimum TTL."""
        store = RedisSessionStore(host="localhost")
        expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

        ttl = store._calculate_ttl_seconds(expires_at)

        # Should be minimum TTL of 1 second
        assert ttl == 1


class TestRedisSessionStoreTLS:
    """Tests for TLS configuration."""

    @pytest.mark.asyncio
    async def test_tls_enabled_uses_ssl(self) -> None:
        """Test that TLS enabled uses ssl=True."""
        store = RedisSessionStore(
            host="redis.example.com",
            port=6379,
            db=0,
            tls_enabled=True,
        )

        with patch("redis.asyncio.Redis") as mock_redis_class:
            mock_client = AsyncMock()
            mock_client.ping = AsyncMock()
            mock_redis_class.return_value = mock_client

            await store._get_client()

            # Verify ssl=True is passed
            call_kwargs = mock_redis_class.call_args.kwargs
            assert call_kwargs.get("ssl") is True

    @pytest.mark.asyncio
    async def test_tls_disabled_uses_no_ssl(self) -> None:
        """Test that TLS disabled uses ssl=False."""
        store = RedisSessionStore(
            host="localhost",
            port=6379,
            db=0,
            tls_enabled=False,
        )

        with patch("redis.asyncio.Redis") as mock_redis_class:
            mock_client = AsyncMock()
            mock_client.ping = AsyncMock()
            mock_redis_class.return_value = mock_client

            await store._get_client()

            # Verify ssl=False is passed
            call_kwargs = mock_redis_class.call_args.kwargs
            assert call_kwargs.get("ssl") is False
