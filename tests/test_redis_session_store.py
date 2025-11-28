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
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from af_identity_service.models.session import Session
from af_identity_service.stores.redis_session_store import (
    RedisConnectionFailedError,
    RedisSessionStore,
    _dict_to_session,
    _redact_host,
    _session_to_dict,
)


class TestRedactHost:
    """Tests for host redaction helper."""

    def test_redact_none_host(self) -> None:
        """Test redacting None host."""
        assert _redact_host(None) == "(not set)"

    def test_redact_empty_host(self) -> None:
        """Test redacting empty host."""
        assert _redact_host("") == "(not set)"

    def test_redact_short_host(self) -> None:
        """Test redacting host with 3 or fewer characters."""
        assert _redact_host("abc") == "***"
        assert _redact_host("ab") == "***"

    def test_redact_normal_host(self) -> None:
        """Test redacting normal host."""
        assert _redact_host("redis.example.com") == "red***"
        assert _redact_host("localhost") == "loc***"


class TestSessionSerialization:
    """Tests for session serialization helpers."""

    def test_session_to_dict(self) -> None:
        """Test converting Session to dictionary."""
        user_id = uuid4()
        session = Session(
            user_id=user_id,
            expires_at=datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        )

        result = _session_to_dict(session)

        assert result["session_id"] == str(session.session_id)
        assert result["user_id"] == str(user_id)
        assert result["revoked"] is False
        assert "created_at" in result
        assert "expires_at" in result

    def test_dict_to_session(self) -> None:
        """Test converting dictionary to Session."""
        session_id = str(uuid4())
        user_id = str(uuid4())
        data = {
            "session_id": session_id,
            "user_id": user_id,
            "created_at": "2025-01-01T12:00:00+00:00",
            "expires_at": "2025-01-02T12:00:00+00:00",
            "revoked": False,
        }

        session = _dict_to_session(data)

        assert str(session.session_id) == session_id
        assert str(session.user_id) == user_id
        assert session.revoked is False

    def test_roundtrip_serialization(self) -> None:
        """Test that session survives roundtrip serialization."""
        original = Session(
            user_id=uuid4(),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            revoked=True,
        )

        data = _session_to_dict(original)
        restored = _dict_to_session(data)

        assert restored.session_id == original.session_id
        assert restored.user_id == original.user_id
        assert restored.revoked == original.revoked


class TestRedisSessionStoreInit:
    """Tests for RedisSessionStore initialization."""

    def test_init_requires_host(self) -> None:
        """Test that host is required."""
        with pytest.raises(ValueError, match="Redis host is required"):
            RedisSessionStore(host="")

    def test_init_with_none_host(self) -> None:
        """Test that None host raises error."""
        with pytest.raises(ValueError, match="Redis host is required"):
            RedisSessionStore(host=None)  # type: ignore

    @patch("af_identity_service.stores.redis_session_store.Redis")
    def test_init_creates_client(self, mock_redis_class: MagicMock) -> None:
        """Test that initialization creates Redis client."""
        store = RedisSessionStore(host="localhost", port=6380, db=1, ssl=True)

        mock_redis_class.assert_called_once_with(
            host="localhost",
            port=6380,
            db=1,
            ssl=True,
            decode_responses=True,
            socket_connect_timeout=5.0,
            socket_timeout=5.0,
        )
        assert store._host_redacted == "loc***"


class TestRedisSessionStoreCreate:
    """Tests for RedisSessionStore.create method."""

    @pytest.fixture
    def mock_redis(self) -> MagicMock:
        """Create a mock Redis client."""
        return MagicMock()

    @pytest.fixture
    def store(self, mock_redis: MagicMock) -> RedisSessionStore:
        """Create a store with mocked Redis client."""
        with patch("af_identity_service.stores.redis_session_store.Redis", return_value=mock_redis):
            store = RedisSessionStore(host="localhost")
        return store

    @pytest.mark.asyncio
    async def test_create_stores_session(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test creating a session stores it in Redis."""
        user_id = uuid4()
        session = Session(
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )

        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe

        result = await store.create(session)

        assert result == session
        mock_redis.pipeline.assert_called_once()
        mock_pipe.setex.assert_called_once()
        mock_pipe.sadd.assert_called_once()
        mock_pipe.expire.assert_called_once()
        mock_pipe.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_connection_error(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test that connection error raises RedisConnectionFailedError."""
        session = Session(
            user_id=uuid4(),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        mock_redis.pipeline.side_effect = RedisConnectionError("Connection refused")

        with pytest.raises(RedisConnectionFailedError):
            await store.create(session)


class TestRedisSessionStoreGet:
    """Tests for RedisSessionStore.get method."""

    @pytest.fixture
    def mock_redis(self) -> MagicMock:
        """Create a mock Redis client."""
        return MagicMock()

    @pytest.fixture
    def store(self, mock_redis: MagicMock) -> RedisSessionStore:
        """Create a store with mocked Redis client."""
        with patch("af_identity_service.stores.redis_session_store.Redis", return_value=mock_redis):
            store = RedisSessionStore(host="localhost")
        return store

    @pytest.mark.asyncio
    async def test_get_returns_session(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test getting a session returns the session."""
        session_id = uuid4()
        user_id = uuid4()
        session_data = {
            "session_id": str(session_id),
            "user_id": str(user_id),
            "created_at": "2025-01-01T12:00:00+00:00",
            "expires_at": "2099-12-31T23:59:59+00:00",  # Far future to be active
            "revoked": False,
        }
        mock_redis.get.return_value = json.dumps(session_data)

        result = await store.get(session_id)

        assert result is not None
        assert result.session_id == session_id
        assert result.user_id == user_id

    @pytest.mark.asyncio
    async def test_get_returns_none_for_missing(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test getting a non-existent session returns None."""
        mock_redis.get.return_value = None

        result = await store.get(uuid4())

        assert result is None

    @pytest.mark.asyncio
    async def test_get_invalid_uuid_raises_error(self, store: RedisSessionStore) -> None:
        """Test that invalid UUID raises ValueError."""
        with pytest.raises(ValueError, match="session_id must be a UUID"):
            await store.get("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_get_connection_error(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test that connection error raises RedisConnectionFailedError."""
        mock_redis.get.side_effect = RedisConnectionError("Connection refused")

        with pytest.raises(RedisConnectionFailedError):
            await store.get(uuid4())


class TestRedisSessionStoreRevoke:
    """Tests for RedisSessionStore.revoke method."""

    @pytest.fixture
    def mock_redis(self) -> MagicMock:
        """Create a mock Redis client."""
        return MagicMock()

    @pytest.fixture
    def store(self, mock_redis: MagicMock) -> RedisSessionStore:
        """Create a store with mocked Redis client."""
        with patch("af_identity_service.stores.redis_session_store.Redis", return_value=mock_redis):
            store = RedisSessionStore(host="localhost")
        return store

    @pytest.mark.asyncio
    async def test_revoke_returns_true_when_found(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test revoking an existing session returns True."""
        session_id = uuid4()
        session_data = {
            "session_id": str(session_id),
            "user_id": str(uuid4()),
            "created_at": "2025-01-01T12:00:00+00:00",
            "expires_at": "2099-12-31T23:59:59+00:00",
            "revoked": False,
        }
        mock_redis.get.return_value = json.dumps(session_data)

        result = await store.revoke(session_id)

        assert result is True
        mock_redis.setex.assert_called_once()
        # Verify the revoked flag was set
        call_args = mock_redis.setex.call_args
        stored_data = json.loads(call_args[0][2])
        assert stored_data["revoked"] is True

    @pytest.mark.asyncio
    async def test_revoke_returns_false_when_not_found(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test revoking a non-existent session returns False."""
        mock_redis.get.return_value = None

        result = await store.revoke(uuid4())

        assert result is False

    @pytest.mark.asyncio
    async def test_revoke_invalid_uuid_raises_error(self, store: RedisSessionStore) -> None:
        """Test that invalid UUID raises ValueError."""
        with pytest.raises(ValueError, match="session_id must be a UUID"):
            await store.revoke("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_revoke_connection_error(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test that connection error raises RedisConnectionFailedError."""
        mock_redis.get.side_effect = RedisConnectionError("Connection refused")

        with pytest.raises(RedisConnectionFailedError):
            await store.revoke(uuid4())


class TestRedisSessionStoreListByUser:
    """Tests for RedisSessionStore.list_by_user method."""

    @pytest.fixture
    def mock_redis(self) -> MagicMock:
        """Create a mock Redis client."""
        return MagicMock()

    @pytest.fixture
    def store(self, mock_redis: MagicMock) -> RedisSessionStore:
        """Create a store with mocked Redis client."""
        with patch("af_identity_service.stores.redis_session_store.Redis", return_value=mock_redis):
            store = RedisSessionStore(host="localhost")
        return store

    @pytest.mark.asyncio
    async def test_list_returns_empty_for_no_sessions(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test listing sessions for user with no sessions."""
        mock_redis.smembers.return_value = set()

        result = await store.list_by_user(uuid4())

        assert result == []

    @pytest.mark.asyncio
    async def test_list_returns_active_sessions(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test listing returns only active sessions by default."""
        user_id = uuid4()
        session_id1 = uuid4()
        session_id2 = uuid4()

        # Session 1: Active
        session1_data = {
            "session_id": str(session_id1),
            "user_id": str(user_id),
            "created_at": "2025-01-01T12:00:00+00:00",
            "expires_at": "2099-12-31T23:59:59+00:00",
            "revoked": False,
        }
        # Session 2: Revoked
        session2_data = {
            "session_id": str(session_id2),
            "user_id": str(user_id),
            "created_at": "2025-01-01T12:00:00+00:00",
            "expires_at": "2099-12-31T23:59:59+00:00",
            "revoked": True,
        }

        mock_redis.smembers.return_value = {str(session_id1), str(session_id2)}
        mock_redis.mget.return_value = [
            json.dumps(session1_data),
            json.dumps(session2_data),
        ]

        result = await store.list_by_user(user_id, include_inactive=False)

        assert len(result) == 1
        assert result[0].session_id == session_id1

    @pytest.mark.asyncio
    async def test_list_includes_inactive_when_requested(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test listing includes inactive sessions when requested."""
        user_id = uuid4()
        session_id1 = uuid4()
        session_id2 = uuid4()

        # Session 1: Active
        session1_data = {
            "session_id": str(session_id1),
            "user_id": str(user_id),
            "created_at": "2025-01-01T12:00:00+00:00",
            "expires_at": "2099-12-31T23:59:59+00:00",
            "revoked": False,
        }
        # Session 2: Revoked
        session2_data = {
            "session_id": str(session_id2),
            "user_id": str(user_id),
            "created_at": "2025-01-01T12:00:00+00:00",
            "expires_at": "2099-12-31T23:59:59+00:00",
            "revoked": True,
        }

        mock_redis.smembers.return_value = {str(session_id1), str(session_id2)}
        mock_redis.mget.return_value = [
            json.dumps(session1_data),
            json.dumps(session2_data),
        ]

        result = await store.list_by_user(user_id, include_inactive=True)

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_list_cleans_up_stale_entries(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test that stale session IDs are removed from the index."""
        user_id = uuid4()
        session_id1 = uuid4()
        stale_session_id = uuid4()

        session1_data = {
            "session_id": str(session_id1),
            "user_id": str(user_id),
            "created_at": "2025-01-01T12:00:00+00:00",
            "expires_at": "2099-12-31T23:59:59+00:00",
            "revoked": False,
        }

        mock_redis.smembers.return_value = {str(session_id1), str(stale_session_id)}
        # stale_session_id returns None (expired via TTL)
        mock_redis.mget.return_value = [json.dumps(session1_data), None]

        result = await store.list_by_user(user_id)

        assert len(result) == 1
        mock_redis.srem.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_invalid_uuid_raises_error(self, store: RedisSessionStore) -> None:
        """Test that invalid UUID raises ValueError."""
        with pytest.raises(ValueError, match="user_id must be a UUID"):
            await store.list_by_user("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_list_connection_error(
        self, store: RedisSessionStore, mock_redis: MagicMock
    ) -> None:
        """Test that connection error raises RedisConnectionFailedError."""
        mock_redis.smembers.side_effect = RedisConnectionError("Connection refused")

        with pytest.raises(RedisConnectionFailedError):
            await store.list_by_user(uuid4())


class TestRedisSessionStoreInterfaceCompliance:
    """Tests to verify RedisSessionStore implements SessionStore interface."""

    @patch("af_identity_service.stores.redis_session_store.Redis")
    def test_implements_session_store(self, mock_redis_class: MagicMock) -> None:
        """Test that RedisSessionStore is a SessionStore."""
        from af_identity_service.stores.session_store import SessionStore

        store = RedisSessionStore(host="localhost")

        assert isinstance(store, SessionStore)

    @patch("af_identity_service.stores.redis_session_store.Redis")
    def test_has_all_required_methods(self, mock_redis_class: MagicMock) -> None:
        """Test that RedisSessionStore has all required methods."""
        store = RedisSessionStore(host="localhost")

        assert hasattr(store, "create")
        assert hasattr(store, "get")
        assert hasattr(store, "revoke")
        assert hasattr(store, "list_by_user")

        # Verify they are async
        import asyncio

        assert asyncio.iscoroutinefunction(store.create)
        assert asyncio.iscoroutinefunction(store.get)
        assert asyncio.iscoroutinefunction(store.revoke)
        assert asyncio.iscoroutinefunction(store.list_by_user)
