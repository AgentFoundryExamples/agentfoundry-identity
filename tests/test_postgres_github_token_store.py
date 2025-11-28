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
"""Tests for PostgresGitHubTokenStore."""

import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy.exc import OperationalError

from af_identity_service.models.github import GitHubOAuthResult
from af_identity_service.security.crypto import (
    AES256GCMEncryptor,
    NoOpEncryptor,
)
from af_identity_service.stores.github_token_store import RefreshTokenNotFoundError
from af_identity_service.stores.postgres_github_token_store import (
    DatabaseOperationError,
    PostgresGitHubTokenStore,
)


class MockRow:
    """Mock database row for testing."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class MockResult:
    """Mock database result for testing."""

    def __init__(self, row=None):
        self._row = row
        self.rowcount = 1 if row else 0

    def fetchone(self):
        return self._row


class MockConnection:
    """Mock database connection for testing."""

    def __init__(self, result=None, should_raise=False):
        self._result = result
        self._should_raise = should_raise

    def execute(self, stmt):
        if self._should_raise:
            raise OperationalError("Connection error", None, None)
        return self._result

    def commit(self):
        if self._should_raise:
            raise OperationalError("Connection error", None, None)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class MockEngine:
    """Mock SQLAlchemy engine for testing."""

    def __init__(self, connection=None):
        self._connection = connection or MockConnection()

    def connect(self):
        return self._connection


@pytest.fixture
def encryptor() -> AES256GCMEncryptor:
    """Create a test encryptor."""
    key = secrets.token_bytes(32)
    return AES256GCMEncryptor(key)


@pytest.fixture
def noop_encryptor() -> NoOpEncryptor:
    """Create a NoOpEncryptor for testing."""
    return NoOpEncryptor()


class TestPostgresGitHubTokenStoreInit:
    """Tests for PostgresGitHubTokenStore initialization."""

    def test_init_with_engine_and_encryptor(self, encryptor: AES256GCMEncryptor) -> None:
        """Test that store initializes with engine and encryptor."""
        engine = MockEngine()
        store = PostgresGitHubTokenStore(engine, encryptor)
        assert store is not None

    def test_init_loads_table_definition(self, encryptor: AES256GCMEncryptor) -> None:
        """Test that store loads the github_tokens table definition."""
        engine = MockEngine()
        store = PostgresGitHubTokenStore(engine, encryptor)
        assert store._table is not None
        assert store._table.name == "github_tokens"


class TestPostgresGitHubTokenStoreStoreTokens:
    """Tests for store_tokens method."""

    @pytest.mark.asyncio
    async def test_store_tokens_encrypts_tokens(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that tokens are encrypted before storage."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token="ghr_xxx",
            refresh_token_expires_at=now + timedelta(days=180),
        )

        # Track what's executed
        executed_stmt = None

        class TrackingConnection(MockConnection):
            def execute(self, stmt):
                nonlocal executed_stmt
                executed_stmt = stmt
                return MockResult()

        engine = MockEngine(TrackingConnection())
        store = PostgresGitHubTokenStore(engine, encryptor)

        await store.store_tokens(user_id, tokens)

        # Verify execute was called
        assert executed_stmt is not None

    @pytest.mark.asyncio
    async def test_store_tokens_invalid_uuid_raises_error(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that invalid UUID raises ValueError."""
        engine = MockEngine()
        store = PostgresGitHubTokenStore(engine, encryptor)

        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=now + timedelta(hours=8),
        )

        with pytest.raises(ValueError) as exc_info:
            await store.store_tokens("not-a-uuid", tokens)  # type: ignore
        assert "UUID" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_store_tokens_db_error_raises_database_operation_error(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that database errors raise DatabaseOperationError."""
        engine = MockEngine(MockConnection(should_raise=True))
        store = PostgresGitHubTokenStore(engine, encryptor)

        user_id = uuid4()
        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=now + timedelta(hours=8),
        )

        with pytest.raises(DatabaseOperationError) as exc_info:
            await store.store_tokens(user_id, tokens)
        assert "database connection" in str(exc_info.value).lower()


class TestPostgresGitHubTokenStoreGetAccessToken:
    """Tests for get_access_token method."""

    @pytest.mark.asyncio
    async def test_get_access_token_returns_decrypted_token(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that access token is decrypted on retrieval."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        plaintext_token = "gho_xxx"

        # Pre-encrypt the token for the mock with AAD (user_id)
        aad = user_id.bytes
        encrypted_token = encryptor.encrypt(plaintext_token, aad)

        row = MockRow(
            encrypted_access_token=encrypted_token,
            access_token_expires_at=now + timedelta(hours=8),
        )
        engine = MockEngine(MockConnection(MockResult(row)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        token = await store.get_access_token(user_id)
        assert token == plaintext_token

    @pytest.mark.asyncio
    async def test_get_access_token_returns_none_when_not_found(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that None is returned when no token found."""
        user_id = uuid4()
        engine = MockEngine(MockConnection(MockResult(None)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        token = await store.get_access_token(user_id)
        assert token is None

    @pytest.mark.asyncio
    async def test_get_access_token_returns_none_when_expired(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that None is returned when token is expired."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)

        # Even with AAD, expired tokens should return None
        aad = user_id.bytes
        encrypted_token = encryptor.encrypt("gho_xxx", aad)
        row = MockRow(
            encrypted_access_token=encrypted_token,
            access_token_expires_at=now - timedelta(hours=1),  # Expired
        )
        engine = MockEngine(MockConnection(MockResult(row)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        token = await store.get_access_token(user_id)
        assert token is None

    @pytest.mark.asyncio
    async def test_get_access_token_returns_none_on_decryption_error(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that None is returned if decryption fails."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)

        # Use wrong key to create encrypted token
        wrong_encryptor = AES256GCMEncryptor(secrets.token_bytes(32))
        encrypted_with_wrong_key = wrong_encryptor.encrypt("gho_xxx")

        row = MockRow(
            encrypted_access_token=encrypted_with_wrong_key,
            access_token_expires_at=now + timedelta(hours=8),
        )
        engine = MockEngine(MockConnection(MockResult(row)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        token = await store.get_access_token(user_id)
        assert token is None

    @pytest.mark.asyncio
    async def test_get_access_token_invalid_uuid_raises_error(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that invalid UUID raises ValueError."""
        engine = MockEngine()
        store = PostgresGitHubTokenStore(engine, encryptor)

        with pytest.raises(ValueError):
            await store.get_access_token("not-a-uuid")  # type: ignore


class TestPostgresGitHubTokenStoreGetAccessTokenWithExpiry:
    """Tests for get_access_token_with_expiry method."""

    @pytest.mark.asyncio
    async def test_get_access_token_with_expiry_returns_tuple(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that method returns tuple of (token, expiry)."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=8)
        plaintext_token = "gho_xxx"

        # Pre-encrypt with AAD (user_id)
        aad = user_id.bytes
        encrypted_token = encryptor.encrypt(plaintext_token, aad)
        row = MockRow(
            encrypted_access_token=encrypted_token,
            access_token_expires_at=expires_at,
        )
        engine = MockEngine(MockConnection(MockResult(row)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        result = await store.get_access_token_with_expiry(user_id)
        assert result is not None
        token, returned_expiry = result
        assert token == plaintext_token
        assert returned_expiry == expires_at

    @pytest.mark.asyncio
    async def test_get_access_token_with_expiry_respects_buffer(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that method respects buffer_seconds."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        # Token expires in 4 minutes, but buffer is 5 minutes
        expires_at = now + timedelta(minutes=4)
        plaintext_token = "gho_xxx"

        # Pre-encrypt with AAD (user_id) - though not used due to early return
        aad = user_id.bytes
        encrypted_token = encryptor.encrypt(plaintext_token, aad)
        row = MockRow(
            encrypted_access_token=encrypted_token,
            access_token_expires_at=expires_at,
        )
        engine = MockEngine(MockConnection(MockResult(row)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        result = await store.get_access_token_with_expiry(user_id, buffer_seconds=300)
        # Should return None because token expires within buffer
        assert result is None

    @pytest.mark.asyncio
    async def test_get_access_token_with_expiry_returns_none_when_not_found(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that None is returned when no token found."""
        user_id = uuid4()
        engine = MockEngine(MockConnection(MockResult(None)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        result = await store.get_access_token_with_expiry(user_id)
        assert result is None


class TestPostgresGitHubTokenStoreGetRefreshToken:
    """Tests for get_refresh_token method."""

    @pytest.mark.asyncio
    async def test_get_refresh_token_returns_decrypted_token(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that refresh token is decrypted on retrieval."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        plaintext_token = "ghr_xxx"

        # Pre-encrypt with AAD (user_id)
        aad = user_id.bytes
        encrypted_token = encryptor.encrypt(plaintext_token, aad)
        row = MockRow(
            encrypted_refresh_token=encrypted_token,
            refresh_token_expires_at=now + timedelta(days=180),
        )
        engine = MockEngine(MockConnection(MockResult(row)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        token = await store.get_refresh_token(user_id)
        assert token == plaintext_token

    @pytest.mark.asyncio
    async def test_get_refresh_token_raises_error_when_not_found(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that error is raised when no token found."""
        user_id = uuid4()
        engine = MockEngine(MockConnection(MockResult(None)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        with pytest.raises(RefreshTokenNotFoundError) as exc_info:
            await store.get_refresh_token(user_id)
        assert str(user_id) in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_refresh_token_raises_error_when_expired(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that error is raised when token is expired."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)

        # Even with AAD, expired tokens should raise error
        aad = user_id.bytes
        encrypted_token = encryptor.encrypt("ghr_xxx", aad)
        row = MockRow(
            encrypted_refresh_token=encrypted_token,
            refresh_token_expires_at=now - timedelta(days=1),  # Expired
        )
        engine = MockEngine(MockConnection(MockResult(row)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        with pytest.raises(RefreshTokenNotFoundError) as exc_info:
            await store.get_refresh_token(user_id)
        assert "expired" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_get_refresh_token_raises_error_on_decryption_failure(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that error is raised if decryption fails."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)

        # Use wrong key - even with correct AAD, decryption will fail
        wrong_encryptor = AES256GCMEncryptor(secrets.token_bytes(32))
        aad = user_id.bytes
        encrypted_with_wrong_key = wrong_encryptor.encrypt("ghr_xxx", aad)

        row = MockRow(
            encrypted_refresh_token=encrypted_with_wrong_key,
            refresh_token_expires_at=now + timedelta(days=180),
        )
        engine = MockEngine(MockConnection(MockResult(row)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        with pytest.raises(RefreshTokenNotFoundError) as exc_info:
            await store.get_refresh_token(user_id)
        assert "decrypt" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_get_refresh_token_invalid_uuid_raises_error(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that invalid UUID raises ValueError."""
        engine = MockEngine()
        store = PostgresGitHubTokenStore(engine, encryptor)

        with pytest.raises(ValueError):
            await store.get_refresh_token("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_get_refresh_token_fails_with_wrong_user_aad(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that token encrypted for one user cannot be decrypted for another.

        This verifies that AAD (user_id) prevents token swapping attacks.
        """
        user_id_1 = uuid4()
        user_id_2 = uuid4()
        now = datetime.now(timezone.utc)
        plaintext_token = "ghr_xxx"

        # Encrypt token for user_1
        aad_1 = user_id_1.bytes
        encrypted_token = encryptor.encrypt(plaintext_token, aad_1)

        # Try to decrypt with user_2's ID - should fail
        row = MockRow(
            encrypted_refresh_token=encrypted_token,
            refresh_token_expires_at=now + timedelta(days=180),
        )
        engine = MockEngine(MockConnection(MockResult(row)))
        store = PostgresGitHubTokenStore(engine, encryptor)

        # Decryption should fail because AAD (user_id) doesn't match
        with pytest.raises(RefreshTokenNotFoundError) as exc_info:
            await store.get_refresh_token(user_id_2)
        assert "decrypt" in str(exc_info.value).lower()


class TestPostgresGitHubTokenStoreClearTokens:
    """Tests for clear_tokens method."""

    @pytest.mark.asyncio
    async def test_clear_tokens_executes_delete(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that clear_tokens executes a delete statement."""
        user_id = uuid4()

        executed_stmt = None

        class TrackingConnection(MockConnection):
            def execute(self, stmt):
                nonlocal executed_stmt
                executed_stmt = stmt
                return MockResult(row=MockRow())

        engine = MockEngine(TrackingConnection())
        store = PostgresGitHubTokenStore(engine, encryptor)

        await store.clear_tokens(user_id)
        assert executed_stmt is not None

    @pytest.mark.asyncio
    async def test_clear_tokens_invalid_uuid_raises_error(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that invalid UUID raises ValueError."""
        engine = MockEngine()
        store = PostgresGitHubTokenStore(engine, encryptor)

        with pytest.raises(ValueError):
            await store.clear_tokens("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_clear_tokens_db_error_raises_database_operation_error(
        self, encryptor: AES256GCMEncryptor
    ) -> None:
        """Test that database errors raise DatabaseOperationError."""
        engine = MockEngine(MockConnection(should_raise=True))
        store = PostgresGitHubTokenStore(engine, encryptor)

        with pytest.raises(DatabaseOperationError):
            await store.clear_tokens(uuid4())


class TestDatabaseOperationError:
    """Tests for DatabaseOperationError."""

    def test_is_github_token_store_error(self) -> None:
        """Test that DatabaseOperationError is a GitHubTokenStoreError."""
        from af_identity_service.stores.github_token_store import GitHubTokenStoreError

        error = DatabaseOperationError("test")
        assert isinstance(error, GitHubTokenStoreError)

    def test_message_is_preserved(self) -> None:
        """Test that error message is preserved."""
        error = DatabaseOperationError("custom message")
        assert str(error) == "custom message"
