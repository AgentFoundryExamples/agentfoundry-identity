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
"""Tests for PostgresUserRepository.

These tests verify the PostgresUserRepository implementation using SQLite
as a test database since it supports the same SQLAlchemy interface.
"""

from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text

from af_identity_service.stores.postgres_user_repository import (
    PostgresUserRepository,
)


class TestPostgresUserRepository:
    """Tests for PostgresUserRepository using SQLite for testing."""

    @pytest.fixture
    def engine(self):
        """Create an in-memory SQLite database for testing."""
        # Use SQLite for testing - it supports similar SQL operations
        engine = create_engine("sqlite:///:memory:")

        # Create the table manually since SQLite syntax differs slightly
        with engine.connect() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE af_users (
                        id TEXT PRIMARY KEY,
                        github_user_id INTEGER UNIQUE,
                        github_login TEXT,
                        created_at TIMESTAMP NOT NULL,
                        updated_at TIMESTAMP NOT NULL
                    )
                    """
                )
            )
            conn.commit()

        return engine

    @pytest.fixture
    def repo(self, engine) -> PostgresUserRepository:
        """Create a PostgresUserRepository connected to the test database."""
        # Override the table to work with our SQLite test table
        return PostgresUserRepository(engine)

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, repo: PostgresUserRepository) -> None:
        """Test getting a user by ID that doesn't exist."""
        user_id = uuid4()
        result = await repo.get_by_id(user_id)

        assert result is None

    @pytest.mark.asyncio
    async def test_get_by_id_invalid_type(self, repo: PostgresUserRepository) -> None:
        """Test that invalid UUID type raises ValueError."""
        with pytest.raises(ValueError):
            await repo.get_by_id("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_get_by_github_id_not_found(
        self, repo: PostgresUserRepository
    ) -> None:
        """Test getting a user by GitHub ID that doesn't exist."""
        result = await repo.get_by_github_id(12345)

        assert result is None


class TestPostgresUserRepositoryIntegration:
    """Integration tests for PostgresUserRepository.

    These tests require a real Postgres database and are skipped
    if one is not available.
    """

    @pytest.fixture
    def pg_engine(self):
        """Create a connection to a real Postgres database.

        This fixture is skipped if Postgres is not available.
        """
        import os
        from urllib.parse import quote_plus

        host = os.environ.get("TEST_POSTGRES_HOST")
        if not host:
            pytest.skip("TEST_POSTGRES_HOST not set - skipping integration tests")

        port = os.environ.get("TEST_POSTGRES_PORT", "5432")
        database = os.environ.get("TEST_POSTGRES_DB", "test_identity")
        user = os.environ.get("TEST_POSTGRES_USER", "postgres")
        password = os.environ.get("TEST_POSTGRES_PASSWORD", "")

        # URL encode the password to handle special characters
        escaped_password = quote_plus(password) if password else ""
        connection_string = (
            f"postgresql+psycopg://{user}:{escaped_password}@{host}:{port}/{database}"
        )

        try:
            engine = create_engine(connection_string)
            # Test connection
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))

            # Create the table for testing
            from af_identity_service.migrations.user_schema import create_af_users_table

            create_af_users_table(engine)

            yield engine

            # Cleanup - drop the table after tests
            with engine.connect() as conn:
                conn.execute(text("DROP TABLE IF EXISTS af_users"))
                conn.commit()

        except Exception as e:
            pytest.skip(f"Could not connect to Postgres: {e}")

    @pytest.fixture
    def pg_repo(self, pg_engine) -> PostgresUserRepository:
        """Create a PostgresUserRepository for integration tests."""
        return PostgresUserRepository(pg_engine)

    @pytest.mark.asyncio
    async def test_upsert_creates_new_user(
        self, pg_repo: PostgresUserRepository
    ) -> None:
        """Test upserting creates a new user when not exists."""
        user = await pg_repo.upsert_by_github_id(12345, "octocat")

        assert user.github_user_id == 12345
        assert user.github_login == "octocat"
        assert user.id is not None
        assert user.created_at is not None
        assert user.updated_at is not None
        assert user.created_at.tzinfo is not None  # UTC-aware

    @pytest.mark.asyncio
    async def test_upsert_updates_existing_user(
        self, pg_repo: PostgresUserRepository
    ) -> None:
        """Test upserting updates an existing user."""
        # Create user
        user1 = await pg_repo.upsert_by_github_id(12345, "octocat")
        original_id = user1.id

        # Update user
        user2 = await pg_repo.upsert_by_github_id(12345, "new_login")

        assert user2.id == original_id
        assert user2.github_login == "new_login"

    @pytest.mark.asyncio
    async def test_get_by_id_after_upsert(
        self, pg_repo: PostgresUserRepository
    ) -> None:
        """Test getting user by ID after upsert."""
        user = await pg_repo.upsert_by_github_id(12345, "octocat")
        found = await pg_repo.get_by_id(user.id)

        assert found is not None
        assert found.id == user.id
        assert found.github_user_id == 12345

    @pytest.mark.asyncio
    async def test_get_by_github_id_after_upsert(
        self, pg_repo: PostgresUserRepository
    ) -> None:
        """Test getting user by GitHub ID after upsert."""
        user = await pg_repo.upsert_by_github_id(12345, "octocat")
        found = await pg_repo.get_by_github_id(12345)

        assert found is not None
        assert found.id == user.id

    @pytest.mark.asyncio
    async def test_timestamps_are_utc_aware(
        self, pg_repo: PostgresUserRepository
    ) -> None:
        """Test that timestamps returned from database are UTC-aware."""
        from datetime import timedelta

        user = await pg_repo.upsert_by_github_id(12345, "octocat")

        assert user.created_at.tzinfo is not None
        assert user.updated_at.tzinfo is not None
        # Check that the timezone has zero UTC offset
        assert user.created_at.tzinfo.utcoffset(None) == timedelta(0)
        assert user.updated_at.tzinfo.utcoffset(None) == timedelta(0)
