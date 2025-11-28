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
"""Database schema for GitHub tokens table.

This module defines the SQLAlchemy table definition and migration functions
for the github_tokens table. The schema stores encrypted refresh and access
tokens for GitHub OAuth, with user_id as the primary key.

Columns:
    user_id: UUID primary key (references af_users.id via application logic)
    encrypted_refresh_token: LargeBinary for AES-256-GCM encrypted refresh token
    refresh_token_expires_at: Timezone-aware timestamp (UTC) for refresh token expiry
    encrypted_access_token: LargeBinary for AES-256-GCM encrypted access token (optional)
    access_token_expires_at: Timezone-aware timestamp (UTC) for access token expiry
    created_at: Timezone-aware timestamp (UTC) when record was created
    updated_at: Timezone-aware timestamp (UTC) when record was last updated

Notes:
    - Foreign key to af_users is NOT enforced at DB level to allow migrations
      to run in any order. Application logic validates user existence.
    - All token columns store encrypted binary data; never store plaintext.
    - The user_id index supports efficient lookups by user.
"""

import structlog
from sqlalchemy import Column, DateTime, Index, LargeBinary, Table, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.engine import Engine
from sqlalchemy.schema import MetaData

logger = structlog.get_logger(__name__)

# Metadata instance for schema management
# Using a separate MetaData to avoid conflicts with user_schema
github_tokens_metadata = MetaData()

# github_tokens table definition
github_tokens_table = Table(
    "github_tokens",
    github_tokens_metadata,
    Column("user_id", UUID(as_uuid=True), primary_key=True),
    Column("encrypted_refresh_token", LargeBinary, nullable=True),
    Column("refresh_token_expires_at", DateTime(timezone=True), nullable=True),
    Column("encrypted_access_token", LargeBinary, nullable=True),
    Column("access_token_expires_at", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Index("ix_github_tokens_user_id", "user_id", unique=True),
)


def create_github_tokens_table(engine: Engine) -> bool:
    """Create the github_tokens table if it doesn't exist.

    This function is idempotent - calling it multiple times on an
    already-initialized database is safe and will not cause errors.

    The table uses timezone-aware timestamps (TIMESTAMPTZ) to ensure
    UTC handling regardless of the Postgres server timezone.

    Note: This does NOT create a foreign key constraint to af_users
    to allow flexible migration ordering. Application logic should
    validate user existence before storing tokens.

    Args:
        engine: SQLAlchemy engine connected to the target database.

    Returns:
        True if the table was created, False if it already existed.

    Raises:
        Exception: If there is a database connection or SQL execution error.
    """
    try:
        with engine.connect() as conn:
            # Check if table exists
            result = conn.execute(
                text(
                    "SELECT EXISTS (SELECT FROM information_schema.tables "
                    "WHERE table_name = 'github_tokens')"
                )
            )
            table_exists = result.scalar()

            if table_exists:
                logger.info("github_tokens table already exists, skipping creation")
                return False

            # Create the table using the metadata definition
            github_tokens_metadata.create_all(engine, tables=[github_tokens_table])
            conn.commit()
            logger.info("github_tokens table created successfully")
            return True

    except Exception as e:
        logger.error("Failed to create github_tokens table", error=str(e))
        raise


def verify_github_tokens_schema(engine: Engine) -> dict[str, bool]:
    """Verify that the github_tokens table has the expected schema.

    This function checks that all required columns exist with the correct
    types and constraints.

    Args:
        engine: SQLAlchemy engine connected to the target database.

    Returns:
        Dictionary with verification results for each schema element.
    """
    results = {
        "table_exists": False,
        "user_id_column": False,
        "encrypted_refresh_token_column": False,
        "refresh_token_expires_at_column": False,
        "encrypted_access_token_column": False,
        "access_token_expires_at_column": False,
        "created_at_column": False,
        "updated_at_column": False,
        "user_id_primary_key": False,
    }

    try:
        with engine.connect() as conn:
            # Check table exists
            result = conn.execute(
                text(
                    "SELECT EXISTS (SELECT FROM information_schema.tables "
                    "WHERE table_name = 'github_tokens')"
                )
            )
            results["table_exists"] = result.scalar() or False

            if not results["table_exists"]:
                return results

            # Check columns
            columns_result = conn.execute(
                text(
                    "SELECT column_name, data_type, is_nullable "
                    "FROM information_schema.columns "
                    "WHERE table_name = 'github_tokens'"
                )
            )
            columns = {row[0]: {"type": row[1], "nullable": row[2]} for row in columns_result}

            results["user_id_column"] = (
                "user_id" in columns and columns["user_id"]["type"] == "uuid"
            )
            results["encrypted_refresh_token_column"] = (
                "encrypted_refresh_token" in columns
                and columns["encrypted_refresh_token"]["type"] == "bytea"
            )
            results["refresh_token_expires_at_column"] = (
                "refresh_token_expires_at" in columns
                and "timestamp" in columns["refresh_token_expires_at"]["type"]
            )
            results["encrypted_access_token_column"] = (
                "encrypted_access_token" in columns
                and columns["encrypted_access_token"]["type"] == "bytea"
            )
            results["access_token_expires_at_column"] = (
                "access_token_expires_at" in columns
                and "timestamp" in columns["access_token_expires_at"]["type"]
            )
            results["created_at_column"] = (
                "created_at" in columns and "timestamp" in columns["created_at"]["type"]
            )
            results["updated_at_column"] = (
                "updated_at" in columns and "timestamp" in columns["updated_at"]["type"]
            )

            # Check primary key on user_id
            pk_result = conn.execute(
                text(
                    "SELECT COUNT(*) FROM information_schema.table_constraints tc "
                    "JOIN information_schema.constraint_column_usage ccu "
                    "ON tc.constraint_name = ccu.constraint_name "
                    "WHERE tc.table_name = 'github_tokens' "
                    "AND tc.constraint_type = 'PRIMARY KEY' "
                    "AND ccu.column_name = 'user_id'"
                )
            )
            results["user_id_primary_key"] = (pk_result.scalar() or 0) > 0

    except Exception as e:
        logger.error("Failed to verify github_tokens schema", error=str(e))
        raise

    return results
