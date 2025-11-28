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
"""Database schema for AFUser table.

This module defines the SQLAlchemy model and migration functions for the
af_users table. The schema enforces uniqueness on id and github_user_id,
and uses timezone-aware timestamps (TIMESTAMPTZ) for all datetime fields.

Columns:
    id: UUID primary key
    github_user_id: Unique nullable integer for GitHub user ID
    github_login: Nullable text for GitHub username
    created_at: Timezone-aware timestamp (UTC) when user was created
    updated_at: Timezone-aware timestamp (UTC) when user was last updated
"""

import structlog
from sqlalchemy import BigInteger, Column, DateTime, Index, String, Table, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.engine import Engine
from sqlalchemy.schema import MetaData

logger = structlog.get_logger(__name__)

# Metadata instance for schema management
metadata = MetaData()

# af_users table definition
af_users_table = Table(
    "af_users",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("github_user_id", BigInteger, unique=True, nullable=True),
    Column("github_login", String, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Index("ix_af_users_github_user_id", "github_user_id", unique=True),
)


def create_af_users_table(engine: Engine) -> bool:
    """Create the af_users table if it doesn't exist.

    This function is idempotent - calling it multiple times on an
    already-initialized database is safe and will not cause errors.

    The table uses timezone-aware timestamps (TIMESTAMPTZ) to ensure
    UTC handling regardless of the Postgres server timezone.

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
                    "WHERE table_name = 'af_users')"
                )
            )
            table_exists = result.scalar()

            if table_exists:
                logger.info("af_users table already exists, skipping creation")
                return False

            # Create the table using the metadata definition
            metadata.create_all(engine, tables=[af_users_table])
            conn.commit()
            logger.info("af_users table created successfully")
            return True

    except Exception as e:
        logger.error("Failed to create af_users table", error=str(e))
        raise


def verify_af_users_schema(engine: Engine) -> dict[str, bool]:
    """Verify that the af_users table has the expected schema.

    This function checks that all required columns exist with the correct
    types and constraints.

    Args:
        engine: SQLAlchemy engine connected to the target database.

    Returns:
        Dictionary with verification results for each schema element.
    """
    results = {
        "table_exists": False,
        "id_column": False,
        "github_user_id_column": False,
        "github_login_column": False,
        "created_at_column": False,
        "updated_at_column": False,
        "github_user_id_unique": False,
    }

    try:
        with engine.connect() as conn:
            # Check table exists
            result = conn.execute(
                text(
                    "SELECT EXISTS (SELECT FROM information_schema.tables "
                    "WHERE table_name = 'af_users')"
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
                    "WHERE table_name = 'af_users'"
                )
            )
            columns = {row[0]: {"type": row[1], "nullable": row[2]} for row in columns_result}

            results["id_column"] = "id" in columns and columns["id"]["type"] == "uuid"
            results["github_user_id_column"] = (
                "github_user_id" in columns and columns["github_user_id"]["type"] == "bigint"
            )
            results["github_login_column"] = (
                "github_login" in columns
                and columns["github_login"]["type"] == "character varying"
            )
            results["created_at_column"] = (
                "created_at" in columns
                and "timestamp" in columns["created_at"]["type"]
            )
            results["updated_at_column"] = (
                "updated_at" in columns
                and "timestamp" in columns["updated_at"]["type"]
            )

            # Check unique constraint on github_user_id
            unique_result = conn.execute(
                text(
                    "SELECT COUNT(*) FROM information_schema.table_constraints tc "
                    "JOIN information_schema.constraint_column_usage ccu "
                    "ON tc.constraint_name = ccu.constraint_name "
                    "WHERE tc.table_name = 'af_users' "
                    "AND tc.constraint_type = 'UNIQUE' "
                    "AND ccu.column_name = 'github_user_id'"
                )
            )
            results["github_user_id_unique"] = (unique_result.scalar() or 0) > 0

    except Exception as e:
        logger.error("Failed to verify af_users schema", error=str(e))
        raise

    return results
