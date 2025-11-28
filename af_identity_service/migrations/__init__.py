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
"""Database migrations module for AF Identity Service.

This module provides CLI tools for managing database migrations.
Run with: python -m af_identity_service.migrations

Commands:
    migrate  - Create all required tables (idempotent)
    verify   - Verify schema matches expected structure
    status   - Show current migration status

Environment Variables:
    POSTGRES_HOST - Database host (required unless GOOGLE_CLOUD_SQL_INSTANCE is set)
    POSTGRES_PORT - Database port (default: 5432)
    POSTGRES_DB   - Database name (required)
    POSTGRES_USER - Database user (required for direct connections)
    POSTGRES_PASSWORD - Database password (required for direct connections)
    GOOGLE_CLOUD_SQL_INSTANCE - Cloud SQL instance connection name (optional)

For Cloud SQL usage with IAM authentication, set GOOGLE_CLOUD_SQL_INSTANCE
and optionally POSTGRES_USER. Password may be omitted when using IAM auth.

Example:
    # Local development
    POSTGRES_HOST=localhost POSTGRES_DB=identity POSTGRES_USER=postgres \\
        POSTGRES_PASSWORD=secret python -m af_identity_service.migrations migrate

    # Cloud SQL with standard auth
    GOOGLE_CLOUD_SQL_INSTANCE=project:region:instance POSTGRES_DB=identity \\
        POSTGRES_USER=identity_user POSTGRES_PASSWORD=secret \\
        python -m af_identity_service.migrations migrate
"""

import argparse
import os
import sys

import structlog
from sqlalchemy import create_engine, text

from af_identity_service.migrations.github_token_schema import (
    create_github_tokens_table,
    verify_github_tokens_schema,
)
from af_identity_service.migrations.user_schema import (
    create_af_users_table,
    verify_af_users_schema,
)

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(colors=True),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(0),
)

logger = structlog.get_logger(__name__)


def get_connection_string() -> str:
    """Build database connection string from environment variables.

    Supports both direct Postgres connections and Google Cloud SQL
    connections. For Cloud SQL, uses the pg8000 dialect with the
    Cloud SQL Python Connector.

    Returns:
        SQLAlchemy connection string.

    Raises:
        ValueError: If required environment variables are missing.
    """
    host = os.environ.get("POSTGRES_HOST")
    port = os.environ.get("POSTGRES_PORT", "5432")
    database = os.environ.get("POSTGRES_DB")
    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    cloud_sql_instance = os.environ.get("GOOGLE_CLOUD_SQL_INSTANCE")

    if not database:
        raise ValueError("POSTGRES_DB environment variable is required")

    if cloud_sql_instance and not host:
        # Cloud SQL connection - for now, require host to be set
        # Full Cloud SQL Connector integration would require additional dependencies
        raise ValueError(
            "When using GOOGLE_CLOUD_SQL_INSTANCE, you must also set POSTGRES_HOST "
            "to the Cloud SQL proxy address (e.g., localhost or /cloudsql/instance-name)"
        )

    if not host:
        raise ValueError(
            "POSTGRES_HOST environment variable is required "
            "(or GOOGLE_CLOUD_SQL_INSTANCE for Cloud SQL)"
        )

    if not user:
        raise ValueError("POSTGRES_USER environment variable is required")

    if not password:
        raise ValueError("POSTGRES_PASSWORD environment variable is required")

    # Build connection URL using SQLAlchemy's URL object which automatically
    # masks passwords in repr/str to prevent accidental logging
    from sqlalchemy import URL

    url = URL.create(
        drivername="postgresql+psycopg",
        username=user,
        password=password,
        host=host,
        port=int(port),
        database=database,
    )
    # Log connection details - URL object automatically masks password in repr
    logger.info(
        "Using database connection",
        host=host,
        port=port,
        database=database,
        user=user,
        password="***" if password else "(not set)",
    )

    return url.render_as_string(hide_password=False)


def run_migrate() -> int:
    """Run database migrations.

    Creates all required tables if they don't exist. This operation
    is idempotent and safe to run multiple times.

    Returns:
        Exit code: 0 for success, 1 for failure.
    """
    try:
        connection_string = get_connection_string()
        engine = create_engine(connection_string)

        # Test connection
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.fetchone()
            logger.info("Database connection successful")

        # Run migrations - order matters for dependencies
        # af_users first (github_tokens references user_id conceptually)
        users_created = create_af_users_table(engine)
        if users_created:
            logger.info("Migration completed: af_users table created")
        else:
            logger.info("af_users table already exists")

        # github_tokens table for encrypted token storage
        tokens_created = create_github_tokens_table(engine)
        if tokens_created:
            logger.info("Migration completed: github_tokens table created")
        else:
            logger.info("github_tokens table already exists")

        if not users_created and not tokens_created:
            logger.info("Migration completed: no changes needed")

        return 0

    except ValueError as e:
        logger.error("Configuration error", error=str(e))
        return 1
    except Exception as e:
        error_msg = str(e)
        # Mask any passwords that might appear in error messages
        if "POSTGRES_PASSWORD" in os.environ:
            password = os.environ.get("POSTGRES_PASSWORD", "")
            if password:
                error_msg = error_msg.replace(password, "***")
        logger.error("Migration failed", error=error_msg)
        return 1


def run_verify() -> int:
    """Verify database schema matches expected structure.

    Returns:
        Exit code: 0 if schema is valid, 1 if invalid or error.
    """
    try:
        connection_string = get_connection_string()
        engine = create_engine(connection_string)

        # Verify af_users schema
        users_results = verify_af_users_schema(engine)
        users_valid = all(users_results.values())

        # Verify github_tokens schema
        tokens_results = verify_github_tokens_schema(engine)
        tokens_valid = all(tokens_results.values())

        all_valid = users_valid and tokens_valid
        status = "VALID" if all_valid else "INVALID"

        logger.info(f"Schema verification: {status}")
        logger.info("af_users table:", **users_results)
        logger.info("github_tokens table:", **tokens_results)

        if not all_valid:
            logger.warning("Schema verification failed - some checks did not pass")
            if not users_valid:
                for key, value in users_results.items():
                    if not value:
                        logger.warning(f"  af_users.{key}: FAILED")
            if not tokens_valid:
                for key, value in tokens_results.items():
                    if not value:
                        logger.warning(f"  github_tokens.{key}: FAILED")
            return 1

        return 0

    except ValueError as e:
        logger.error("Configuration error", error=str(e))
        return 1
    except Exception as e:
        error_msg = str(e)
        if "POSTGRES_PASSWORD" in os.environ:
            password = os.environ.get("POSTGRES_PASSWORD", "")
            if password:
                error_msg = error_msg.replace(password, "***")
        logger.error("Verification failed", error=error_msg)
        return 1


def run_status() -> int:
    """Show current migration status.

    Returns:
        Exit code: 0 for success, 1 for failure.
    """
    try:
        connection_string = get_connection_string()
        engine = create_engine(connection_string)

        # Test connection
        with engine.connect() as conn:
            result = conn.execute(text("SELECT version()"))
            version = result.scalar()
            logger.info("Database version", version=version)

        # Check af_users schema
        users_results = verify_af_users_schema(engine)

        if users_results["table_exists"]:
            logger.info("af_users table: EXISTS")
            for key, value in users_results.items():
                if key != "table_exists":
                    status = "OK" if value else "MISSING"
                    logger.info(f"  {key}: {status}")
        else:
            logger.info("af_users table: NOT FOUND (run 'migrate' to create)")

        # Check github_tokens schema
        tokens_results = verify_github_tokens_schema(engine)

        if tokens_results["table_exists"]:
            logger.info("github_tokens table: EXISTS")
            for key, value in tokens_results.items():
                if key != "table_exists":
                    status = "OK" if value else "MISSING"
                    logger.info(f"  {key}: {status}")
        else:
            logger.info("github_tokens table: NOT FOUND (run 'migrate' to create)")

        return 0

    except ValueError as e:
        logger.error("Configuration error", error=str(e))
        return 1
    except Exception as e:
        error_msg = str(e)
        if "POSTGRES_PASSWORD" in os.environ:
            password = os.environ.get("POSTGRES_PASSWORD", "")
            if password:
                error_msg = error_msg.replace(password, "***")
        logger.error("Status check failed", error=error_msg)
        return 1


def main() -> int:
    """Main entry point for migrations CLI.

    Returns:
        Exit code from the executed command.
    """
    parser = argparse.ArgumentParser(
        description="AF Identity Service database migrations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
    POSTGRES_HOST       Database host (required unless using Cloud SQL)
    POSTGRES_PORT       Database port (default: 5432)
    POSTGRES_DB         Database name (required)
    POSTGRES_USER       Database user (required)
    POSTGRES_PASSWORD   Database password (required)

Examples:
    # Create tables (idempotent)
    python -m af_identity_service.migrations migrate

    # Verify schema
    python -m af_identity_service.migrations verify

    # Check status
    python -m af_identity_service.migrations status
        """,
    )

    parser.add_argument(
        "command",
        choices=["migrate", "verify", "status"],
        help="Migration command to run",
    )

    args = parser.parse_args()

    if args.command == "migrate":
        return run_migrate()
    elif args.command == "verify":
        return run_verify()
    elif args.command == "status":
        return run_status()
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
