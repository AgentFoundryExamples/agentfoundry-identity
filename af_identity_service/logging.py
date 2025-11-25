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
"""Structlog configuration for the Identity Service.

This module configures structlog with:
- Service name ('af-identity-service') automatically added to all log entries
- Request ID correlation for tracing requests across log entries
- User ID placeholder for authenticated requests
- JSON or console output format based on configuration
"""

import logging
import sys
from contextvars import ContextVar
from typing import Any

import structlog

from af_identity_service import __service_name__
from af_identity_service.config import Settings

# Context variables for request-scoped logging
request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
user_id_ctx: ContextVar[str | None] = ContextVar("user_id", default=None)


def add_service_context(
    logger: logging.Logger, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Add service-level context to all log entries.

    Args:
        logger: The logger instance (unused).
        method_name: The logging method name (unused).
        event_dict: The event dictionary to modify.

    Returns:
        The modified event dictionary with service context.
    """
    event_dict["service"] = __service_name__
    return event_dict


def add_request_context(
    logger: logging.Logger, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Add request-level context to log entries.

    This processor adds request_id and af_user_id from context variables,
    ensuring all log entries within a request share the same correlation IDs.
    Only adds fields when they have actual values to keep logs clean.

    Args:
        logger: The logger instance (unused).
        method_name: The logging method name (unused).
        event_dict: The event dictionary to modify.

    Returns:
        The modified event dictionary with request context.
    """
    # Add request_id if available
    request_id = request_id_ctx.get()
    if request_id is not None:
        event_dict["request_id"] = request_id

    # Add user_id if available
    user_id = user_id_ctx.get()
    if user_id is not None:
        event_dict["af_user_id"] = user_id

    return event_dict


def configure_logging(settings: Settings) -> None:
    """Configure structlog for the Identity Service.

    This function sets up structlog with appropriate processors for
    JSON or console output, and configures the standard library logging
    to integrate with structlog.

    Args:
        settings: The service settings containing log configuration.
    """
    # Determine log level
    log_level = getattr(logging, settings.log_level, logging.INFO)

    # Common processors for all output formats
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        add_service_context,
        add_request_context,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if settings.log_format == "json":
        # JSON format for production
        processors: list[structlog.types.Processor] = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Console format for development
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging to use structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    # Set log level for uvicorn and other libraries
    logging.getLogger("uvicorn").setLevel(log_level)
    logging.getLogger("uvicorn.access").setLevel(log_level)
    logging.getLogger("uvicorn.error").setLevel(log_level)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structlog logger instance.

    Args:
        name: Optional logger name. If not provided, uses the caller's module.

    Returns:
        A bound structlog logger instance.
    """
    return structlog.get_logger(name)
