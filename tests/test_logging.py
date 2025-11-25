# SPDX-License-Identifier: GPL-3.0-only
"""Tests for logging configuration and middleware."""

import json
import os
import uuid
from io import StringIO
from unittest.mock import patch

import pytest
import structlog

from af_identity_service import __service__
from af_identity_service.logging import (
    REQUEST_ID_HEADER,
    add_service_context,
    configure_logging,
    get_logger,
    request_id_var,
)


class TestServiceContext:
    """Tests for service context injection."""

    def test_add_service_context_adds_service_name(self) -> None:
        """Test that add_service_context adds service name to logs."""
        event_dict: dict = {"event": "test"}
        result = add_service_context(None, "info", event_dict)

        assert result["service"] == __service__

    def test_add_service_context_adds_request_id_when_set(self) -> None:
        """Test that add_service_context adds request_id when in context."""
        test_id = "test-request-123"
        token = request_id_var.set(test_id)
        try:
            event_dict: dict = {"event": "test"}
            result = add_service_context(None, "info", event_dict)

            assert result["request_id"] == test_id
        finally:
            request_id_var.reset(token)

    def test_add_service_context_no_request_id_when_not_set(self) -> None:
        """Test that add_service_context doesn't add request_id when not set."""
        # Ensure request_id is not set
        token = request_id_var.set(None)
        try:
            event_dict: dict = {"event": "test"}
            result = add_service_context(None, "info", event_dict)

            assert "request_id" not in result
        finally:
            request_id_var.reset(token)


class TestConfigureLogging:
    """Tests for logging configuration."""

    def test_configure_logging_sets_up_structlog(self) -> None:
        """Test that configure_logging properly configures structlog."""
        configure_logging()

        # Get a logger and verify it works
        logger = get_logger("test")
        assert logger is not None

    def test_get_logger_returns_bound_logger(self) -> None:
        """Test that get_logger returns a structlog logger."""
        configure_logging()
        logger = get_logger("test_module")

        assert logger is not None


class TestRequestIdHeader:
    """Tests for request ID header constant."""

    def test_request_id_header_value(self) -> None:
        """Test that REQUEST_ID_HEADER has the correct value."""
        assert REQUEST_ID_HEADER == "X-Request-ID"


class TestRequestIdContextVar:
    """Tests for request_id context variable."""

    def test_request_id_var_default_is_none(self) -> None:
        """Test that request_id_var defaults to None."""
        # Get value in fresh context
        assert request_id_var.get() is None

    def test_request_id_var_can_be_set_and_retrieved(self) -> None:
        """Test that request_id_var can be set and retrieved."""
        test_id = str(uuid.uuid4())
        token = request_id_var.set(test_id)
        try:
            assert request_id_var.get() == test_id
        finally:
            request_id_var.reset(token)

    def test_request_id_var_reset_clears_value(self) -> None:
        """Test that resetting request_id_var clears the value."""
        test_id = "test-id"
        token = request_id_var.set(test_id)
        request_id_var.reset(token)

        assert request_id_var.get() is None
