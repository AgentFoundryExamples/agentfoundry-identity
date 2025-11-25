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
"""Session model definition.

This module defines the Session Pydantic model which represents
a user session in the Agent Foundry identity system. Includes helper
methods for revocation and expiry checks.
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Session(BaseModel):
    """User session model.

    Represents an authenticated user session. Sessions are identified
    by a UUID and linked to a user. Sessions can be revoked and have
    an expiration time.

    All datetime fields are timezone-aware UTC timestamps.

    Attributes:
        session_id: Unique identifier for the session (UUID4).
        user_id: The UUID of the user this session belongs to.
        created_at: Timestamp when the session was created (UTC).
        expires_at: Timestamp when the session expires (UTC).
        revoked: Whether the session has been explicitly revoked.
    """

    session_id: UUID = Field(
        default_factory=uuid4, description="Unique session identifier (UUID4)"
    )
    user_id: UUID = Field(..., description="UUID of the user this session belongs to")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the session was created (UTC)",
    )
    expires_at: datetime = Field(..., description="Timestamp when the session expires (UTC)")
    revoked: bool = Field(default=False, description="Whether the session has been revoked")

    def is_revoked(self) -> bool:
        """Check if the session has been revoked.

        Returns:
            True if the session has been explicitly revoked, False otherwise.
        """
        return self.revoked

    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if the session has expired.

        Args:
            now: Optional current time for comparison. If not provided,
                 uses the current UTC time. Must be timezone-aware.

        Returns:
            True if the session has expired, False otherwise.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        return now >= self.expires_at

    def is_active(self, now: datetime | None = None) -> bool:
        """Check if the session is active (not revoked and not expired).

        Args:
            now: Optional current time for comparison. If not provided,
                 uses the current UTC time. Must be timezone-aware.

        Returns:
            True if the session is active, False otherwise.
        """
        return not self.is_revoked() and not self.is_expired(now)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "session_id": "550e8400-e29b-41d4-a716-446655440000",
                    "user_id": "660e8400-e29b-41d4-a716-446655440001",
                    "created_at": "2025-01-01T12:00:00Z",
                    "expires_at": "2025-01-02T12:00:00Z",
                    "revoked": False,
                }
            ]
        }
    }
