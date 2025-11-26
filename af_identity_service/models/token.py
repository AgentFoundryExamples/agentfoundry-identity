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
"""Token introspection model definition.

This module defines the AFTokenIntrospection Pydantic model which
is the response format for AF token introspection endpoints.
"""

from datetime import datetime, timezone
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class AFTokenIntrospection(BaseModel):
    """AF Token introspection response model.

    This model is exposed for token introspection API responses,
    providing information about the token holder and their session.

    All datetime fields are timezone-aware UTC timestamps.

    Attributes:
        user_id: The UUID of the authenticated user.
        github_login: The GitHub username if the user is linked via OAuth.
        github_user_id: The GitHub user ID if the user is linked via OAuth.
        session_id: The UUID of the active session.
        expires_at: Timestamp when the token/session expires (UTC).
    """

    user_id: UUID = Field(..., description="UUID of the authenticated user")
    github_login: str | None = Field(
        default=None, description="GitHub username if linked via OAuth"
    )
    github_user_id: int | None = Field(
        default=None, description="GitHub user ID if linked via OAuth"
    )
    session_id: UUID = Field(..., description="UUID of the active session")
    expires_at: datetime = Field(
        ..., description="Timestamp when the token/session expires (UTC)"
    )

    @field_validator("expires_at", mode="after")
    @classmethod
    def validate_timezone_aware(cls, v: datetime) -> datetime:
        """Validate that expires_at is timezone-aware.

        If a naive datetime is provided, it is assumed to be UTC and
        converted to a timezone-aware datetime.

        Args:
            v: The datetime value to validate.

        Returns:
            A timezone-aware datetime (UTC).
        """
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "user_id": "550e8400-e29b-41d4-a716-446655440000",
                    "github_login": "octocat",
                    "github_user_id": 12345,
                    "session_id": "660e8400-e29b-41d4-a716-446655440001",
                    "expires_at": "2025-01-02T12:00:00Z",
                }
            ]
        }
    }
