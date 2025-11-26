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
"""AFUser model definition.

This module defines the AFUser Pydantic model which represents
a user in the Agent Foundry identity system. All datetime fields
are timezone-aware and serialized in UTC.
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AFUser(BaseModel):
    """Agent Foundry User model.

    Represents a user in the AF identity system. Users are uniquely
    identified by their UUID. The github_user_id and github_login
    fields are optional and populated after GitHub OAuth authentication.

    All datetime fields are timezone-aware UTC timestamps.

    Attributes:
        id: Unique identifier for the user (UUID4).
        github_user_id: The GitHub user ID if linked, None otherwise.
        github_login: The GitHub username if linked, None otherwise.
        created_at: Timestamp when the user was created (UTC).
        updated_at: Timestamp when the user was last updated (UTC).
    """

    id: UUID = Field(default_factory=uuid4, description="Unique user identifier (UUID4)")
    github_user_id: int | None = Field(
        default=None, description="GitHub user ID if linked via OAuth"
    )
    github_login: str | None = Field(
        default=None, description="GitHub username if linked via OAuth"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the user was created (UTC)",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the user was last updated (UTC)",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "github_user_id": 12345,
                    "github_login": "octocat",
                    "created_at": "2025-01-01T12:00:00Z",
                    "updated_at": "2025-01-01T12:00:00Z",
                }
            ]
        }
    }
