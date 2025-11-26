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
"""GitHub identity models.

This module defines models for GitHub OAuth integration:
- GitHubIdentity: Pydantic model for GitHub user profile information
- GitHubOAuthResult: Data class for GitHub OAuth token operations
"""

from dataclasses import dataclass
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class GitHubIdentity(BaseModel):
    """GitHub user identity information.

    Represents the user profile data retrieved from GitHub's API
    after successful OAuth authentication.

    Attributes:
        github_user_id: The unique GitHub user ID.
        login: The GitHub username.
        avatar_url: URL to the user's GitHub avatar image, if available.
    """

    github_user_id: int = Field(..., description="GitHub user ID")
    login: str = Field(..., description="GitHub username")
    avatar_url: str | None = Field(default=None, description="URL to user's avatar image")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "github_user_id": 12345,
                    "login": "octocat",
                    "avatar_url": "https://avatars.githubusercontent.com/u/12345",
                }
            ]
        }
    }


@dataclass
class GitHubOAuthResult:
    """Result of GitHub OAuth token operations.

    Data class capturing the token data returned by the GitHub OAuth flow,
    including both access and refresh tokens with their expiration times.
    This is returned by the GitHubOAuthDriver interface methods.

    All datetime fields are normalized to UTC timezone-aware datetimes.
    If a naive datetime is provided, it is assumed to be UTC.

    Attributes:
        access_token: The GitHub access token.
        access_token_expires_at: Expiration time for the access token (UTC).
        refresh_token: The GitHub refresh token, if provided.
        refresh_token_expires_at: Expiration time for the refresh token (UTC), if provided.
    """

    access_token: str
    access_token_expires_at: datetime
    refresh_token: str | None = None
    refresh_token_expires_at: datetime | None = None

    def __post_init__(self) -> None:
        """Normalize datetime fields to UTC timezone-aware datetimes."""
        if self.access_token_expires_at.tzinfo is None:
            object.__setattr__(
                self,
                "access_token_expires_at",
                self.access_token_expires_at.replace(tzinfo=timezone.utc),
            )
        if (
            self.refresh_token_expires_at is not None
            and self.refresh_token_expires_at.tzinfo is None
        ):
            object.__setattr__(
                self,
                "refresh_token_expires_at",
                self.refresh_token_expires_at.replace(tzinfo=timezone.utc),
            )
