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

This module defines Pydantic models for GitHub OAuth integration:
- GitHubIdentity: GitHub user profile information
- GitHubOAuthResult: Result of GitHub OAuth token operations
"""

from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator


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


class GitHubOAuthResult(BaseModel):
    """Result of GitHub OAuth token operations.

    Captures the token data returned by the GitHub OAuth flow,
    including both access and refresh tokens with their expiration times.
    This is returned by the GitHubOAuthDriver interface methods.

    Attributes:
        access_token: The GitHub access token.
        access_token_expires_at: Expiration time for the access token (UTC).
        refresh_token: The GitHub refresh token, if provided.
        refresh_token_expires_at: Expiration time for the refresh token (UTC), if provided.
    """

    access_token: str = Field(..., description="GitHub access token")
    access_token_expires_at: datetime = Field(
        ..., description="Access token expiration time (UTC)"
    )
    refresh_token: str | None = Field(
        default=None, description="GitHub refresh token, if provided"
    )
    refresh_token_expires_at: datetime | None = Field(
        default=None, description="Refresh token expiration time (UTC), if provided"
    )

    @field_validator("access_token_expires_at", mode="after")
    @classmethod
    def validate_access_token_timezone(cls, v: datetime) -> datetime:
        """Validate that access_token_expires_at is timezone-aware.

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

    @field_validator("refresh_token_expires_at", mode="after")
    @classmethod
    def validate_refresh_token_timezone(cls, v: datetime | None) -> datetime | None:
        """Validate that refresh_token_expires_at is timezone-aware if set.

        If a naive datetime is provided, it is assumed to be UTC and
        converted to a timezone-aware datetime.

        Args:
            v: The datetime value to validate, or None.

        Returns:
            A timezone-aware datetime (UTC), or None if not set.
        """
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "access_token": "gho_xxxxx",
                    "access_token_expires_at": "2025-01-01T13:00:00Z",
                    "refresh_token": "ghr_xxxxx",
                    "refresh_token_expires_at": "2025-07-01T12:00:00Z",
                }
            ]
        }
    }
