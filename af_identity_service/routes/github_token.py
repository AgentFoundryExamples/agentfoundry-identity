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
"""GitHub token distribution route for Agent Foundry Identity Service.

This module provides the POST /v1/github/token endpoint for internal
AF services to request GitHub access tokens on behalf of authenticated users.
"""

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from af_identity_service.logging import (
    github_login_ctx,
    github_user_id_ctx,
    session_id_ctx,
    user_id_ctx,
)
from af_identity_service.security.auth import (
    AuthenticatedContext,
    create_auth_dependency,
)
from af_identity_service.services.github_tokens import (
    GitHubTokenService,
    RefreshTokenMissingError,
    TokenRefreshError,
)
from af_identity_service.stores.session_store import SessionStore
from af_identity_service.stores.user_store import AFUserRepository

logger = structlog.get_logger(__name__)


class GitHubTokenRequest(BaseModel):
    """Request body for POST /v1/github/token."""

    force_refresh: bool = Field(
        default=False,
        description="If true, bypass cache and always request a new token from GitHub.",
    )


class GitHubTokenResponse(BaseModel):
    """Response body for POST /v1/github/token."""

    access_token: str = Field(
        ...,
        description="GitHub access token for API calls.",
    )
    expires_at: str = Field(
        ...,
        description="ISO 8601 timestamp when the token expires.",
    )


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(..., description="Error type.")
    message: str = Field(..., description="Human-readable error message.")


def create_github_token_router(
    jwt_secret: str,
    session_store: SessionStore,
    user_repository: AFUserRepository,
    github_token_service: GitHubTokenService,
) -> APIRouter:
    """Create the GitHub token distribution router.

    Args:
        jwt_secret: The secret for JWT validation.
        session_store: The session store for session validation.
        user_repository: The user repository for user retrieval.
        github_token_service: Service for GitHub token operations.

    Returns:
        A FastAPI APIRouter with the GitHub token endpoint.
    """
    router = APIRouter(prefix="/v1/github", tags=["github"])

    # Create auth dependency
    auth_required = create_auth_dependency(
        jwt_secret=jwt_secret,
        session_store=session_store,
        user_repository=user_repository,
    )

    @router.post(
        "/token",
        response_model=GitHubTokenResponse,
        responses={
            200: {"description": "GitHub token retrieved successfully"},
            401: {"description": "Invalid or expired AF JWT", "model": ErrorResponse},
            404: {
                "description": "GitHub linking incomplete (no refresh token)",
                "model": ErrorResponse,
            },
            502: {"description": "GitHub service error", "model": ErrorResponse},
        },
        summary="Get GitHub access token",
        description=(
            "Returns a GitHub access token for the authenticated user. "
            "Tokens are cached server-side and reused when valid. "
            "Use force_refresh=true to bypass cache and request a fresh token. "
            "This endpoint is intended for internal AF service use."
        ),
    )
    async def get_github_token(
        request: GitHubTokenRequest = GitHubTokenRequest(),
        auth: AuthenticatedContext = Depends(auth_required),
    ) -> GitHubTokenResponse:
        """Get a GitHub access token for the authenticated user.

        Validates the AF JWT, checks for stored refresh tokens,
        and returns a valid GitHub access token, refreshing if needed.
        """
        # Set logging context
        user_id_ctx.set(str(auth.user.id))
        session_id_ctx.set(str(auth.session.session_id))
        if auth.user.github_user_id is not None:
            github_user_id_ctx.set(auth.user.github_user_id)
        if auth.user.github_login is not None:
            github_login_ctx.set(auth.user.github_login)

        try:
            result = await github_token_service.get_access_token(
                user_id=auth.user.id,
                force_refresh=request.force_refresh,
            )
        except RefreshTokenMissingError:
            logger.warning(
                "github.token.request.failure",
                af_user_id=str(auth.user.id),
                reason="refresh_token_missing",
            )
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "github_not_linked",
                    "message": "GitHub account not linked. Please complete GitHub OAuth.",
                },
            )
        except TokenRefreshError:
            logger.error(
                "github.token.request.failure",
                af_user_id=str(auth.user.id),
                reason="refresh_failed",
            )
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "github_error",
                    "message": "Failed to refresh GitHub token. Please try again.",
                },
            )

        logger.info(
            "github.token.request.success",
            af_user_id=str(auth.user.id),
            github_user_id=auth.user.github_user_id,
            force_refresh=request.force_refresh,
        )

        return GitHubTokenResponse(
            access_token=result.access_token,
            expires_at=result.expires_at.isoformat(),
        )

    return router
