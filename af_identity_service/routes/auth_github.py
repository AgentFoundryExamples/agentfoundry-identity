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
"""GitHub OAuth routes for Agent Foundry Identity Service.

This module provides the POST /v1/auth/github/start and POST /v1/auth/github/callback
endpoints for GitHub OAuth authentication flow.
"""

import structlog
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from af_identity_service.services.oauth import (
    GitHubDriverError,
    InvalidStateError,
    OAuthService,
)

logger = structlog.get_logger(__name__)


class StartRequest(BaseModel):
    """Request body for POST /v1/auth/github/start."""

    redirect_uri: str = Field(
        ...,
        description="The URI to redirect to after GitHub authorization.",
        min_length=1,
    )


class StartResponse(BaseModel):
    """Response body for POST /v1/auth/github/start."""

    authorization_url: str = Field(
        ...,
        description="The GitHub authorization URL to redirect the user to.",
    )
    state: str = Field(
        ...,
        description="The state token for CSRF protection. Store this to validate callbacks.",
    )


class CallbackRequest(BaseModel):
    """Request body for POST /v1/auth/github/callback."""

    code: str = Field(
        ...,
        description="The authorization code from GitHub.",
        min_length=1,
    )
    state: str = Field(
        ...,
        description="The state token from the callback URL.",
        min_length=1,
    )


class CallbackUserResponse(BaseModel):
    """User info returned in callback response."""

    id: str = Field(..., description="The user's UUID.")
    github_login: str | None = Field(None, description="The user's GitHub username.")
    github_user_id: int | None = Field(None, description="The user's GitHub user ID.")


class CallbackResponse(BaseModel):
    """Response body for POST /v1/auth/github/callback."""

    af_token: str = Field(
        ...,
        description="The Agent Foundry JWT token for authentication.",
    )
    user: CallbackUserResponse = Field(
        ...,
        description="The authenticated user's information.",
    )


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(..., description="Error type.")
    message: str = Field(..., description="Human-readable error message.")


def create_auth_github_router(oauth_service: OAuthService) -> APIRouter:
    """Create the GitHub OAuth router.

    Args:
        oauth_service: The OAuth service for handling authentication.

    Returns:
        A FastAPI APIRouter with the GitHub OAuth endpoints.
    """
    router = APIRouter(prefix="/v1/auth/github", tags=["auth"])

    @router.post(
        "/start",
        response_model=StartResponse,
        responses={
            200: {"description": "Authorization URL generated successfully"},
            400: {"description": "Invalid request", "model": ErrorResponse},
        },
        summary="Start GitHub OAuth flow",
        description=(
            "Generates a GitHub authorization URL and state token. "
            "The client should redirect the user to the authorization URL. "
            "The state token must be stored and passed back to the callback endpoint."
        ),
    )
    async def start_oauth(request: StartRequest) -> StartResponse:
        """Start the GitHub OAuth flow.

        Generates a secure state token and returns a GitHub authorization URL.
        The client must redirect the user to this URL to initiate authentication.
        """
        result = await oauth_service.start_oauth(request.redirect_uri)
        return StartResponse(
            authorization_url=result.authorization_url,
            state=result.state,
        )

    @router.post(
        "/callback",
        response_model=CallbackResponse,
        responses={
            200: {"description": "Authentication successful"},
            400: {"description": "Invalid state or request", "model": ErrorResponse},
            502: {"description": "GitHub service error", "model": ErrorResponse},
        },
        summary="Handle GitHub OAuth callback",
        description=(
            "Completes the GitHub OAuth flow by exchanging the authorization code "
            "for tokens, upserting the user, creating a session, and minting a JWT. "
            "GitHub tokens are stored securely and never exposed to the client."
        ),
    )
    async def callback(request: CallbackRequest) -> JSONResponse:
        """Handle GitHub OAuth callback.

        Validates the state token, exchanges the authorization code for tokens,
        upserts the user record, stores tokens securely, creates a session,
        and returns an AF JWT for authentication.
        """
        try:
            result = await oauth_service.handle_callback(
                code=request.code,
                state=request.state,
            )
        except InvalidStateError as e:
            logger.warning("OAuth callback failed: invalid state", error=str(e))
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_state", "message": str(e)},
            )
        except GitHubDriverError as e:
            logger.error("OAuth callback failed: GitHub driver error", error=str(e))
            raise HTTPException(
                status_code=502,
                detail={"error": "github_error", "message": str(e)},
            )

        return JSONResponse(
            status_code=200,
            content={
                "af_token": result.af_token,
                "user": {
                    "id": str(result.user.id),
                    "github_login": result.user.github_login,
                    "github_user_id": result.user.github_user_id,
                },
            },
        )

    return router
