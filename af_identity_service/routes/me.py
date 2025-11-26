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
"""User profile route for Agent Foundry Identity Service.

This module provides the GET /v1/me endpoint for authenticated users
to retrieve their profile information.
"""

import structlog
from fastapi import APIRouter, Depends
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
from af_identity_service.stores.session_store import SessionStore
from af_identity_service.stores.user_store import AFUserRepository

logger = structlog.get_logger(__name__)


class MeResponse(BaseModel):
    """Response body for GET /v1/me."""

    id: str = Field(
        ...,
        description="The user's UUID.",
    )
    github_login: str | None = Field(
        None,
        description="The user's GitHub username if linked.",
    )
    github_user_id: int | None = Field(
        None,
        description="The user's GitHub user ID if linked.",
    )
    linked_providers: list[str] = Field(
        ...,
        description="List of linked identity providers.",
    )


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(..., description="Error type.")
    message: str = Field(..., description="Human-readable error message.")


def create_me_router(
    jwt_secret: str,
    session_store: SessionStore,
    user_repository: AFUserRepository,
) -> APIRouter:
    """Create the user profile router.

    Args:
        jwt_secret: The secret for JWT validation.
        session_store: The session store for session validation.
        user_repository: The user repository for user retrieval.

    Returns:
        A FastAPI APIRouter with the /v1/me endpoint.
    """
    router = APIRouter(prefix="/v1", tags=["user"])

    # Create auth dependency
    auth_required = create_auth_dependency(
        jwt_secret=jwt_secret,
        session_store=session_store,
        user_repository=user_repository,
    )

    @router.get(
        "/me",
        response_model=MeResponse,
        responses={
            200: {"description": "User profile retrieved successfully"},
            401: {"description": "Invalid or expired token", "model": ErrorResponse},
        },
        summary="Get current user profile",
        description=(
            "Returns the authenticated user's profile information including "
            "linked identity providers."
        ),
    )
    async def get_me(
        auth: AuthenticatedContext = Depends(auth_required),
    ) -> MeResponse:
        """Get the authenticated user's profile.

        Returns basic profile information and list of linked providers.
        """
        # Set logging context
        user_id_ctx.set(str(auth.user.id))
        session_id_ctx.set(str(auth.session.session_id))
        if auth.user.github_user_id is not None:
            github_user_id_ctx.set(auth.user.github_user_id)
        if auth.user.github_login is not None:
            github_login_ctx.set(auth.user.github_login)

        # Build linked providers list
        linked_providers: list[str] = []
        if auth.user.github_user_id is not None:
            linked_providers.append("github")

        logger.info(
            "user.profile.retrieved",
            af_user_id=str(auth.user.id),
            github_user_id=auth.user.github_user_id,
            linked_providers=linked_providers,
        )

        return MeResponse(
            id=str(auth.user.id),
            github_login=auth.user.github_login,
            github_user_id=auth.user.github_user_id,
            linked_providers=linked_providers,
        )

    return router
