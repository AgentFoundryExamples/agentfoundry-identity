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
"""Admin routes for Agent Foundry Identity Service.

This module provides admin debugging endpoints that are gated behind
the ADMIN_TOOLS_ENABLED environment flag. When disabled, these
endpoints return 404 to avoid information disclosure.
"""

from uuid import UUID

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
from af_identity_service.stores.session_store import SessionStore
from af_identity_service.stores.user_store import AFUserRepository

logger = structlog.get_logger(__name__)


class SessionInfo(BaseModel):
    """Session information for admin endpoints."""

    session_id: str = Field(..., description="The session's UUID.")
    created_at: str = Field(..., description="ISO 8601 timestamp when the session was created.")
    expires_at: str = Field(..., description="ISO 8601 timestamp when the session expires.")
    revoked: bool = Field(..., description="Whether the session has been revoked.")
    is_active: bool = Field(..., description="Whether the session is currently active.")


class UserSessionsResponse(BaseModel):
    """Response body for admin session listing."""

    user_id: str = Field(..., description="The user's UUID.")
    sessions: list[SessionInfo] = Field(..., description="List of sessions for the user.")


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(..., description="Error type.")
    message: str = Field(..., description="Human-readable error message.")


def create_admin_router(
    jwt_secret: str,
    session_store: SessionStore,
    user_repository: AFUserRepository,
    admin_enabled: bool,
) -> APIRouter:
    """Create the admin router.

    Args:
        jwt_secret: The secret for JWT validation.
        session_store: The session store for session operations.
        user_repository: The user repository for user retrieval.
        admin_enabled: Whether admin endpoints are enabled.

    Returns:
        A FastAPI APIRouter with admin endpoints (or 404 when disabled).
    """
    router = APIRouter(prefix="/v1/admin", tags=["admin"])

    # Create a dependency that checks admin_enabled BEFORE authentication
    # This ensures 404 is returned instead of 401 when admin tools are disabled
    def check_admin_enabled() -> None:
        """Check if admin tools are enabled before processing request."""
        if not admin_enabled:
            raise HTTPException(status_code=404, detail="Not found")

    # Create auth dependency
    auth_required = create_auth_dependency(
        jwt_secret=jwt_secret,
        session_store=session_store,
        user_repository=user_repository,
    )

    @router.get(
        "/users/{user_id}/sessions",
        response_model=UserSessionsResponse,
        responses={
            200: {"description": "Sessions retrieved successfully"},
            401: {"description": "Invalid or expired token", "model": ErrorResponse},
            404: {"description": "Not found or admin tools disabled", "model": ErrorResponse},
        },
        summary="List sessions for a user (admin)",
        description=(
            "Lists all sessions for a specified user. "
            "This endpoint is only available when ADMIN_TOOLS_ENABLED is true. "
            "Intended for debugging and diagnostics."
        ),
        dependencies=[Depends(check_admin_enabled)],
    )
    async def list_user_sessions(
        user_id: str,
        include_inactive: bool = False,
        auth: AuthenticatedContext = Depends(auth_required),
    ) -> UserSessionsResponse:
        """List all sessions for a user.

        Returns session diagnostics for the specified user.
        Only available when admin tools are enabled.
        """
        # Set logging context
        user_id_ctx.set(str(auth.user.id))
        session_id_ctx.set(str(auth.session.session_id))
        if auth.user.github_user_id is not None:
            github_user_id_ctx.set(auth.user.github_user_id)
        if auth.user.github_login is not None:
            github_login_ctx.set(auth.user.github_login)

        # Parse user_id
        try:
            target_user_id = UUID(user_id)
        except ValueError:
            raise HTTPException(
                status_code=404,
                detail="Not found",
            )

        # Get sessions for the user
        sessions = await session_store.list_by_user(
            user_id=target_user_id,
            include_inactive=include_inactive,
        )

        # Build response
        session_infos = [
            SessionInfo(
                session_id=str(s.session_id),
                created_at=s.created_at.isoformat(),
                expires_at=s.expires_at.isoformat(),
                revoked=s.revoked,
                is_active=s.is_active(),
            )
            for s in sessions
        ]

        logger.info(
            "admin.sessions.retrieved",
            af_user_id=str(auth.user.id),
            target_user_id=user_id,
            session_count=len(sessions),
            include_inactive=include_inactive,
        )

        return UserSessionsResponse(
            user_id=user_id,
            sessions=session_infos,
        )

    return router
