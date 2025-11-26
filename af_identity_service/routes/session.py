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
"""Session management routes for Agent Foundry Identity Service.

This module provides the POST /v1/auth/session/revoke endpoint
for revoking sessions.
"""

import structlog
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from af_identity_service.logging import (
    github_login_ctx,
    github_user_id_ctx,
    session_id_ctx,
    user_id_ctx,
)
from af_identity_service.security.auth import (
    AuthenticationError,
    SessionNotFoundError,
    SessionOwnershipError,
    authenticate_request,
    revoke_session,
)
from af_identity_service.stores.session_store import SessionStore
from af_identity_service.stores.user_store import AFUserRepository

logger = structlog.get_logger(__name__)


class RevokeSessionRequest(BaseModel):
    """Request body for POST /v1/auth/session/revoke."""

    session_id: str = Field(
        ...,
        description="The session ID to revoke. Use 'current' to revoke the current session.",
        examples=["550e8400-e29b-41d4-a716-446655440000", "current"],
    )


class RevokeSessionResponse(BaseModel):
    """Response body for POST /v1/auth/session/revoke."""

    status: str = Field(..., description="Operation status.")
    session_id: str = Field(..., description="The ID of the revoked session.")


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(..., description="Error type.")
    message: str = Field(..., description="Human-readable error message.")


def create_session_router(
    jwt_secret: str,
    session_store: SessionStore,
    user_repository: AFUserRepository,
) -> APIRouter:
    """Create the session management router.

    Args:
        jwt_secret: The secret for JWT validation.
        session_store: The session store for session operations.
        user_repository: The user repository for user retrieval.

    Returns:
        A FastAPI APIRouter with session management endpoints.
    """
    router = APIRouter(prefix="/v1/auth/session", tags=["auth"])

    @router.post(
        "/revoke",
        response_model=RevokeSessionResponse,
        responses={
            200: {"description": "Session revoked successfully"},
            401: {"description": "Invalid or expired token", "model": ErrorResponse},
            403: {"description": "Session does not belong to user", "model": ErrorResponse},
            404: {"description": "Session not found", "model": ErrorResponse},
        },
        summary="Revoke a session",
        description=(
            "Revokes the specified session, invalidating any tokens associated with it. "
            "Use 'current' as session_id to revoke the current session (logout). "
            "Users can only revoke their own sessions. "
            "Requires a valid Bearer token."
        ),
    )
    async def revoke_session_endpoint(
        request: RevokeSessionRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> RevokeSessionResponse:
        """Revoke a session.

        Authenticates the request and revokes the specified session.
        This operation is idempotent - revoking an already revoked session
        will still return success.
        """
        # Authenticate the request
        try:
            auth_ctx = await authenticate_request(
                authorization=authorization,
                jwt_secret=jwt_secret,
                session_store=session_store,
                user_repository=user_repository,
            )
        except AuthenticationError as e:
            logger.debug(
                "session.revoke.auth_failure",
                error_code=e.error_code,
            )
            raise HTTPException(
                status_code=401,
                detail={"error": e.error_code, "message": e.message},
            )

        # Set logging context for all subsequent logs in this request
        user_id_ctx.set(str(auth_ctx.user.id))
        session_id_ctx.set(str(auth_ctx.session.session_id))
        if auth_ctx.user.github_user_id is not None:
            github_user_id_ctx.set(auth_ctx.user.github_user_id)
        if auth_ctx.user.github_login is not None:
            github_login_ctx.set(auth_ctx.user.github_login)

        # Revoke the session
        try:
            _, resolved_session_id = await revoke_session(
                session_id=request.session_id,
                current_session_id=auth_ctx.session.session_id,
                current_user_id=auth_ctx.user.id,
                session_store=session_store,
            )
        except SessionNotFoundError as e:
            logger.debug(
                "session.revoke.not_found",
                requested_session_id=request.session_id,
            )
            raise HTTPException(
                status_code=404,
                detail={"error": e.error_code, "message": e.message},
            )
        except SessionOwnershipError as e:
            logger.warning(
                "session.revoke.ownership_denied",
                requested_session_id=request.session_id,
            )
            raise HTTPException(
                status_code=403,
                detail={"error": e.error_code, "message": e.message},
            )
        except ValueError as e:
            logger.debug(
                "session.revoke.invalid_format",
                requested_session_id=request.session_id,
                error=str(e),
            )
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_session_id", "message": str(e)},
            )

        logger.info(
            "session.revoked",
            af_user_id=str(auth_ctx.user.id),
            revoked_session_id=str(resolved_session_id),
            requested_session_id=request.session_id,
        )

        return RevokeSessionResponse(
            status="ok",
            session_id=str(resolved_session_id),
        )

    return router
