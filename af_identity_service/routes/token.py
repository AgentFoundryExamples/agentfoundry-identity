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
"""Token introspection routes for Agent Foundry Identity Service.

This module provides the POST /v1/auth/token/introspect endpoint
for validating AF JWTs and returning token introspection payloads.
"""

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from af_identity_service.logging import (
    github_login_ctx,
    github_user_id_ctx,
    session_id_ctx,
    user_id_ctx,
)
from af_identity_service.models.token import AFTokenIntrospection
from af_identity_service.security.auth import (
    AuthenticationError,
    authenticate_request,
)
from af_identity_service.stores.session_store import SessionStore
from af_identity_service.stores.user_store import AFUserRepository

logger = structlog.get_logger(__name__)


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(..., description="Error type.")
    message: str = Field(..., description="Human-readable error message.")


def create_token_router(
    jwt_secret: str,
    session_store: SessionStore,
    user_repository: AFUserRepository,
) -> APIRouter:
    """Create the token introspection router.

    Args:
        jwt_secret: The secret for JWT validation.
        session_store: The session store for session validation.
        user_repository: The user repository for user retrieval.

    Returns:
        A FastAPI APIRouter with the token introspection endpoint.
    """
    router = APIRouter(prefix="/v1/auth/token", tags=["auth"])

    @router.post(
        "/introspect",
        response_model=AFTokenIntrospection,
        responses={
            200: {"description": "Token introspection successful"},
            401: {"description": "Invalid or expired token", "model": ErrorResponse},
        },
        summary="Introspect AF JWT token",
        description=(
            "Validates the provided AF JWT and returns introspection information "
            "including user identity and session details. Requires a valid Bearer token."
        ),
    )
    async def introspect_token(
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> AFTokenIntrospection:
        """Introspect the provided AF JWT token.

        Validates the token signature, expiration, and session status.
        Returns detailed information about the token holder.
        """
        try:
            auth_ctx = await authenticate_request(
                authorization=authorization,
                jwt_secret=jwt_secret,
                session_store=session_store,
                user_repository=user_repository,
            )
        except AuthenticationError as e:
            logger.debug(
                "token.introspect.failure",
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

        # Build introspection response using JWT expiry (not session expiry)
        # JWT expiry is typically shorter than session expiry
        jwt_expires_at = datetime.fromtimestamp(auth_ctx.claims.exp, tz=timezone.utc)
        introspection = AFTokenIntrospection(
            user_id=auth_ctx.user.id,
            github_login=auth_ctx.user.github_login,
            github_user_id=auth_ctx.user.github_user_id,
            session_id=auth_ctx.session.session_id,
            expires_at=jwt_expires_at,
        )

        logger.info(
            "token.introspect",
            af_user_id=str(auth_ctx.user.id),
            session_id=str(auth_ctx.session.session_id),
            github_user_id=auth_ctx.user.github_user_id,
            github_login=auth_ctx.user.github_login,
        )

        return introspection

    return router
