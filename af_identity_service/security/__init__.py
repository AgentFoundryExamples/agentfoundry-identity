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
"""Agent Foundry Identity Security.

This module exports security-related functionality for JWT minting,
validation, and request authentication.
"""

from af_identity_service.security.auth import (
    AuthenticatedContext,
    AuthenticationError,
    InvalidTokenError,
    MissingAuthorizationError,
    SessionNotFoundError,
    SessionOwnershipError,
    authenticate_request,
    parse_authorization_header,
    revoke_session,
)
from af_identity_service.security.jwt import (
    JWTClaims,
    JWTExpiredError,
    JWTMintError,
    JWTValidationError,
    mint_af_jwt,
    validate_af_jwt,
)

__all__ = [
    # JWT minting and validation
    "JWTClaims",
    "JWTExpiredError",
    "JWTMintError",
    "JWTValidationError",
    "mint_af_jwt",
    "validate_af_jwt",
    # Authentication
    "AuthenticatedContext",
    "AuthenticationError",
    "InvalidTokenError",
    "MissingAuthorizationError",
    "SessionNotFoundError",
    "SessionOwnershipError",
    "authenticate_request",
    "parse_authorization_header",
    "revoke_session",
]
