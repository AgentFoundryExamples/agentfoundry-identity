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
validation, request authentication, and token encryption.
"""

from af_identity_service.security.auth import (
    AuthenticatedContext,
    AuthenticationError,
    AuthRequired,
    InvalidTokenError,
    MissingAuthorizationError,
    SessionNotFoundError,
    SessionOwnershipError,
    authenticate_request,
    create_auth_dependency,
    parse_authorization_header,
    revoke_session,
)
from af_identity_service.security.crypto import (
    AES256GCMEncryptor,
    DecryptionError,
    EncryptionKeyError,
    NoOpEncryptor,
    TokenEncryptionError,
    TokenEncryptor,
    get_token_encryptor,
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
    "AuthRequired",
    "InvalidTokenError",
    "MissingAuthorizationError",
    "SessionNotFoundError",
    "SessionOwnershipError",
    "authenticate_request",
    "create_auth_dependency",
    "parse_authorization_header",
    "revoke_session",
    # Token Encryption
    "TokenEncryptor",
    "AES256GCMEncryptor",
    "NoOpEncryptor",
    "TokenEncryptionError",
    "EncryptionKeyError",
    "DecryptionError",
    "get_token_encryptor",
]
