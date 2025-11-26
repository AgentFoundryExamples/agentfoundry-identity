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
"""JWT minting functionality for Agent Foundry Identity Service.

This module provides functions to mint AF JWTs with specific claims
for authenticated users with active sessions.
"""

import base64
import hmac
import json
from datetime import datetime, timezone
from uuid import UUID

import structlog

logger = structlog.get_logger(__name__)


class JWTMintError(Exception):
    """Raised when JWT minting fails."""

    pass


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding.

    Args:
        data: The bytes to encode.

    Returns:
        Base64url encoded string without padding.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _create_signature(payload: str, secret: str) -> str:
    """Create HMAC-SHA256 signature for the payload.

    Args:
        payload: The string to sign (header.payload).
        secret: The secret key for signing.

    Returns:
        Base64url encoded signature.
    """
    signature = hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        "sha256",
    ).digest()
    return _base64url_encode(signature)


def mint_af_jwt(
    secret: str,
    user_id: UUID,
    session_id: UUID,
    expires_at: datetime,
    issued_at: datetime | None = None,
) -> str:
    """Mint an Agent Foundry JWT token.

    Creates a JWT token with claims {sub: user_id, sid: session_id, exp, iat}.
    The token is signed using HMAC-SHA256 with the provided secret.

    Args:
        secret: The IDENTITY_JWT_SECRET for signing tokens.
        user_id: The user's UUID (becomes 'sub' claim).
        session_id: The session's UUID (becomes 'sid' claim).
        expires_at: When the token expires (must be timezone-aware UTC).
        issued_at: When the token was issued (defaults to now, must be UTC).

    Returns:
        A signed JWT token string.

    Raises:
        JWTMintError: If minting fails due to invalid parameters.
    """
    if not secret or len(secret) < 32:
        raise JWTMintError("Secret must be at least 32 characters")

    if issued_at is None:
        issued_at = datetime.now(timezone.utc)

    # Ensure datetimes are timezone-aware
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)

    # Build header
    header = {
        "alg": "HS256",
        "typ": "JWT",
    }

    # Build payload with claims
    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "exp": int(expires_at.timestamp()),
        "iat": int(issued_at.timestamp()),
    }

    # Encode header and payload
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))

    # Create signature
    signing_input = f"{header_b64}.{payload_b64}"
    signature = _create_signature(signing_input, secret)

    # Assemble JWT
    token = f"{signing_input}.{signature}"

    logger.debug(
        "Minted AF JWT",
        user_id=str(user_id),
        session_id=str(session_id),
        expires_at=expires_at.isoformat(),
    )

    return token
