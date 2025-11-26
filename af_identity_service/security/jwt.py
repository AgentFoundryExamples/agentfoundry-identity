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
"""JWT minting and validation functionality for Agent Foundry Identity Service.

This module provides functions to mint and validate AF JWTs with specific claims
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


class JWTValidationError(Exception):
    """Raised when JWT validation fails.

    This exception is raised for any token validation failure including:
    - Malformed tokens
    - Invalid signature
    - Expired tokens
    - Missing required claims

    The error message is designed to be safe for client consumption
    and does not leak cryptographic details.
    """

    pass


class JWTExpiredError(JWTValidationError):
    """Raised when a JWT has expired.

    This is a specific subclass of JWTValidationError to allow
    short-circuiting validation before checking SessionStore.
    """

    pass


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes.

    Handles missing padding that is common in JWT tokens.

    Args:
        data: The base64url encoded string.

    Returns:
        Decoded bytes.

    Raises:
        JWTValidationError: If decoding fails.
    """
    # Add padding if necessary
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding

    try:
        return base64.urlsafe_b64decode(data)
    except Exception:
        raise JWTValidationError("Invalid token format")


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


class JWTClaims:
    """Validated JWT claims.

    This class holds the extracted claims from a validated JWT token.

    Attributes:
        user_id: The user's UUID from the 'sub' claim.
        session_id: The session's UUID from the 'sid' claim.
        exp: The expiration timestamp from the 'exp' claim.
        iat: The issued-at timestamp from the 'iat' claim.
    """

    def __init__(self, user_id: UUID, session_id: UUID, exp: int, iat: int) -> None:
        """Initialize JWT claims.

        Args:
            user_id: The user's UUID.
            session_id: The session's UUID.
            exp: The expiration Unix timestamp.
            iat: The issued-at Unix timestamp.
        """
        self.user_id = user_id
        self.session_id = session_id
        self.exp = exp
        self.iat = iat


def validate_af_jwt(
    token: str,
    secret: str,
    now: datetime | None = None,
) -> JWTClaims:
    """Validate an Agent Foundry JWT token.

    Verifies the token signature using HMAC-SHA256, checks expiration,
    and extracts claims.

    Args:
        token: The JWT token string to validate.
        secret: The IDENTITY_JWT_SECRET used for signature verification.
        now: Optional current time for expiration check. Defaults to UTC now.

    Returns:
        JWTClaims with the extracted and validated claims.

    Raises:
        JWTValidationError: If the token is malformed or has invalid signature.
        JWTExpiredError: If the token has expired (subclass of JWTValidationError).
    """
    if now is None:
        now = datetime.now(timezone.utc)

    # Split token into parts
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTValidationError("Invalid token format")

    header_b64, payload_b64, signature_b64 = parts

    # Verify signature first (without revealing timing information)
    signing_input = f"{header_b64}.{payload_b64}"
    expected_signature = _create_signature(signing_input, secret)

    if not hmac.compare_digest(signature_b64, expected_signature):
        raise JWTValidationError("Invalid token")

    # Decode header and verify algorithm
    try:
        header_bytes = _base64url_decode(header_b64)
        header = json.loads(header_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise JWTValidationError("Invalid token format")

    if header.get("alg") != "HS256":
        raise JWTValidationError("Unsupported token algorithm")

    # Decode payload
    try:
        payload_bytes = _base64url_decode(payload_b64)
        payload = json.loads(payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise JWTValidationError("Invalid token format")

    # Extract and validate required claims
    try:
        sub = payload.get("sub")
        sid = payload.get("sid")
        exp = payload.get("exp")
        iat = payload.get("iat")

        if not all([sub, sid, exp is not None, iat is not None]):
            raise JWTValidationError("Missing required claims")

        user_id = UUID(sub)
        session_id = UUID(sid)
        exp_int = int(exp)
        iat_int = int(iat)
    except (ValueError, TypeError):
        raise JWTValidationError("Invalid token claims")

    # Check expiration
    exp_datetime = datetime.fromtimestamp(exp_int, tz=timezone.utc)
    if now >= exp_datetime:
        raise JWTExpiredError("Token has expired")

    logger.debug(
        "Validated AF JWT",
        user_id=str(user_id),
        session_id=str(session_id),
    )

    return JWTClaims(
        user_id=user_id,
        session_id=session_id,
        exp=exp_int,
        iat=iat_int,
    )
