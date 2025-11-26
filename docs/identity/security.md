# Security and Authentication

This document describes the authentication mechanisms, token introspection, and session management features of the Agent Foundry Identity Service.

## Overview

The Identity Service provides JWT-based authentication with session management. The system ensures:

- Secure JWT signing and validation using HMAC-SHA256
- Session-bound tokens that can be revoked at any time
- Structured error responses without leaking cryptographic details
- Request-scoped logging with user and session context

## JWT Format

AF JWTs are standard JWT tokens with the following claims:

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | UUID | The user's unique identifier |
| `sid` | UUID | The session's unique identifier |
| `exp` | int | Expiration timestamp (Unix epoch) |
| `iat` | int | Issued-at timestamp (Unix epoch) |

JWTs are signed using HMAC-SHA256 with the `IDENTITY_JWT_SECRET` environment variable.

## Authentication Flow

### 1. Obtain a Token

Tokens are obtained through the GitHub OAuth flow:

```http
POST /v1/auth/github/start
Content-Type: application/json

{
  "redirect_uri": "https://your-app.com/callback"
}
```

After completing the OAuth flow at the returned URL, exchange the code:

```http
POST /v1/auth/github/callback
Content-Type: application/json

{
  "code": "<github_auth_code>",
  "state": "<state_from_start>"
}
```

Response:
```json
{
  "af_token": "<jwt_token>",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "github_login": "octocat",
    "github_user_id": 12345
  }
}
```

### 2. Using the Token

Include the token in the `Authorization` header:

```http
Authorization: Bearer <af_token>
```

## Token Introspection

### POST /v1/auth/token/introspect

Validates a token and returns information about the authenticated user and session.

**Request:**
```http
POST /v1/auth/token/introspect
Authorization: Bearer <af_token>
```

**Success Response (200):**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "github_login": "octocat",
  "github_user_id": 12345,
  "session_id": "660e8400-e29b-41d4-a716-446655440001",
  "expires_at": "2025-01-02T12:00:00Z"
}
```

**Error Responses:**

| Status | Error Code | Description |
|--------|------------|-------------|
| 401 | `missing_authorization` | Authorization header missing or malformed |
| 401 | `invalid_token` | Token is invalid, expired, or session is revoked |
| 401 | `session_not_found` | Session does not exist |

**Example Error Response:**
```json
{
  "detail": {
    "error": "invalid_token",
    "message": "Token has expired"
  }
}
```

### Downstream Service Usage

AF services can use token introspection to validate incoming requests:

```python
import httpx

async def validate_token(token: str) -> dict:
    """Validate an AF token against the identity service."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://identity.agentfoundry.example/v1/auth/token/introspect",
            headers={"Authorization": f"Bearer {token}"}
        )
        if response.status_code != 200:
            raise AuthenticationError(response.json()["detail"])
        return response.json()
```

## Session Revocation

### POST /v1/auth/session/revoke

Revokes a session, invalidating all tokens associated with it.

**Request:**
```http
POST /v1/auth/session/revoke
Authorization: Bearer <af_token>
Content-Type: application/json

{
  "session_id": "current"
}
```

The `session_id` field accepts:
- `"current"` - Revokes the session associated with the current token (logout)
- A UUID string - Revokes the specified session

**Success Response (200):**
```json
{
  "status": "ok",
  "session_id": "660e8400-e29b-41d4-a716-446655440001"
}
```

**Error Responses:**

| Status | Error Code | Description |
|--------|------------|-------------|
| 400 | `invalid_session_id` | Session ID format is invalid |
| 401 | `missing_authorization` | Authorization header missing or malformed |
| 401 | `invalid_token` | Token is invalid or expired |
| 404 | `session_not_found` | Session does not exist |

### Idempotency

Session revocation is idempotent - revoking an already revoked session will still return success. This ensures logout flows are reliable.

### CLI Logout Example

```python
async def logout(af_token: str) -> None:
    """Logout by revoking the current session."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://identity.agentfoundry.example/v1/auth/session/revoke",
            headers={"Authorization": f"Bearer {af_token}"},
            json={"session_id": "current"}
        )
        response.raise_for_status()
```

## Validation Behavior

### JWT Validation Order

Token validation follows this order to minimize unnecessary operations:

1. **Parse Authorization header** - Check for Bearer scheme
2. **Validate JWT signature** - Using constant-time comparison
3. **Check JWT expiration** - Reject immediately without SessionStore query
4. **Verify session in SessionStore** - Check session exists and is active
5. **Check session revocation** - Reject if session is revoked
6. **Check session expiration** - Reject if session has expired

### Edge Cases

| Scenario | Behavior |
|----------|----------|
| Expired JWT | Returns 401 without querying SessionStore |
| Revoked session | Returns 401 with "Session has been revoked" |
| Expired session | Returns 401 with "Session has expired" |
| Missing session | Returns 401 with "Session not found" |
| Malformed header | Returns 401 with "Authorization header required" |

## Structured Logging

All authentication events are logged with structured context:

```json
{
  "event": "auth.success",
  "af_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "session_id": "660e8400-e29b-41d4-a716-446655440001",
  "github_user_id": 12345,
  "github_login": "octocat",
  "request_id": "abc123"
}
```

### Log Context Fields

After successful authentication, the following fields are automatically added to all structlog events within the request:

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | string | Unique request identifier for correlation |
| `af_user_id` | string | Authenticated user's UUID |
| `session_id` | string | Active session's UUID |
| `github_user_id` | int | GitHub user ID (if linked) |
| `github_login` | string | GitHub username (if linked) |

### Logged Events

| Event | Level | Description |
|-------|-------|-------------|
| `auth.success` | debug | Request authenticated successfully |
| `auth.token.expired` | debug | JWT has expired |
| `auth.token.invalid` | debug | JWT validation failed |
| `auth.session.not_found` | debug | Session not in store |
| `auth.session.revoked` | debug | Session has been revoked |
| `auth.session.expired` | debug | Session has expired |
| `token.introspect` | info | Token introspection completed |
| `session.revoked` | info | Session was revoked |

## Security Considerations

### Error Messages

Error messages are designed to be safe for client display without leaking internal details:

- ✅ "Invalid or expired token" - Safe generic message
- ✅ "Token has expired" - Specific but safe
- ❌ "HMAC signature mismatch" - Leaks implementation details

### Timing Attacks

JWT signature verification uses `hmac.compare_digest()` for constant-time comparison, preventing timing attacks.

### Token Replay

Tokens are bound to sessions in the SessionStore. Even if a token is leaked:

1. It can be revoked by revoking the session
2. It expires according to `jwt_expiry_seconds` configuration
3. The session expires according to `session_expiry_seconds` configuration

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `IDENTITY_JWT_SECRET` | Required | Secret for JWT signing (min 32 chars) |
| `JWT_EXPIRY_SECONDS` | 3600 | JWT lifetime in seconds (1 hour) |
| `SESSION_EXPIRY_SECONDS` | 86400 | Session lifetime in seconds (24 hours) |

## Authentication Dependencies

### Using create_auth_dependency

The `create_auth_dependency` function creates a reusable FastAPI dependency that:

1. Authenticates incoming requests using JWT and session validation
2. Automatically sets up structlog context with user/session identifiers
3. Returns `AuthenticatedContext` for use in route handlers

**Setup Example:**

```python
from fastapi import FastAPI, Depends
from af_identity_service.security import create_auth_dependency, AuthenticatedContext

app = FastAPI()

# Create the auth dependency once with your configuration
auth_required = create_auth_dependency(
    jwt_secret=settings.identity_jwt_secret,
    session_store=deps.auth_session_store,
    user_repository=deps.user_repository,
)

# Use it in any route that requires authentication
@app.get("/protected")
async def protected_route(
    auth: AuthenticatedContext = Depends(auth_required)
):
    # auth.user, auth.session, and auth.claims are available
    return {
        "user_id": str(auth.user.id),
        "github_login": auth.user.github_login,
        "session_id": str(auth.session.session_id)
    }
```

**Benefits:**

- **Reusability**: Define the dependency once, use it in many routes
- **Automatic error handling**: Returns structured 401 errors on auth failure
- **Automatic logging context**: Sets `af_user_id`, `session_id`, `github_user_id`, and `github_login` in structlog context
- **Type safety**: Route handlers receive strongly-typed `AuthenticatedContext`

### AuthenticatedContext

The `AuthenticatedContext` dataclass provides access to:

```python
from af_identity_service.security.auth import AuthenticatedContext

# auth_ctx contains:
# - auth_ctx.user: AFUser instance (id, github_login, github_user_id)
# - auth_ctx.session: Session instance (session_id, user_id, expires_at, revoked_at)
# - auth_ctx.claims: JWTClaims instance (user_id, session_id, exp, iat)
```

### Logging Context

After successful authentication via the dependency, the following fields are automatically added to all structlog events within the request:

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | string | Unique request identifier for correlation |
| `af_user_id` | string | Authenticated user's UUID |
| `session_id` | string | Active session's UUID |
| `github_user_id` | int | GitHub user ID (if linked) |
| `github_login` | string | GitHub username (if linked) |

This ensures all log entries within a request can be correlated and traced to specific users and sessions.
