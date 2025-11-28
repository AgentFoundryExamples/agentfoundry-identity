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

## GitHub Token Encryption

### Overview

In production deployments, GitHub OAuth tokens (refresh tokens and access tokens) are encrypted at rest using AES-256-GCM before being stored in PostgreSQL. This protects tokens from exposure if the database is compromised.

### Encryption Mechanism

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 96 bits (12 bytes) - randomly generated per encryption
- **Authentication Tag**: 128 bits (16 bytes)

The ciphertext format is: `IV (12 bytes) || ciphertext || auth_tag (16 bytes)`

AES-GCM provides authenticated encryption, meaning it guarantees both confidentiality (data cannot be read) and integrity (data cannot be tampered with).

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN_ENC_KEY` | Required in prod | 256-bit AES key (hex or base64 encoded) |

#### Generating a Key

Generate a secure 256-bit key using Python:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

This outputs a 64-character hex string (32 bytes = 256 bits).

#### Key Format

The key can be provided as:
- **Hex encoding**: 64 hexadecimal characters (e.g., `a1b2c3...`)
- **Base64 encoding**: 44 base64 characters with optional padding

### Development vs Production

| Environment | Token Storage |
|------------|---------------|
| Development (`IDENTITY_ENVIRONMENT=dev`) | In-memory, unencrypted (NoOpEncryptor with base64) |
| Production (`IDENTITY_ENVIRONMENT=prod`) | PostgreSQL with AES-256-GCM encryption |

In development mode without `GITHUB_TOKEN_ENC_KEY`:
- Tokens are stored in memory only
- A warning is logged about unencrypted storage
- This is only suitable for local development

In production mode:
- `GITHUB_TOKEN_ENC_KEY` is **required**
- Service will fail to start without a valid key
- All tokens are encrypted before storage

### Key Management Best Practices

#### Secure Storage

Store the encryption key securely:
- **Cloud deployments**: Use a secrets manager (AWS Secrets Manager, Google Secret Manager, HashiCorp Vault)
- **Kubernetes**: Use Kubernetes Secrets with encryption at rest
- **Never** commit keys to source control
- **Never** log keys or include them in error messages

#### Key Rotation

When rotating the encryption key:

1. **Before rotation**: Ensure all current tokens can be decrypted
2. **Deploy new key**: Update `GITHUB_TOKEN_ENC_KEY` in the environment
3. **Re-encrypt tokens**: Run a migration script to decrypt with old key and re-encrypt with new key
4. **Verify**: Confirm all tokens decrypt successfully with the new key
5. **Remove old key**: Only after verification

**Important**: If the key is rotated without re-encrypting existing tokens, users will see "Unable to decrypt refresh token" errors and must re-authenticate.

#### Recovery Procedures

If decryption fails (e.g., key was lost):

1. Users will receive an error indicating re-authentication is required
2. Clear the invalid token entries from `github_tokens` table
3. Users must re-authenticate through the OAuth flow
4. New tokens will be encrypted with the current key

### Database Schema

The `github_tokens` table stores encrypted tokens:

| Column | Type | Description |
|--------|------|-------------|
| `user_id` | UUID | Primary key, user identifier |
| `encrypted_refresh_token` | BYTEA | AES-256-GCM encrypted refresh token |
| `refresh_token_expires_at` | TIMESTAMPTZ | Refresh token expiration time |
| `encrypted_access_token` | BYTEA | AES-256-GCM encrypted access token |
| `access_token_expires_at` | TIMESTAMPTZ | Access token expiration time |
| `created_at` | TIMESTAMPTZ | Record creation time |
| `updated_at` | TIMESTAMPTZ | Last update time |

### Security Guarantees

1. **Confidentiality**: Tokens cannot be read without the encryption key
2. **Integrity**: Any tampering with ciphertext is detected during decryption
3. **Unique IVs**: Each encryption uses a random IV, preventing pattern analysis
4. **No plaintext logging**: Token values are never logged

### Error Handling

| Scenario | Behavior |
|----------|----------|
| Missing key in prod | Service fails to start with clear error |
| Invalid key format | Service fails to start with format error |
| Decryption failure | Returns "Unable to decrypt" error, user must re-authenticate |
| Database error | Returns generic error, details logged server-side |

### Monitoring and Alerts

Consider monitoring for:
- Decryption failure rate (may indicate key rotation issues)
- Token encryption/decryption latency
- Database connection errors in token operations
