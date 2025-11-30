# Agent Foundry Identity Service - Usage Guide

This document describes how to use the Agent Foundry Identity Service APIs, including token lifetimes, configuration, and recommended patterns for internal services.

## Running the Service

### Development Mode

In development mode (`IDENTITY_ENVIRONMENT=dev`), the service uses in-memory implementations for all stores:

```bash
# Minimum required environment variables for development
export IDENTITY_ENVIRONMENT=dev
export IDENTITY_JWT_SECRET="your-32-character-secret-key-here"
export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"

# Optional: Use console logging for development
export LOG_FORMAT=console

# Start the service
af-identity
```

**Dev mode characteristics:**
- Uses in-memory stores (data lost on restart)
- No external dependencies required (Postgres, Redis)
- Fast startup and health checks
- Suitable for local development and testing

### Production Mode

In production mode (`IDENTITY_ENVIRONMENT=prod`), the service requires Postgres and Redis backends:

```bash
# Environment configuration (required)
export IDENTITY_ENVIRONMENT=prod
export IDENTITY_JWT_SECRET="your-32-character-secret-key-here"
export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"

# Postgres configuration (required in prod)
export POSTGRES_HOST="your-postgres-host"
export POSTGRES_PORT=5432
export POSTGRES_DB="identity_service"
export POSTGRES_USER="identity_user"
export POSTGRES_PASSWORD="your-postgres-password"

# Redis configuration (required in prod)
export REDIS_HOST="your-redis-host"
export REDIS_PORT=6379
export REDIS_DB=0
export REDIS_TLS_ENABLED=false  # Set to true for managed Redis services

# Token encryption (required in prod)
export GITHUB_TOKEN_ENC_KEY="your-64-hex-character-encryption-key"

# Start the service
af-identity
```

**Prod mode characteristics:**
- Uses PostgresUserRepository for user persistence
- Uses PostgresGitHubTokenStore for encrypted token storage
- Uses RedisSessionStore for distributed session management
- Fails fast on initialization if backends are unavailable
- Requires database migrations to be run before starting

**Important:** Run database migrations before starting in prod mode to ensure all required tables exist.

### Cloud SQL (Google Cloud)

For Cloud Run deployments with Cloud SQL:

```bash
export GOOGLE_CLOUD_SQL_INSTANCE="project:region:instance"
export POSTGRES_DB="identity_service"
# User/password may be optional with IAM database authentication
```

## Health Endpoint

### GET /healthz

The health endpoint reports the overall service health and backend availability.

**Response (healthy):**
```json
{
  "status": "healthy",
  "service": "af-identity-service",
  "version": "0.1.0",
  "backends": {
    "db": "ok",
    "redis": "ok"
  }
}
```

**Response (degraded):**
```json
{
  "status": "degraded",
  "service": "af-identity-service",
  "version": "0.1.0",
  "backends": {
    "db": "unavailable",
    "redis": "ok"
  },
  "dependencies": {
    "session_store": true,
    "github_driver": true
  }
}
```

**Backend Status Values:**
| Status | Meaning |
|--------|---------|
| `ok` | Backend is healthy and responsive |
| `in_memory` | Using in-memory store (dev mode) |
| `degraded` | Backend is slow or timing out |
| `unavailable` | Backend is unreachable |

**Health Check Behavior:**
- Backend health checks have a 2-second timeout to avoid blocking
- Partial backend failures result in `degraded` status (not 503)
- In dev mode, backends show as `in_memory`
- The service remains operational even if some backends are degraded

## Token Types and Lifetimes

### AF JWT Tokens

**Purpose**: Short-lived tokens for authenticating API requests to AF services.

| Property | Default | Range | Description |
|----------|---------|-------|-------------|
| Lifetime | 1 hour | 60s - 24h | Configured via `JWT_EXPIRY_SECONDS` |

**Recommendations**:
- Use 1 hour (3600s) for interactive applications
- Use shorter lifetimes (15-30 minutes) for high-security environments
- Tokens should be refreshed by re-authenticating or using session-based refresh

### Sessions

**Purpose**: Server-side tracking of authenticated users across multiple token refreshes.

| Property | Default | Range | Description |
|----------|---------|-------|-------------|
| Lifetime | 24 hours | 5m - 7 days | Configured via `SESSION_EXPIRY_SECONDS` |

**Recommendations**:
- Use 30 days (2592000s) for long-lived applications
- Use 24 hours (86400s) for standard web applications
- Sessions can be revoked before expiry via `/v1/auth/session/revoke`

### GitHub Access Tokens

**Purpose**: Short-lived tokens for making GitHub API calls on behalf of users.

| Property | Typical Value | Description |
|----------|--------------|-------------|
| Lifetime | 8 hours | Set by GitHub, not configurable |
| Refresh Token | 6 months | Used to obtain new access tokens |

**Recommendations**:
- Always use the cached token from `/v1/github/token` rather than storing tokens client-side
- Use `force_refresh=true` only when necessary (e.g., after permission changes)
- Tokens are cached server-side and reused automatically

## API Endpoints

### POST /v1/github/token

**Purpose**: Internal endpoint for AF services to obtain GitHub access tokens on behalf of authenticated users.

**Authentication**: Requires valid AF JWT in `Authorization: Bearer <token>` header.

**Request Body**:
```json
{
  "force_refresh": false
}
```

**Response**:
```json
{
  "access_token": "gho_...",
  "expires_at": "2025-01-01T12:00:00Z"
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid or expired AF JWT
- `404 Not Found`: User has not completed GitHub OAuth linking (no refresh token)
- `502 Bad Gateway`: GitHub API error during token refresh

**Usage Example** (Python):
```python
import httpx

async def get_github_token(af_token: str, identity_url: str) -> str:
    """Get a GitHub access token using AF JWT."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{identity_url}/v1/github/token",
            headers={"Authorization": f"Bearer {af_token}"},
            json={"force_refresh": False},
        )
        response.raise_for_status()
        return response.json()["access_token"]
```

### GET /v1/me

**Purpose**: Returns the authenticated user's profile information.

**Authentication**: Requires valid AF JWT in `Authorization: Bearer <token>` header.

**Response**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "github_login": "octocat",
  "github_user_id": 12345,
  "linked_providers": ["github"]
}
```

### GET /v1/admin/users/{user_id}/sessions

**Purpose**: Admin debugging endpoint for listing sessions per user.

**Availability**: Only available when `ADMIN_TOOLS_ENABLED=true`.

**Authentication**: Requires valid AF JWT.

**Query Parameters**:
- `include_inactive` (boolean, default: false): Include expired and revoked sessions

**Response**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "sessions": [
    {
      "session_id": "660e8400-e29b-41d4-a716-446655440001",
      "created_at": "2025-01-01T12:00:00Z",
      "expires_at": "2025-01-02T12:00:00Z",
      "revoked": false,
      "is_active": true
    }
  ]
}
```

**Security Note**: This endpoint returns 404 when `ADMIN_TOOLS_ENABLED=false` to avoid information disclosure.

## Configuration Reference

### Environment Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `IDENTITY_ENVIRONMENT` | dev | Environment mode: `dev` or `prod` |

### Secrets (Required)

| Variable | Description |
|----------|-------------|
| `IDENTITY_JWT_SECRET` | Secret for signing JWTs (min 32 chars) |
| `GITHUB_CLIENT_ID` | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App client secret |

### Postgres Configuration (Required in prod)

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_HOST` | (none) | Postgres host address |
| `POSTGRES_PORT` | 5432 | Postgres port |
| `POSTGRES_DB` | (none) | Database name |
| `POSTGRES_USER` | (none) | Database username |
| `POSTGRES_PASSWORD` | (none) | Database password |
| `GOOGLE_CLOUD_SQL_INSTANCE` | (none) | Cloud SQL instance (alternative to host) |

### Redis Configuration (Required in prod)

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | (none) | Redis host address |
| `REDIS_PORT` | 6379 | Redis port |
| `REDIS_DB` | 0 | Redis database number (0-15) |
| `REDIS_TLS_ENABLED` | false | Enable TLS for Redis connections |

### Token Encryption (Required in prod)

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN_ENC_KEY` | 256-bit AES key (64 hex chars) for token encryption |

Generate an encryption key with:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Token Lifetimes

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_EXPIRY_SECONDS` | 3600 (1h) | AF JWT token lifetime |
| `SESSION_EXPIRY_SECONDS` | 86400 (24h) | Session lifetime |

### Admin Tools

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_TOOLS_ENABLED` | false | Enable admin debugging endpoints |
| `ADMIN_GITHUB_IDS` | (empty) | GitHub IDs with admin access |

## Internal Service Integration

### Calling /v1/github/token from AF Services

AF services that need to make GitHub API calls on behalf of users should:

1. **Receive the AF JWT** from the incoming request
2. **Call /v1/github/token** with the AF JWT to get a GitHub token
3. **Use the GitHub token** to make GitHub API calls
4. **Handle errors gracefully**:
   - `404`: User needs to re-authenticate with GitHub
   - `502`: Transient GitHub error, retry with backoff

```python
async def process_request(af_token: str):
    # Get GitHub token
    github_token = await get_github_token(af_token, IDENTITY_SERVICE_URL)
    
    # Use GitHub token for API calls
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.github.com/user/repos",
            headers={"Authorization": f"Bearer {github_token}"},
        )
        return response.json()
```

### Token Caching

The Identity Service automatically caches GitHub access tokens server-side:

- Valid tokens are returned from cache without hitting GitHub
- Nearly-expired tokens (within 5 minutes of expiry) trigger a refresh
- `force_refresh=true` bypasses the cache and always requests fresh tokens

### Refresh Token Rotation

When GitHub rotates refresh tokens during token refresh:

1. The new refresh token is immediately persisted
2. Future requests will use the new refresh token
3. Old refresh tokens become invalid

This happens transparently - callers of `/v1/github/token` don't need to handle rotation.

## Audit Logging

The service emits structured audit logs for security-relevant operations:

| Event | Level | Fields |
|-------|-------|--------|
| `github.token.refresh.success` | INFO | `af_user_id`, `access_token_expires_at`, `refresh_token_rotated` |
| `github.token.refresh.failure` | ERROR | `af_user_id`, `reason`, `error` |
| `admin.sessions.retrieved` | INFO | `af_user_id`, `target_user_id`, `session_count` |

Sensitive data (tokens) are never logged.
