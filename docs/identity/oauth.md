# OAuth Flow Documentation

This document describes the GitHub OAuth authentication flow implemented by the Agent Foundry Identity Service.

## Overview

The Identity Service implements GitHub OAuth 2.0 to authenticate users. The flow consists of two main endpoints:

1. **POST /v1/auth/github/start** - Initiates the OAuth flow
2. **POST /v1/auth/github/callback** - Completes the OAuth flow

## Security Considerations

### State/CSRF Protection

The OAuth flow uses a secure state token to prevent Cross-Site Request Forgery (CSRF) attacks:

1. When starting OAuth, the service generates a cryptographically secure state token using `secrets.token_urlsafe(32)`
2. The state is stored server-side with a 10-minute TTL
3. The state must be passed back during the callback
4. Invalid or expired states result in a 400 error
5. States are consumed on use (one-time-use)

### Token Security

GitHub tokens are **never** exposed to clients:

- Access and refresh tokens are stored securely in `GitHubTokenStore`
- The callback response only contains AF tokens and user metadata
- Logs never include raw token values, only prefixes for debugging
- Production implementations should encrypt refresh tokens at rest

## OAuth Sequence

```
┌──────────┐          ┌────────────────┐          ┌────────┐
│  Client  │          │ Identity Svc   │          │ GitHub │
└────┬─────┘          └───────┬────────┘          └───┬────┘
     │                        │                       │
     │ POST /v1/auth/github/start                     │
     │ {redirect_uri}         │                       │
     │───────────────────────>│                       │
     │                        │                       │
     │                   Generate state               │
     │                   Store state                  │
     │                        │                       │
     │ {authorization_url, state}                     │
     │<───────────────────────│                       │
     │                        │                       │
     │ Redirect user to authorization_url             │
     │──────────────────────────────────────────────>│
     │                        │                       │
     │ User authorizes application                    │
     │                        │                       │
     │ Redirect to callback with code & state         │
     │<──────────────────────────────────────────────│
     │                        │                       │
     │ POST /v1/auth/github/callback                  │
     │ {code, state}          │                       │
     │───────────────────────>│                       │
     │                        │                       │
     │                   Validate state               │
     │                        │                       │
     │                        │ Exchange code         │
     │                        │──────────────────────>│
     │                        │                       │
     │                        │ {access_token, ...}   │
     │                        │<──────────────────────│
     │                        │                       │
     │                        │ GET /user             │
     │                        │──────────────────────>│
     │                        │                       │
     │                        │ {user profile}        │
     │                        │<──────────────────────│
     │                        │                       │
     │                   Upsert user                  │
     │                   Store tokens                 │
     │                   Create session               │
     │                   Mint AF JWT                  │
     │                        │                       │
     │ {af_token, user}       │                       │
     │<───────────────────────│                       │
     │                        │                       │
```

## API Reference

### POST /v1/auth/github/start

Initiates the GitHub OAuth flow by generating an authorization URL.

**Request Body:**
```json
{
  "redirect_uri": "https://your-app.com/callback"
}
```

**Response (200 OK):**
```json
{
  "authorization_url": "https://github.com/login/oauth/authorize?client_id=...&redirect_uri=...&scope=...&state=...",
  "state": "abc123..."
}
```

**Logging Events:**
- `auth.github.start` - Logged when OAuth flow is initiated

### POST /v1/auth/github/callback

Completes the GitHub OAuth flow by exchanging the authorization code for tokens.

**Request Body:**
```json
{
  "code": "github_authorization_code",
  "state": "state_from_start_response"
}
```

**Response (200 OK):**
```json
{
  "af_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "github_login": "octocat",
    "github_user_id": 12345
  }
}
```

**Error Responses:**

- **400 Bad Request** - Invalid or expired state
  ```json
  {
    "detail": {
      "error": "invalid_state",
      "message": "Invalid or expired state token"
    }
  }
  ```

- **502 Bad Gateway** - GitHub API error
  ```json
  {
    "detail": {
      "error": "github_error",
      "message": "Failed to exchange code: ..."
    }
  }
  ```

**Logging Events:**
- `auth.github.callback.success` - Logged on successful authentication
- `auth.github.callback.failure` - Logged on authentication failure
- `session.created` - Logged when a new session is created

## AF JWT Claims

The AF JWT token returned by the callback endpoint contains the following claims:

| Claim | Description |
|-------|-------------|
| `sub` | User ID (UUID) |
| `sid` | Session ID (UUID) |
| `exp` | Expiration timestamp (Unix epoch) |
| `iat` | Issued at timestamp (Unix epoch) |

The token is signed using HMAC-SHA256 with the `IDENTITY_JWT_SECRET`.

## Configuration

The OAuth flow can be configured using environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_CLIENT_ID` | (required) | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | (required) | GitHub OAuth App client secret |
| `OAUTH_SCOPES` | `read:user,user:email` | Scopes to request from GitHub |
| `JWT_EXPIRY_SECONDS` | `3600` | JWT token lifetime (default: 1 hour) |
| `SESSION_EXPIRY_SECONDS` | `86400` | Session lifetime (default: 24 hours) |

## Edge Cases

### Missing State

If the callback is received without a state or with a mismatched state:
- Returns 400 Bad Request with `error: invalid_state`
- Logs `auth.github.callback.failure` with `reason: invalid_state`

### Expired State

State tokens expire after 10 minutes:
- Returns 400 Bad Request with `error: invalid_state`
- Logs `auth.github.callback.failure` with `reason: invalid_state`

### Missing Refresh Token

GitHub may not always return a refresh token:
- Login still succeeds
- The `github_token_available` field in the result indicates if refresh is available
- Token refresh operations will fail for this user

### Existing User

When a user with the same `github_user_id` already exists:
- The user record is updated (not duplicated)
- `github_login` is refreshed to the current value
- `updated_at` timestamp is set to current time
- A new session is created

## Production Considerations

### State Store

The default `InMemoryStateStore` is suitable for single-instance deployments only. For production with multiple instances, use a distributed store like Redis.

### Token Encryption

Production implementations of `GitHubTokenStore` must encrypt refresh tokens at rest using AES-256-GCM or equivalent, with keys managed by a KMS.

### Rate Limiting

Consider implementing rate limiting on OAuth endpoints to prevent abuse:
- `/v1/auth/github/start` - Limit per IP
- `/v1/auth/github/callback` - Limit per IP and state token

### Monitoring

Monitor the following events for security and operational awareness:
- `auth.github.callback.failure` with `reason: invalid_state` - Potential CSRF attempts
- `auth.github.callback.failure` with `reason: token_exchange_failed` - GitHub API issues
- High volume of `auth.github.start` events - Potential abuse
