# Identity Service Architecture

This document describes the storage and driver abstractions that underpin the Agent Foundry Identity Service.

## Data Contracts

All identity data models are hard contracts that downstream services depend on. Changes to these models require careful versioning.

### AFUser

The primary user model representing an authenticated user in the AF system.

```python
class AFUser(BaseModel):
    id: UUID                      # Unique user identifier (UUID4)
    github_user_id: int | None    # GitHub user ID if linked via OAuth
    github_login: str | None      # GitHub username if linked via OAuth
    created_at: datetime          # Timestamp when user was created (UTC)
    updated_at: datetime          # Timestamp when user was last updated (UTC)
```

All datetime fields are timezone-aware UTC timestamps. When serializing to JSON, datetimes are formatted in ISO 8601 format.

### GitHubIdentity

GitHub user profile information retrieved from the GitHub API.

```python
class GitHubIdentity(BaseModel):
    github_user_id: int          # GitHub user ID
    login: str                   # GitHub username
    avatar_url: str | None       # URL to user's avatar image
```

### Session

Internal session model for tracking authenticated user sessions.

```python
class Session(BaseModel):
    session_id: UUID             # Unique session identifier (UUID4)
    user_id: UUID                # UUID of the user this session belongs to
    created_at: datetime         # Timestamp when session was created (UTC)
    expires_at: datetime         # Timestamp when session expires (UTC)
    revoked: bool                # Whether the session has been revoked
```

Helper methods:
- `is_revoked()`: Returns True if session is explicitly revoked
- `is_expired(now=None)`: Returns True if session has expired
- `is_active(now=None)`: Returns True if session is not revoked and not expired

### AFTokenIntrospection

Response model for AF token introspection endpoints.

```python
class AFTokenIntrospection(BaseModel):
    user_id: UUID                # UUID of the authenticated user
    github_login: str | None     # GitHub username if linked via OAuth
    github_user_id: int | None   # GitHub user ID if linked via OAuth
    session_id: UUID             # UUID of the active session
    expires_at: datetime         # Timestamp when token/session expires (UTC)
```

### GitHubOAuthResult

Result of GitHub OAuth token operations. This is a plain Python dataclass (not a Pydantic model) that is returned by the driver interface methods.

```python
@dataclass
class GitHubOAuthResult:
    access_token: str                        # GitHub access token
    access_token_expires_at: datetime        # Access token expiration time (UTC)
    refresh_token: str | None = None         # GitHub refresh token, if provided
    refresh_token_expires_at: datetime | None = None  # Refresh token expiration time (UTC)
```

All datetime fields are normalized to UTC timezone-aware datetimes via `__post_init__`. If a naive datetime is provided, it is assumed to be UTC and converted to a timezone-aware datetime.

## Storage Abstractions

All stores are designed to be swappable for database-backed or private implementations. The v1 release ships with in-memory implementations suitable for development.

### AFUserRepository

User persistence abstraction with methods:

- `get_by_id(user_id: UUID) -> AFUser | None`: Retrieve user by UUID
- `get_by_github_id(github_user_id: int) -> AFUser | None`: Retrieve user by GitHub ID
- `upsert_by_github_id(github_user_id: int, github_login: str) -> AFUser`: Create or update user

**Thread Safety**: Implementations must be thread-safe to avoid race conditions in multi-worker Cloud Run environments.

**Validation**: Invalid UUID inputs raise `ValueError` early.

### SessionStore

Session persistence abstraction with methods:

- `create(session: Session) -> Session`: Create and store a new session
- `get(session_id: UUID) -> Session | None`: Retrieve session by ID
- `revoke(session_id: UUID) -> bool`: Revoke a session
- `list_by_user(user_id: UUID, include_inactive: bool = False) -> list[Session]`: List user's sessions

**Expiration Handling**: The store treats expired sessions as inactive even if not explicitly revoked, avoiding time-skew bugs. When listing sessions with `include_inactive=False`, both revoked and expired sessions are filtered out.

**Thread Safety**: Implementations must be thread-safe.

### GitHubTokenStore

Token persistence abstraction with methods:

- `store_tokens(user_id: UUID, tokens: GitHubOAuthResult) -> None`: Store tokens for a user
- `get_access_token(user_id: UUID) -> str | None`: Get cached access token if not expired
- `get_refresh_token(user_id: UUID) -> str`: Get refresh token (raises if not found)
- `clear_tokens(user_id: UUID) -> None`: Clear all tokens for a user

**Encryption Expectations**: Production implementations MUST encrypt refresh tokens at rest using a secure encryption algorithm (e.g., AES-256-GCM). The encryption key should be managed via a secure key management service (KMS).

**Missing Tokens**: `get_refresh_token` raises `RefreshTokenNotFoundError` if no refresh token exists for the user, surfacing clear errors for new users without tokens.

## Driver Abstractions

### GitHubOAuthDriver

GitHub OAuth operations abstraction with methods:

- `exchange_code_for_tokens(code: str) -> GitHubOAuthResult`: Exchange authorization code for tokens
- `refresh_access_token(refresh_token: str) -> GitHubOAuthResult`: Refresh expired access token
- `get_user_profile(access_token: str) -> GitHubIdentity`: Get authenticated user's profile

**Error Handling**: Operations raise `GitHubOAuthDriverError` on failure.

## In-Memory Implementations

All in-memory implementations are marked as dev-only and emit structlog events for debugging:

### InMemoryUserRepository

- Thread-safe using `threading.Lock`
- Maintains two indices: by UUID and by GitHub ID
- Logs user creation and updates

### InMemorySessionStore

- Thread-safe using `threading.Lock`
- Maintains session and user-session indices
- Logs session creation, retrieval, and revocation
- Filters expired sessions when listing

### InMemoryGitHubTokenStore

- Thread-safe using `threading.Lock`
- **WARNING**: Does NOT encrypt tokens (dev-only)
- Logs token storage and retrieval (without exposing token values)
- Validates token expiration on access

### StubGitHubOAuthDriver

- Does NOT make real API calls
- Returns predictable fake tokens and profiles
- Logs all operations for debugging
- **WARNING**: Should NEVER be used in production

## Encryption Expectations

For production deployments:

1. **Refresh Token Encryption**: Refresh tokens must be encrypted at rest using AES-256-GCM or equivalent
2. **Key Management**: Use a cloud KMS (e.g., Google Cloud KMS, AWS KMS) for encryption key management
3. **Key Rotation**: Implement a key rotation strategy
4. **Audit Logging**: Log all token access without exposing raw values
5. **Secure Transport**: All token operations must use TLS

## Edge Cases

### Invalid UUID Inputs

All repository and store methods validate UUID inputs early:

```python
if not isinstance(user_id, UUID):
    raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")
```

### Session Expiration vs Revocation

Sessions have two independent states:
- **Expired**: `expires_at` has passed (automatic)
- **Revoked**: Explicitly marked as revoked (manual)

A session is inactive if either condition is true. This prevents time-skew bugs where slightly out-of-sync clocks might treat expired sessions as active.

### Missing Refresh Tokens

New users completing OAuth for the first time may not have refresh tokens (depending on GitHub's OAuth configuration). The `GitHubTokenStore.get_refresh_token` method raises `RefreshTokenNotFoundError` with a clear message:

```python
raise RefreshTokenNotFoundError(f"No refresh token found for user {user_id}")
```

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Identity Service                              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐         │
│  │   AFUser       │  │   Session      │  │ AFTokenIntro   │         │
│  │   Model        │  │   Model        │  │   spection     │         │
│  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘         │
│          │                   │                   │                   │
│          ▼                   ▼                   │                   │
│  ┌────────────────┐  ┌────────────────┐         │                   │
│  │ AFUser         │  │ Session        │         │                   │
│  │ Repository     │  │ Store          │         │                   │
│  │ (Abstract)     │  │ (Abstract)     │         │                   │
│  └───────┬────────┘  └───────┬────────┘         │                   │
│          │                   │                   │                   │
│          ▼                   ▼                   │                   │
│  ┌────────────────┐  ┌────────────────┐         │                   │
│  │ InMemory       │  │ InMemory       │         │                   │
│  │ UserRepository │  │ SessionStore   │         │                   │
│  │ (Dev)          │  │ (Dev)          │         │                   │
│  └────────────────┘  └────────────────┘         │                   │
│                                                  │                   │
│  ┌────────────────┐  ┌────────────────┐         │                   │
│  │ GitHubOAuth    │  │ GitHubToken    │         │                   │
│  │ Driver         │  │ Store          │         │                   │
│  │ (Abstract)     │  │ (Abstract)     │         │                   │
│  └───────┬────────┘  └───────┬────────┘         │                   │
│          │                   │                   │                   │
│          ▼                   ▼                   │                   │
│  ┌────────────────┐  ┌────────────────┐         │                   │
│  │ Stub           │  │ InMemory       │         │                   │
│  │ GitHubOAuth    │  │ GitHubToken    │         │                   │
│  │ Driver (Dev)   │  │ Store (Dev)    │         │                   │
│  └────────────────┘  └────────────────┘         │                   │
└─────────────────────────────────────────────────────────────────────┘
```

## Production Implementations

When implementing production versions of these stores:

1. **Database Backend**: Use PostgreSQL or similar for AFUserRepository and SessionStore
2. **Token Storage**: Use encrypted column or dedicated secrets manager for GitHubTokenStore
3. **Caching**: Consider Redis for session caching and access token caching
4. **Metrics**: Add Prometheus metrics for store operations
5. **Health Checks**: Implement `health_check()` methods that verify database connectivity
