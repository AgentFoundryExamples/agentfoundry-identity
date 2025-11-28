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
│    ┌─────┴─────┐             ▼                   │                   │
│    │           │     ┌────────────────┐          │                   │
│    ▼           ▼     │ InMemory       │          │                   │
│  ┌──────────┐ ┌──────────┐            │          │                   │
│  │ InMemory │ │ Postgres │ SessionStore          │                   │
│  │ User     │ │ User     │ (Dev)      │          │                   │
│  │ Repo     │ │ Repo     │            │          │                   │
│  │ (Dev)    │ │ (Prod)   └────────────┘          │                   │
│  └──────────┘ └──────────┘                       │                   │
│                    │                             │                   │
│                    ▼                             │                   │
│               ┌──────────┐                       │                   │
│               │PostgreSQL│                       │                   │
│               │(af_users)│                       │                   │
│               └──────────┘                       │                   │
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

## Postgres Persistence

The Identity Service supports PostgreSQL for durable storage of user records. This section describes the persistence model and how to manage migrations.

### Database Schema

The `af_users` table stores user records with the following schema:

```sql
CREATE TABLE af_users (
    id UUID PRIMARY KEY,                        -- Unique user identifier (UUID4)
    github_user_id BIGINT UNIQUE,               -- GitHub user ID (nullable, unique)
    github_login VARCHAR,                       -- GitHub username (nullable)
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,  -- Creation timestamp (UTC)
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL   -- Last update timestamp (UTC)
);

-- Index for fast lookup by GitHub user ID
CREATE UNIQUE INDEX ix_af_users_github_user_id ON af_users (github_user_id);
```

**Key Design Decisions**:

- `id` is the primary key using UUID4 for distributed uniqueness
- `github_user_id` has a unique constraint to prevent duplicate GitHub accounts
- All timestamps use `TIMESTAMP WITH TIME ZONE` (TIMESTAMPTZ) to ensure UTC handling regardless of server timezone
- `github_user_id` and `github_login` are nullable for users not yet linked via GitHub OAuth

### PostgresUserRepository

The `PostgresUserRepository` implements the `AFUserRepository` interface using SQLAlchemy Core:

```python
from sqlalchemy import create_engine
from af_identity_service.stores.postgres_user_repository import PostgresUserRepository

# Create engine with connection pooling
engine = create_engine(
    "postgresql+psycopg://user:password@host:5432/database",
    pool_size=5,
    max_overflow=10,
)

# Initialize repository
repo = PostgresUserRepository(engine)

# Use the same interface as InMemoryUserRepository
user = await repo.upsert_by_github_id(12345, "octocat")
found = await repo.get_by_id(user.id)
```

**Thread Safety**: The repository is thread-safe. Each operation uses its own connection from the pool.

**Error Handling**:
- `DuplicateGitHubUserError`: Raised when inserting a duplicate `github_user_id`
- `DatabaseConnectionError`: Raised for connection failures (credentials sanitized)
- `ValueError`: Raised for invalid UUID inputs

### Running Migrations

Migrations are managed via a CLI tool. The migration system is idempotent - running migrations multiple times is safe.

#### Local Development

```bash
# Set environment variables
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=identity
export POSTGRES_USER=postgres
export POSTGRES_PASSWORD=secret

# Run migrations
python -m af_identity_service.migrations migrate

# Verify schema
python -m af_identity_service.migrations verify

# Check status
python -m af_identity_service.migrations status
```

#### Cloud SQL

For Google Cloud SQL, you can use the Cloud SQL Auth Proxy:

```bash
# Start the Cloud SQL Auth Proxy
cloud-sql-proxy PROJECT:REGION:INSTANCE &

# Run migrations
export POSTGRES_HOST=localhost
export POSTGRES_DB=identity
export POSTGRES_USER=identity_user
export POSTGRES_PASSWORD=secret
export GOOGLE_CLOUD_SQL_INSTANCE=project:region:instance

python -m af_identity_service.migrations migrate
```

For Cloud SQL IAM authentication, configure your application with the appropriate IAM credentials.

### Configuration

The service uses these environment variables for Postgres configuration:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTGRES_HOST` | Yes* | - | Database host address |
| `POSTGRES_PORT` | No | 5432 | Database port |
| `POSTGRES_DB` | Yes | - | Database name |
| `POSTGRES_USER` | Yes | - | Database username |
| `POSTGRES_PASSWORD` | Yes | - | Database password |
| `GOOGLE_CLOUD_SQL_INSTANCE` | No | - | Cloud SQL instance connection name |

*Required unless using Cloud SQL with IAM authentication.

### Schema Versioning

The current schema version is tracked implicitly via the table structure. Future versions may introduce explicit schema versioning.

**Version History**:
- v1 (initial): Basic `af_users` table with GitHub identity fields

## Redis Session Store

The Identity Service uses Redis (MemoryStore) for production session persistence. This section describes the Redis session store design and operational considerations.

### Why Redis for Sessions?

Sessions are ephemeral by nature but require durability during their lifetime:
- **Fast Access**: Session validation happens on every authenticated request
- **Automatic Expiration**: Redis TTL provides native expiration without GC overhead
- **Distributed State**: Multiple service instances can share session state
- **Revocation Support**: Sessions can be explicitly revoked while respecting TTL semantics

### Storage Schema

Sessions are stored as JSON documents with the following structure:

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "660e8400-e29b-41d4-a716-446655440001",
  "created_at": "2025-01-01T12:00:00+00:00",
  "expires_at": "2025-01-02T12:00:00+00:00",
  "revoked": false
}
```

### Key Structure

The store uses predictable key patterns for efficient operations:

| Key Pattern | Purpose | Example |
|-------------|---------|---------|
| `session:{session_id}` | Session data (JSON) | `session:550e8400-e29b-41d4-a716-446655440000` |
| `user_sessions:{user_id}` | Set of session IDs for a user | `user_sessions:660e8400-e29b-41d4-a716-446655440001` |

### TTL Strategy

Session TTL is managed at two levels:

1. **Application TTL**: The `expires_at` field defines when the session logically expires
2. **Redis TTL**: Set to match `expires_at` for automatic key deletion

**Revoked Sessions**: When a session is revoked, the TTL is extended by 24 hours to ensure:
- The revoked flag persists for authentication checks
- Prevents "resurrection" attacks where re-creating a session with the same ID might succeed

```
┌─────────────────────────────────────────────────────────────────┐
│                    Session Lifecycle                             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Created ──────────────────────────────── expires_at ─── TTL    │
│     │                                         │            │     │
│     │        Active (is_active = true)        │            │     │
│     │                                         │            │     │
│     │   Revoked                               │            │     │
│     │     │                                   │            │     │
│     │     └───── revoked=true ────────────────┼────────────┤     │
│     │            (Extended TTL +24h)          │   +24h     │     │
│     │                                         │            │     │
└─────────────────────────────────────────────────────────────────┘
```

### User Session Index

To support `list_by_user` without expensive `SCAN` operations, each user has a SET containing their session IDs:

```
user_sessions:{user_id} = {session_id_1, session_id_2, ...}
```

**Index Cleanup**: When listing sessions, stale entries (sessions that expired via TTL) are automatically removed from the index using `SREM`.

### Configuration

Redis connection is configured via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_HOST` | Yes (prod) | - | Redis host address |
| `REDIS_PORT` | No | 6379 | Redis port number |
| `REDIS_DB` | No | 0 | Redis database number (0-15) |
| `REDIS_TLS_ENABLED` | No | false | Enable TLS for connections |

### Error Handling

Redis operations follow graceful degradation principles:

- **Connection Errors**: Logged with redacted host info, raise `RedisConnectionFailedError`
- **Operation Errors**: Logged with context, raise `RedisSessionStoreError`
- **Timeout**: 5 second socket timeout prevents hanging requests

Connection errors do NOT crash the process; they are surfaced to callers for appropriate handling (e.g., returning HTTP 503).

### Operational Tuning

**Memory Management**:
- Sessions use TTL-based expiration; no manual eviction needed
- Monitor memory usage with `INFO memory`
- Set `maxmemory-policy volatile-ttl` to evict keys with nearest TTL if memory pressure occurs

**Connection Pooling**:
- The store uses a single Redis client per instance
- Each operation uses a dedicated connection from the pool
- Default pool size is appropriate for most workloads

**High Availability**:
- For production, use Redis Cluster or managed Redis (Cloud Memorystore)
- Configure replicas for read scaling if needed
- Use TLS for all connections in production

### Security Considerations

1. **No Sensitive Data in Sessions**: Sessions contain only UUIDs and timestamps
2. **TLS Required**: Enable `REDIS_TLS_ENABLED=true` in production
3. **Network Isolation**: Redis should only be accessible from service instances
4. **Logging**: Host information is redacted in logs to prevent credential leakage

## Production Implementations

When implementing production versions of these stores:

1. **Database Backend**: Use PostgreSQL for AFUserRepository (implemented) and SessionStore
2. **Token Storage**: Use encrypted column or dedicated secrets manager for GitHubTokenStore
3. **Session Storage**: Use Redis for session persistence (implemented via RedisSessionStore)
4. **Metrics**: Add Prometheus metrics for store operations
5. **Health Checks**: Implement `health_check()` methods that verify database connectivity
