# Identity Service Overview

This document provides a detailed overview of the Agent Foundry Identity Service architecture, components, and operational semantics.

## Service Purpose

The Identity Service provides authentication and authorization capabilities for Agent Foundry applications. It handles:

- **GitHub OAuth Authentication**: Users authenticate via GitHub OAuth
- **JWT Token Issuance**: Stateless authentication tokens for API access
- **Session Management**: Server-side session tracking (pluggable storage)
- **User Identity**: GitHub user information and admin role assignment

## Environment Modes

The service supports two environment modes controlled by the `IDENTITY_ENVIRONMENT` variable:

### Development Mode (`dev`) - Default

Development mode uses in-memory stub implementations that require no external dependencies:

- **Session Store**: In-memory (data lost on restart)
- **User Repository**: In-memory (data lost on restart)
- **Token Store**: In-memory (data lost on restart)
- **GitHub Driver**: Stub driver with fake responses

This mode is suitable for:
- Local development
- Unit and integration testing
- Quick prototyping

### Production Mode (`prod`)

Production mode requires external backends for persistent storage:

- **Session Store**: Redis (requires `REDIS_HOST`)
- **User Repository**: PostgreSQL (requires Postgres configuration)
- **Token Store**: PostgreSQL (requires Postgres configuration)
- **GitHub Driver**: Real HTTP client (planned)

**Note**: Production backend implementations are prepared but not yet fully implemented. The service will log a warning when running in prod mode with stub implementations.

## Environment Variables

### Environment Mode

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IDENTITY_ENVIRONMENT` | No | `dev` | Environment mode: `dev` or `prod` |

### Required Secrets (All Modes)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IDENTITY_JWT_SECRET` | Yes | - | JWT signing key (min 32 characters) |
| `GITHUB_CLIENT_ID` | Yes | - | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | Yes | - | GitHub OAuth App client secret |

### PostgreSQL Configuration (Required in `prod` mode)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTGRES_HOST` | Conditional* | - | PostgreSQL host address |
| `POSTGRES_PORT` | No | `5432` | PostgreSQL port |
| `POSTGRES_DB` | Conditional** | - | Database name |
| `POSTGRES_USER` | Conditional** | - | Database username |
| `POSTGRES_PASSWORD` | Conditional** | - | Database password (sensitive) |
| `GOOGLE_CLOUD_SQL_INSTANCE` | Conditional* | - | Cloud SQL instance (e.g., `project:region:instance`) |

\* Either `POSTGRES_HOST` or `GOOGLE_CLOUD_SQL_INSTANCE` is required in prod mode.
\*\* Required when `POSTGRES_HOST` is set.

### Redis Configuration (Required in `prod` mode)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_HOST` | Conditional | - | Redis host address (required in prod) |
| `REDIS_PORT` | No | `6379` | Redis port |
| `REDIS_DB` | No | `0` | Redis database number (0-15) |
| `REDIS_TLS_ENABLED` | No | `false` | Enable TLS for Redis connections |

### OAuth Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OAUTH_SCOPES` | No | `read:user,user:email` | GitHub OAuth scopes (comma-separated) |

### Session Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_EXPIRY_SECONDS` | No | `3600` | JWT token lifetime (60-86400 seconds) |
| `SESSION_EXPIRY_SECONDS` | No | `86400` | Session lifetime (300-604800 seconds) |

### Admin Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ADMIN_GITHUB_IDS` | No | `""` | Admin GitHub user IDs (comma-separated) |
| `ADMIN_TOOLS_ENABLED` | No | `false` | Enable admin endpoints |

### Logging Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LOG_LEVEL` | No | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `LOG_FORMAT` | No | `json` | Log format (`json` or `console`) |

### Service Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SERVICE_HOST` | No | `0.0.0.0` | Host to bind to |
| `SERVICE_PORT` | No | `8080` | Port to bind to |

## Architecture

### Design Principles

1. **Stateless Operation**: The service runs without local state, suitable for horizontal scaling on Cloud Run
2. **Fail-Fast Configuration**: Missing required configuration causes immediate startup failure
3. **Structured Observability**: JSON-formatted logs with correlation IDs for distributed tracing
4. **Dependency Injection**: Pluggable components for session storage and GitHub integration
5. **Environment-Aware**: Deterministic loading of dev stubs or prod backends

### Component Overview

```
+-------------------------------------------------------------------+
|                    FastAPI Application                             |
|  +----------------+  +----------------+  +----------------+        |
|  | Request ID     |  |   Health       |  |   OAuth        |        |
|  | Middleware     |--|   Router       |  |   Router       |        |
|  +----------------+  +----------------+  +----------------+        |
|         |                |                  |                      |
|         v                v                  v                      |
|  +-----------------------------------------------------------------+
|  |              Dependency Container                               |
|  |  +-----------------+ +-----------------+ +---------------+      |
|  |  |  Session Store  | | User Repository | | GitHub Driver |      |
|  |  |  (Stub/Redis)   | | (Stub/Postgres) | | (Stub/Real)   |      |
|  |  +-----------------+ +-----------------+ +---------------+      |
|  |                                                                 |
|  |  Environment helpers:                                           |
|  |  - use_stub_session_store()                                     |
|  |  - use_stub_user_repository()                                   |
|  |  - use_stub_token_store()                                       |
|  |  - use_stub_github_driver()                                     |
|  +-----------------------------------------------------------------+
|         |                                                          |
|         v                                                          |
|  +-----------------------------------------------------------------+
|  |              Configuration (Pydantic Settings)                  |
|  |  IDENTITY_ENVIRONMENT | IDENTITY_JWT_SECRET | Postgres/Redis    |
|  +-----------------------------------------------------------------+
+-------------------------------------------------------------------+
```

## Components

### Configuration (`config.py`)

The configuration module uses Pydantic Settings to validate environment variables at startup.

**Required Variables** (service won't start without these):
- `IDENTITY_JWT_SECRET`: JWT signing key (min 32 characters)
- `GITHUB_CLIENT_ID`: GitHub OAuth App client ID
- `GITHUB_CLIENT_SECRET`: GitHub OAuth App client secret

**Environment-Specific Variables** (required in prod mode):
- PostgreSQL: `POSTGRES_HOST` or `GOOGLE_CLOUD_SQL_INSTANCE`, plus `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`
- Redis: `REDIS_HOST`

**Validation Behavior**:
- Missing required variables raise `ConfigurationError` with descriptive messages
- Invalid values (e.g., short JWT secret) are rejected with clear error messages
- Invalid `IDENTITY_ENVIRONMENT` values raise a descriptive error
- Production mode validates that all backend configuration is present
- Configuration is cached after first load (`@lru_cache`)
- Sensitive values are redacted in logs via `get_redacted_config_dict()`

### Logging (`logging.py`)

Structured logging is implemented with structlog, providing:

**Context Variables**:
- `service`: Always `af-identity-service`
- `request_id`: UUID4 generated per request
- `af_user_id`: User's identifier (set after authentication)

**Output Formats**:
- `json`: Production format, one JSON object per line
- `console`: Development format with colors and formatting

**Example JSON Log Entry**:
```json
{
  "event": "Starting Identity Service",
  "service": "af-identity-service",
  "environment": "dev",
  "version": "0.1.0",
  "level": "info",
  "logger": "af_identity_service.app",
  "timestamp": "2025-01-01T12:00:00.000000Z"
}
```

### Dependencies (`dependencies.py`)

The dependency container provides lazy initialization of pluggable components:

**Environment Properties**:
- `environment`: Returns the current environment mode (`dev` or `prod`)
- `is_prod`: True if running in production mode
- `is_dev`: True if running in development mode

**Factory Helpers** (for selecting stub vs prod implementations):
- `use_stub_session_store()`: Returns True in dev mode
- `use_stub_user_repository()`: Returns True in dev mode
- `use_stub_token_store()`: Returns True in dev mode
- `use_stub_github_driver()`: Returns True in dev mode

**SessionStore** (Abstract):
- Interface for session storage
- Dev: `InMemorySessionStore`
- Prod: Redis (planned)

**UserRepository** (Abstract):
- Interface for user storage
- Dev: `InMemoryUserRepository`
- Prod: PostgreSQL (planned)

**GitHubDriver** (Abstract):
- Interface for GitHub API interactions
- Dev: `StubGitHubOAuthDriver`
- Prod: Real HTTP client (planned)

**Initialization Behavior**:
- Dependencies are created without network I/O
- Initialization errors are captured and surfaced via health checks
- `health_check()` method reports component status
- Environment mode is logged at initialization

### Application (`app.py`)

The FastAPI application factory provides:

**Startup Logging**:
- Environment mode is logged at startup
- Configuration is logged (with secrets redacted) at DEBUG level

**Middleware**:
- `RequestIDMiddleware`: Generates UUID4 request IDs
  - Sets context variable for structlog
  - Returns ID in `X-Request-ID` response header

**Endpoints**:
- `GET /healthz`: Health check endpoint
  - Returns 200 when healthy
  - Returns 503 when degraded (with dependency status)

**Entry Points**:
- `create_app()`: ASGI application factory
- `main()`: CLI entrypoint for uvicorn

## Operational Semantics

### Startup Sequence

1. Load configuration from environment variables
2. Validate all required settings (fail-fast)
3. Validate production-specific settings if `IDENTITY_ENVIRONMENT=prod`
4. Configure structlog with appropriate format
5. Log startup with environment mode
6. Initialize dependency container (respects environment mode)
7. Verify dependencies are healthy
8. Create FastAPI application
9. Mount middleware and routers
10. Begin accepting requests

### Health Check Behavior

The `/healthz` endpoint:

**Healthy Response** (200):
```json
{
  "status": "healthy",
  "service": "af-identity-service",
  "version": "0.1.0"
}
```

**Degraded Response** (503):
```json
{
  "status": "degraded",
  "service": "af-identity-service",
  "version": "0.1.0",
  "dependencies": {
    "session_store": false,
    "github_driver": true
  }
}
```

### Request Processing

1. Request arrives at FastAPI
2. `RequestIDMiddleware` generates UUID4 request ID
3. Context variable `request_id_ctx` is set
4. Request is processed by route handlers
5. All log entries include the request ID
6. Response includes `X-Request-ID` header
7. Context variables are reset

### Error Handling

**Configuration Errors**:
- Raised at startup, before server begins listening
- Include descriptive messages explaining what's missing
- Exit code 1 for CLI invocation
- Production-specific errors clearly indicate which backend variables are missing

**Health Check Errors**:
- Caught and returned as 503 responses
- No stack traces exposed to clients
- Errors logged with full details

## Cloud Run Deployment

### Recommended Settings (Development)

For development/testing on Cloud Run with in-memory stores:

```yaml
# Cloud Run service configuration (dev mode)
spec:
  template:
    spec:
      containers:
        - name: af-identity-service
          env:
            - name: IDENTITY_ENVIRONMENT
              value: dev
            - name: LOG_FORMAT
              value: json
            - name: LOG_LEVEL
              value: INFO
          resources:
            limits:
              memory: 256Mi
              cpu: 1000m
          ports:
            - containerPort: 8080
```

### Recommended Settings (Production)

For production with persistent backends:

```yaml
# Cloud Run service configuration (prod mode)
spec:
  template:
    spec:
      containers:
        - name: af-identity-service
          env:
            - name: IDENTITY_ENVIRONMENT
              value: prod
            - name: LOG_FORMAT
              value: json
            - name: LOG_LEVEL
              value: INFO
            - name: GOOGLE_CLOUD_SQL_INSTANCE
              value: my-project:us-central1:my-instance
            - name: POSTGRES_DB
              value: identity_service
            - name: POSTGRES_USER
              valueFrom:
                secretKeyRef:
                  name: postgres-credentials
                  key: username
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: postgres-credentials
                  key: password
            - name: REDIS_HOST
              value: redis.example.com
            - name: REDIS_TLS_ENABLED
              value: "true"
          resources:
            limits:
              memory: 512Mi
              cpu: 1000m
          ports:
            - containerPort: 8080
```

### Health Check Configuration

Configure Cloud Run to use the health endpoint:

```yaml
spec:
  template:
    spec:
      containers:
        - livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 3
            periodSeconds: 5
```

### Secret Management

Use Secret Manager for sensitive values:

```bash
# Create secrets
echo -n "your-jwt-secret" | gcloud secrets create jwt-secret --data-file=-
echo -n "your-github-secret" | gcloud secrets create github-secret --data-file=-
echo -n "your-postgres-password" | gcloud secrets create postgres-password --data-file=-

# Grant access to Cloud Run service account
gcloud secrets add-iam-policy-binding jwt-secret \
  --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

## Future Extensions

The current bootstrap implementation provides placeholders for:

1. **Real GitHub OAuth Flow**: Replace `StubGitHubOAuthDriver` with HTTP client
2. **Distributed Sessions**: Replace `InMemorySessionStore` with Redis
3. **Persistent User Storage**: Replace `InMemoryUserRepository` with PostgreSQL
4. **Persistent Token Storage**: Replace `InMemoryGitHubTokenStore` with PostgreSQL
5. **Token Validation Endpoints**: Add JWT verification routes
6. **User Management**: Add user lookup and admin endpoints
7. **Rate Limiting**: Add request rate limiting middleware
