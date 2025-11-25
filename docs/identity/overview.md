# Identity Service Overview

This document provides a detailed overview of the Agent Foundry Identity Service architecture, components, and operational semantics.

## Service Purpose

The Identity Service provides authentication and authorization capabilities for Agent Foundry applications. It handles:

- **GitHub OAuth Authentication**: Users authenticate via GitHub OAuth
- **JWT Token Issuance**: Stateless authentication tokens for API access
- **Session Management**: Server-side session tracking (pluggable storage)
- **User Identity**: GitHub user information and admin role assignment

## Architecture

### Design Principles

1. **Stateless Operation**: The service runs without local state, suitable for horizontal scaling on Cloud Run
2. **Fail-Fast Configuration**: Missing required configuration causes immediate startup failure
3. **Structured Observability**: JSON-formatted logs with correlation IDs for distributed tracing
4. **Dependency Injection**: Pluggable components for session storage and GitHub integration

### Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Application                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Request ID   │  │   Health     │  │   OAuth      │          │
│  │ Middleware   │──│   Router     │  │   Router     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                │                  │                   │
│         ▼                ▼                  ▼                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Dependency Container                        │   │
│  │  ┌──────────────────┐  ┌──────────────────┐            │   │
│  │  │  Session Store   │  │  GitHub Driver   │            │   │
│  │  │  (In-Memory)     │  │  (Placeholder)   │            │   │
│  │  └──────────────────┘  └──────────────────┘            │   │
│  └─────────────────────────────────────────────────────────┘   │
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Configuration (Pydantic Settings)           │   │
│  │  IDENTITY_JWT_SECRET | GITHUB_CLIENT_ID | OAUTH_SCOPES  │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### Configuration (`config.py`)

The configuration module uses Pydantic Settings to validate environment variables at startup.

**Required Variables** (service won't start without these):
- `IDENTITY_JWT_SECRET`: JWT signing key (min 32 characters)
- `GITHUB_CLIENT_ID`: GitHub OAuth App client ID
- `GITHUB_CLIENT_SECRET`: GitHub OAuth App client secret

**Validation Behavior**:
- Missing required variables raise `ConfigurationError` with descriptive messages
- Invalid values (e.g., short JWT secret) are rejected with clear error messages
- Configuration is cached after first load (`@lru_cache`)

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
  "event": "Request processed",
  "service": "af-identity-service",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "af_user_id": "github:12345",
  "level": "info",
  "logger": "af_identity_service.app",
  "timestamp": "2025-01-01T12:00:00.000000Z"
}
```

### Dependencies (`dependencies.py`)

The dependency container provides lazy initialization of pluggable components:

**SessionStore** (Abstract):
- Interface for session storage
- Default: `InMemorySessionStore` (development only)
- Production: Replace with Redis or similar

**GitHubDriver** (Abstract):
- Interface for GitHub API interactions
- Default: `PlaceholderGitHubDriver` (raises NotImplementedError)
- Production: Replace with real HTTP client implementation

**Initialization Behavior**:
- Dependencies are created without network I/O
- Initialization errors are captured and surfaced via health checks
- `health_check()` method reports component status

### Application (`app.py`)

The FastAPI application factory provides:

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
3. Configure structlog with appropriate format
4. Initialize dependency container
5. Verify dependencies are healthy
6. Create FastAPI application
7. Mount middleware and routers
8. Begin accepting requests

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

**Health Check Errors**:
- Caught and returned as 503 responses
- No stack traces exposed to clients
- Errors logged with full details

## Cloud Run Deployment

### Recommended Settings

```yaml
# Cloud Run service configuration
spec:
  template:
    spec:
      containers:
        - name: af-identity-service
          env:
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

# Grant access to Cloud Run service account
gcloud secrets add-iam-policy-binding jwt-secret \
  --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

## Future Extensions

The current bootstrap implementation provides placeholders for:

1. **Real GitHub OAuth Flow**: Replace `PlaceholderGitHubDriver` with HTTP client
2. **Distributed Sessions**: Replace `InMemorySessionStore` with Redis
3. **Token Validation Endpoints**: Add JWT verification routes
4. **User Management**: Add user lookup and admin endpoints
5. **Rate Limiting**: Add request rate limiting middleware
