# Agent Foundry Identity Service

FastAPI-based authentication and authorization service for Agent Foundry. This service handles GitHub OAuth authentication, session management, and JWT token issuance.

## Features

- **GitHub OAuth Integration**: Authenticate users via GitHub OAuth
- **JWT Token Management**: Issue and validate JWT tokens for API authentication
- **Session Management**: Pluggable session storage (in-memory by default)
- **Structured Logging**: JSON-formatted logs with request correlation IDs
- **Health Checks**: Operational health endpoint for monitoring
- **Cloud Run Ready**: Designed to run statelessly on Google Cloud Run

## Quick Start

### Prerequisites

- Python 3.11 or higher
- A GitHub OAuth App ([create one here](https://github.com/settings/developers))

### Local Development

1. **Clone the repository and install dependencies:**

   ```bash
   git clone https://github.com/AgentFoundryExamples/agentfoundry-identity.git
   cd agentfoundry-identity
   pip install -e ".[dev]"
   ```

2. **Configure environment variables:**

   ```bash
   cp .env.example .env
   # Edit .env with your GitHub OAuth credentials
   ```

   Required variables:
   - `IDENTITY_JWT_SECRET`: Secret key for JWT signing (min 32 characters)
   - `GITHUB_CLIENT_ID`: Your GitHub OAuth App client ID
   - `GITHUB_CLIENT_SECRET`: Your GitHub OAuth App client secret

3. **Run the service:**

   ```bash
   # Using the CLI entrypoint
   af-identity

   # Or using uvicorn directly
   uvicorn af_identity_service.app:create_app --factory --reload
   ```

4. **Verify it's running:**

   ```bash
   curl http://localhost:8080/healthz
   # Expected: {"status":"healthy","service":"af-identity-service","version":"0.1.0"}
   ```

### Running Tests

```bash
pytest
```

## API Endpoints

### Health Check

```
GET /healthz
```

Returns the service health status:
- `200 OK`: Service is healthy
- `503 Service Unavailable`: Service is degraded

Response:
```json
{
  "status": "healthy",
  "service": "af-identity-service",
  "version": "0.1.0"
}
```

### GitHub OAuth

The service provides GitHub OAuth endpoints for authentication:

```
POST /v1/auth/github/start
POST /v1/auth/github/callback
```

See [docs/identity/oauth.md](docs/identity/oauth.md) for detailed OAuth flow documentation.

### GitHub Token Distribution

Internal endpoint for AF services to obtain GitHub access tokens:

```
POST /v1/github/token
```

Returns a GitHub access token for the authenticated user. Tokens are cached server-side and reused when valid.

See [docs/identity/usage.md](docs/identity/usage.md) for detailed usage documentation.

### User Profile

```
GET /v1/me
```

Returns the authenticated user's profile including linked providers.

### Admin Endpoints

Admin debugging endpoints (gated by `ADMIN_TOOLS_ENABLED`):

```
GET /v1/admin/users/{user_id}/sessions
```

See [docs/identity/usage.md](docs/identity/usage.md) for configuration and usage details.

### API Documentation

When running locally, interactive API documentation is available at:
- Swagger UI: http://localhost:8080/docs
- ReDoc: http://localhost:8080/redoc

## Configuration

All configuration is via environment variables. See [.env.example](.env.example) for the complete list.

### Required Variables

| Variable | Description |
|----------|-------------|
| `IDENTITY_JWT_SECRET` | Secret key for JWT signing (min 32 chars) |
| `GITHUB_CLIENT_ID` | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App client secret |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_SCOPES` | `read:user,user:email` | GitHub OAuth scopes |
| `JWT_EXPIRY_SECONDS` | `3600` | JWT token lifetime |
| `SESSION_EXPIRY_SECONDS` | `86400` | Session lifetime |
| `ADMIN_GITHUB_IDS` | (empty) | Admin user GitHub IDs |
| `ADMIN_TOOLS_ENABLED` | `false` | Enable admin debugging endpoints |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `LOG_FORMAT` | `json` | Log format (json/console) |
| `SERVICE_HOST` | `0.0.0.0` | Bind host |
| `SERVICE_PORT` | `8080` | Bind port |

## Cloud Run Deployment

1. **Build the container:**

   ```bash
   gcloud builds submit --tag gcr.io/PROJECT_ID/af-identity-service
   ```

2. **Deploy to Cloud Run:**

   ```bash
   gcloud run deploy af-identity-service \
     --image gcr.io/PROJECT_ID/af-identity-service \
     --platform managed \
     --region us-central1 \
     --set-env-vars "IDENTITY_JWT_SECRET=your-secret" \
     --set-env-vars "GITHUB_CLIENT_ID=your-client-id" \
     --set-env-vars "GITHUB_CLIENT_SECRET=your-client-secret" \
     --allow-unauthenticated
   ```

   **Security Note**: For production, use Secret Manager for sensitive values:
   
   ```bash
   gcloud run deploy af-identity-service \
     --set-secrets "IDENTITY_JWT_SECRET=jwt-secret:latest" \
     --set-secrets "GITHUB_CLIENT_SECRET=github-secret:latest"
   ```

## Logging

The service uses [structlog](https://www.structlog.org/) for structured logging.

### Log Format

In production (`LOG_FORMAT=json`), logs are JSON-formatted:

```json
{
  "event": "Health check passed",
  "service": "af-identity-service",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "af_user_id": null,
  "level": "debug",
  "timestamp": "2025-01-01T00:00:00.000000Z"
}
```

For development (`LOG_FORMAT=console`), logs are human-readable with colors.

### Correlation IDs

Every request receives a unique `request_id` (UUID4) that:
- Is included in all log entries for that request
- Is returned in the `X-Request-ID` response header
- Can be used to trace requests across services

## Architecture

See [docs/identity/overview.md](docs/identity/overview.md) for detailed architecture documentation.

## Project Structure

```
af_identity_service/
├── __init__.py      # Package metadata
├── version.py       # Single source of truth for service version
├── app.py           # FastAPI app factory and entrypoint
├── config.py        # Pydantic settings validation
├── logging.py       # Structlog configuration
└── dependencies.py  # Dependency injection container
```

## Version

The current version is **0.1.0**. The version is defined in `af_identity_service/version.py` and is the single source of truth for:
- Health endpoint responses (`/healthz`)
- Package metadata
- API documentation

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Release Preparation

Before deploying to production, review [docs/identity/release.md](docs/identity/release.md) for:
- Environment variable validation checklist
- `IDENTITY_JWT_SECRET` rotation guidance
- Manual smoke tests for `/healthz`, `/v1/auth/token/introspect`, and `/v1/github/token`
- Version bump procedures

### Quick Smoke Test

```bash
# Health check
curl http://localhost:8080/healthz

# Token introspection (should return 401)
curl -X POST http://localhost:8080/v1/auth/token/introspect \
  -H "Authorization: Bearer invalid-token"

# GitHub token (should return 401)
curl -X POST http://localhost:8080/v1/github/token \
  -H "Content-Type: application/json" \
  -d '{"force_refresh": false}'
```

## Security Notes

### GitHub Refresh Token Storage

> **⚠️ Development Warning**: The default in-memory token storage is for development only.

GitHub refresh tokens are stored server-side to enable token refresh without user interaction. The default `InMemoryGitHubTokenStore` does not persist data and is not suitable for production.

**For production deployments**, replace with an encrypted backend that:
- Encrypts tokens at rest (AES-256-GCM recommended)
- Uses a KMS for encryption key management
- Provides durability across service restarts

### JWT Secret Rotation

When rotating `IDENTITY_JWT_SECRET` for a new environment:
1. Generate a new secret: `openssl rand -base64 32`
2. Update the environment variable
3. Coordinate with users—all existing AF JWTs will become invalid
4. Never reuse secrets between environments

See [docs/identity/security.md](docs/identity/security.md) for detailed security guidance.



# Permanents (License, Contributing, Author)

Do not change any of the below sections

## License

All Agent Foundry work is licensed under the GPLv3 License - see the LICENSE file for details.

## Contributing

Feel free to submit issues and enhancement requests!

## Author

Created by Agent Foundry and John Brosnihan
