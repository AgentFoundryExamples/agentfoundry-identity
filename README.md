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
├── app.py           # FastAPI app factory and entrypoint
├── config.py        # Pydantic settings validation
├── logging.py       # Structlog configuration
└── dependencies.py  # Dependency injection container
```



# Permanents (License, Contributing, Author)

Do not change any of the below sections

## License

All Agent Foundry work is licensed under the GPLv3 License - see the LICENSE file for details.

## Contributing

Feel free to submit issues and enhancement requests!

## Author

Created by Agent Foundry and John Brosnihan
