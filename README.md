# AF Identity Service

FastAPI-based authentication and authorization service for Agent Foundry.

## Features

- OAuth 2.0 authentication with GitHub
- JWT token-based session management
- Structured logging with request tracing
- Health check endpoint with factory verification
- Cloud Run compatible configuration

## Quick Start

### Prerequisites

- Python 3.11+
- [Poetry](https://python-poetry.org/docs/#installation) for dependency management

### Installation

```bash
# Clone the repository
git clone https://github.com/AgentFoundryExamples/agentfoundry-identity.git
cd agentfoundry-identity

# Install dependencies
poetry install

# Copy and configure environment
cp .env.example .env
# Edit .env with your secrets (see Configuration below)
```

### Configuration

Copy `.env.example` to `.env` and set the required values:

| Variable | Required | Description |
|----------|----------|-------------|
| `IDENTITY_JWT_SECRET` | Yes | Secret key for JWT signing (min 32 chars) |
| `GITHUB_CLIENT_ID` | Yes | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | Yes | GitHub OAuth app client secret |
| `ACCESS_TOKEN_LIFETIME_SECONDS` | No | Access token lifetime (default: 3600) |
| `REFRESH_TOKEN_LIFETIME_SECONDS` | No | Refresh token lifetime (default: 86400) |
| `ADMIN_MODE` | No | Enable admin mode (default: false) |

Generate a secure JWT secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Running Locally

```bash
# Start the development server
poetry run uvicorn af_identity_service.app:app --reload --host 0.0.0.0 --port 8000

# Or with poetry shell
poetry shell
uvicorn af_identity_service.app:app --reload
```

The service will be available at `http://localhost:8000`.

### Health Check

The `/healthz` endpoint returns service health status:

```bash
curl http://localhost:8000/healthz
```

Response:
```json
{
  "status": "healthy",
  "service": "af-identity-service",
  "version": "0.1.0",
  "checks": {
    "driver_factory": "ok",
    "session_store_factory": "ok"
  }
}
```

## Development

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=af_identity_service --cov-report=term-missing
```

### Logging

The service uses [structlog](https://www.structlog.org/) for structured JSON logging, suitable for Cloud Run and other log aggregation systems.

Log entries include:
- `service`: Service name (`af-identity-service`)
- `request_id`: Unique request identifier (propagated from `X-Request-ID` header or generated)
- `timestamp`: ISO 8601 formatted timestamp
- `level`: Log level

Example log entry:
```json
{
  "event": "application_starting",
  "service": "af-identity-service",
  "version": "0.1.0",
  "timestamp": "2024-01-15T10:30:00.000000Z",
  "level": "info"
}
```

## API Documentation

When running locally, interactive API documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`



# Permanents (License, Contributing, Author)

Do not change any of the below sections

## License

All Agent Foundry work is licensed under the GPLv3 License - see the LICENSE file for details.

## Contributing

Feel free to submit issues and enhancement requests!

## Author

Created by Agent Foundry and John Brosnihan
