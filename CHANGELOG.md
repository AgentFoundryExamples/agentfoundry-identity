# Changelog

All notable changes to the Agent Foundry Identity Service will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-11-30

Production-hardening release introducing durable Postgres/Redis backends, encrypted token storage, and comprehensive deployment documentation.

### Added

#### Production Infrastructure

- **Environment Mode Switch**: New `IDENTITY_ENVIRONMENT` setting (`dev`/`prod`) controls backend selection
  - `dev`: In-memory stores for local development (data lost on restart)
  - `prod`: Requires Postgres and Redis with encryption enabled
- **PostgreSQL Integration**: `PostgresGitHubTokenStore` and `PostgresUserRepository` for durable storage
  - Automatic connection pooling with configurable limits
  - Cloud SQL ready with socket path support
- **Redis Session Store**: `RedisSessionStore` for distributed session management
  - TLS support for secure connections
  - Automatic session expiry via Redis TTL
  - Secondary index for efficient user session listing
- **Database Migrations**: New migration system for schema management
  - `python -m af_identity_service.migrations migrate` - Create/update tables
  - `python -m af_identity_service.migrations verify` - Verify schema
  - `python -m af_identity_service.migrations status` - Check migration status

#### Token Encryption

- **AES-256-GCM Encryption**: GitHub tokens encrypted at rest in PostgreSQL
  - Random IV per encryption operation
  - User-bound authenticated additional data (AAD) prevents token swapping
- **Token Encryption Key**: New required variable `GITHUB_TOKEN_ENC_KEY` (256-bit hex)
- **Key Rotation Support**: Dual-key mode via `GITHUB_TOKEN_ENC_KEY_OLD` for non-disruptive rotation
  - New encryptions use current key
  - Decryption attempts both keys during rotation period

#### Documentation

- **Deployment Guide** (`docs/identity/deployment.md`): Complete Cloud Run deployment instructions
  - Cloud SQL provisioning with SSL/TLS
  - MemoryStore (Redis) setup with TLS
  - Secret Manager integration
  - VPC connector configuration for private networking
- **Security Documentation** (`docs/identity/security.md`): Updated with production requirements
  - Token encryption details and key management
  - Production store requirements
  - Key rotation procedures
- **Environment Configuration** (`.env.example`): Expanded with all production variables

### Changed

- **Health Endpoint**: `/healthz` now reports backend health status (`db`, `redis`) in prod mode
- **Startup Validation**: Service fails fast if prod backends are misconfigured

### Security

- GitHub refresh and access tokens are now encrypted at rest using AES-256-GCM
- Production mode enforces encrypted Postgres and TLS-enabled Redis
- Token encryption keys must be stored in Secret Manager (not environment variables directly)

### Breaking Changes (Operational)

> **Note**: API contracts remain stable. These are operational changes for production deployments.

- **New Required Variables (prod mode)**:
  - `GITHUB_TOKEN_ENC_KEY` - Token encryption key (64 hex characters)
  - `POSTGRES_HOST`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` - Database connection
  - `REDIS_HOST` - Redis connection
  - `REDIS_TLS_ENABLED=true` - Required for production Redis
- **Migration Required**: Run `python -m af_identity_service.migrations migrate` before first prod deployment

### Upgrade Notes

1. **Before deploying v0.2.0** (infrastructure setup):
   - Provision Cloud SQL (PostgreSQL) with SSL enabled
   - Provision MemoryStore (Redis) with TLS enabled
   - Generate and store encryption key: `python -c "import secrets; print(secrets.token_hex(32))"`
   - Store all secrets in Secret Manager

2. **Run database migrations** (requires Postgres access):
   - Configure `POSTGRES_*` environment variables for migration tool
   - Run migrations: `python -m af_identity_service.migrations migrate`
   - Verify schema: `python -m af_identity_service.migrations verify`

3. **Deploy the service**:
   - Set `IDENTITY_ENVIRONMENT=prod`
   - Configure all required environment variables (see Breaking Changes above)
   - Verify health endpoint returns `{"status": "healthy", "backends": {"db": "ok", "redis": "ok"}}`

4. **Existing users**: Users authenticated before 0.2.0 will need to re-authenticate after migration to prod backends (in-memory data is not migrated)

See [docs/identity/deployment.md](docs/identity/deployment.md) for complete production deployment instructions.

---

## [0.1.0] - 2025-11-26

Initial release of the Agent Foundry Identity Service.

### Added

#### Authentication & Authorization
- **GitHub OAuth Integration**: Complete OAuth 2.0 flow with CSRF protection via secure state tokens
- **AF JWT Token Issuance**: HMAC-SHA256 signed JWTs with configurable expiry (`JWT_EXPIRY_SECONDS`)
- **Session Management**: Server-side session tracking with configurable expiry (`SESSION_EXPIRY_SECONDS`)
- **Token Introspection**: `POST /v1/auth/token/introspect` for validating AF tokens
- **Session Revocation**: `POST /v1/auth/session/revoke` for logout and session invalidation

#### API Endpoints
- `GET /healthz` - Health check with version reporting
- `POST /v1/auth/github/start` - Initiate GitHub OAuth flow
- `POST /v1/auth/github/callback` - Complete GitHub OAuth flow
- `POST /v1/auth/token/introspect` - Validate AF JWT tokens
- `POST /v1/auth/session/revoke` - Revoke sessions (logout)
- `POST /v1/github/token` - Obtain GitHub access tokens for authenticated users
- `GET /v1/me` - Get authenticated user profile

#### Admin Tools
- `GET /v1/admin/users/{user_id}/sessions` - List user sessions (gated by `ADMIN_TOOLS_ENABLED`)

> **⚠️ Security Note**: Admin endpoints are disabled by default. Enable only in trusted environments by setting `ADMIN_TOOLS_ENABLED=true`.

#### Infrastructure
- **Structured Logging**: JSON-formatted logs with request correlation IDs via structlog
- **Request ID Middleware**: UUID4 request IDs in `X-Request-ID` headers
- **Fail-Fast Configuration**: Immediate startup failure on missing required configuration
- **Health Checks**: Dependency health reporting for operational monitoring
- **Cloud Run Ready**: Stateless operation suitable for horizontal scaling

### Security Notes

#### Token Storage
- GitHub refresh tokens are stored server-side in `GitHubTokenStore`
- **⚠️ Development Warning**: The default `InMemoryGitHubTokenStore` is for development only
- **Production Requirement**: Replace with an encrypted backend (e.g., Redis with AES-256-GCM encryption) for production deployments

#### Environment Secrets
- `IDENTITY_JWT_SECRET` must be at least 32 characters and kept secret
- Rotate `IDENTITY_JWT_SECRET` when deploying to new environments
- Use Secret Manager (e.g., GCP Secret Manager) for production deployments

### Configuration

Required environment variables:
- `IDENTITY_JWT_SECRET` - JWT signing secret (min 32 characters)
- `GITHUB_CLIENT_ID` - GitHub OAuth App client ID  
- `GITHUB_CLIENT_SECRET` - GitHub OAuth App client secret

Optional environment variables:
- `JWT_EXPIRY_SECONDS` - JWT lifetime (default: 3600)
- `SESSION_EXPIRY_SECONDS` - Session lifetime (default: 86400)
- `ADMIN_TOOLS_ENABLED` - Enable admin endpoints (default: false)
- `LOG_LEVEL` - Logging level (default: INFO)
- `LOG_FORMAT` - Log format: json or console (default: json)

See [.env.example](.env.example) for the complete configuration reference.

### Breaking Changes

None - this is the initial release.

### Upgrade Notes

For future versions, see [docs/identity/release.md](docs/identity/release.md) for upgrade procedures and version bump guidance.

---

## Version Bump Guide

When releasing a new version:

1. **Update the version** in `af_identity_service/version.py`
2. **Add a new section** to this CHANGELOG with the new version number and date
3. **Document all changes** following the Keep a Changelog format
4. **Tag the release** in git: `git tag -a v0.2.0 -m "Release v0.2.0"`

Semantic versioning guidelines:
- **MAJOR** (1.0.0): Breaking API changes (endpoint removal, response format changes)
- **MINOR** (0.2.0): New features, backward compatible (new endpoints, optional fields)
- **PATCH** (0.1.1): Bug fixes, backward compatible (security fixes, documentation)
