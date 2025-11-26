# Changelog

All notable changes to the Agent Foundry Identity Service will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
