# Release Preparation Guide

This document describes the release preparation process for the Agent Foundry Identity Service, including environment validation, smoke testing, and version bump procedures.

## Pre-Release Checklist

Before deploying a new release, complete the following steps:

### 1. Environment Variable Validation

Verify all required environment variables are configured correctly:

```bash
# Required secrets - must be set
echo "Checking required variables..."
test -n "$IDENTITY_JWT_SECRET" && echo "✓ IDENTITY_JWT_SECRET is set" || echo "✗ IDENTITY_JWT_SECRET is missing"
test -n "$GITHUB_CLIENT_ID" && echo "✓ GITHUB_CLIENT_ID is set" || echo "✗ GITHUB_CLIENT_ID is missing"
test -n "$GITHUB_CLIENT_SECRET" && echo "✓ GITHUB_CLIENT_SECRET is set" || echo "✗ GITHUB_CLIENT_SECRET is missing"
```

#### JWT Secret Requirements

- **Minimum length**: 32 characters
- **Regeneration**: Rotate when deploying to new environments
- **Generation command**: `openssl rand -base64 32`

> **⚠️ Critical**: When rotating `IDENTITY_JWT_SECRET`, all existing AF JWTs will become invalid. Coordinate with dependent services and users.

#### Token Lifetime Validation

Verify token lifetime settings are appropriate for your environment:

| Variable | Default | Production Recommendation |
|----------|---------|--------------------------|
| `JWT_EXPIRY_SECONDS` | 3600 (1 hour) | 1800-3600 (30 min - 1 hour) |
| `SESSION_EXPIRY_SECONDS` | 86400 (24 hours) | 86400-604800 (1-7 days) |

### 2. Admin Tools Configuration

Verify admin tools are disabled in production:

```bash
# Should be 'false' or unset in production
echo "ADMIN_TOOLS_ENABLED: ${ADMIN_TOOLS_ENABLED:-false}"
```

> **Security Note**: Admin endpoints (`/v1/admin/*`) are gated by the `ADMIN_TOOLS_ENABLED` flag. Keep disabled unless actively debugging.

### 3. Logging Configuration

Verify logging is configured for production:

```bash
# Production settings
echo "LOG_LEVEL: ${LOG_LEVEL:-INFO}"
echo "LOG_FORMAT: ${LOG_FORMAT:-json}"
```

Recommended production settings:
- `LOG_LEVEL=INFO` (avoid DEBUG in production)
- `LOG_FORMAT=json` (for structured log aggregation)

## Smoke Tests

After deployment, run these manual smoke tests to verify the service is operating correctly.

### Test 1: Health Check (`/healthz`)

```bash
# Replace with your service URL
IDENTITY_URL="http://localhost:8080"

curl -s "$IDENTITY_URL/healthz" | jq .
```

**Expected response**:
```json
{
  "status": "healthy",
  "service": "af-identity-service",
  "version": "0.2.0"
}
```

**Verify**:
- [ ] Status is `healthy`
- [ ] Version matches expected release version
- [ ] Response time is < 100ms

### Test 2: Token Introspection (`/v1/auth/token/introspect`)

Test with an invalid token to verify the endpoint responds correctly:

```bash
curl -s -X POST "$IDENTITY_URL/v1/auth/token/introspect" \
  -H "Authorization: Bearer invalid-token" \
  -H "Content-Type: application/json" | jq .
```

**Expected response** (401 Unauthorized):
```json
{
  "detail": {
    "error": "invalid_token",
    "message": "Invalid or expired token"
  }
}
```

**Verify**:
- [ ] Returns 401 status code
- [ ] Error message does not leak implementation details

### Test 3: GitHub Token Endpoint (`/v1/github/token`)

Test authentication requirement:

```bash
curl -s -X POST "$IDENTITY_URL/v1/github/token" \
  -H "Content-Type: application/json" \
  -d '{"force_refresh": false}' | jq .
```

**Expected response** (401 Unauthorized):
```json
{
  "detail": {
    "error": "missing_authorization",
    "message": "Authorization header required"
  }
}
```

**Verify**:
- [ ] Returns 401 without valid token
- [ ] Does not expose internal errors

### Test 4: OAuth Flow Start

Verify OAuth flow initialization works:

```bash
curl -s -X POST "$IDENTITY_URL/v1/auth/github/start" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uri": "https://example.com/callback"}' | jq .
```

**Expected response** (200 OK):
```json
{
  "authorization_url": "https://github.com/login/oauth/authorize?...",
  "state": "..."
}
```

**Verify**:
- [ ] Returns valid GitHub authorization URL
- [ ] State token is generated

## Version Bump Procedure

When preparing a new release, follow these steps:

### 1. Update Version Constant

Edit `af_identity_service/version.py`:

```python
__version__ = "0.2.0"  # Update to new version
```

This single file is the source of truth for:
- Health endpoint (`/healthz`) responses
- Package metadata (`pyproject.toml`)
- API documentation

### 2. Update CHANGELOG

Add a new section to `CHANGELOG.md`:

```markdown
## [0.2.0] - YYYY-MM-DD

### Added
- New feature description

### Changed
- Changed behavior description

### Fixed
- Bug fix description

### Security
- Security fix description
```

### 3. Verify Version Propagation

After updating, verify the version is correctly reflected:

```bash
# Check Python package version
python -c "from af_identity_service import __version__; print(__version__)"

# Start service and check health endpoint
curl -s http://localhost:8080/healthz | jq -r '.version'
```

Both should report the same version.

### 4. Tag the Release

```bash
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

## Production Deployment Checklist

Before deploying to production, verify all dependencies and run migrations.

### Pre-Deployment Verification

#### 1. Verify Production Dependencies

```bash
# Check PostgreSQL connectivity
PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB -c "SELECT 1;"

# Check Redis connectivity (with TLS)
# REDIS_PORT defaults to 6379 if not set
redis-cli -h $REDIS_HOST -p ${REDIS_PORT:-6379} --tls PING

# Verify encryption key format (64 hex characters)
python -c "import binascii; key='$GITHUB_TOKEN_ENC_KEY'; binascii.unhexlify(key); print(f'Key valid: {len(key)} chars')"
```

#### 2. Run Database Migrations

Migrations must complete successfully before starting the service in prod mode:

```bash
# Run migrations
python -m af_identity_service.migrations migrate

# Verify schema is correct
python -m af_identity_service.migrations verify

# Check migration status
python -m af_identity_service.migrations status
```

**Expected output from `migrate`:**
```
Creating table: af_users
Creating table: github_tokens
Migration complete. Tables created: 2
```

**Expected output from `verify`:**
```
Schema verification passed. All tables and columns match expected structure.
```

#### 3. Validate Environment Variables

```bash
# Required secrets (must be set, not shown)
echo "IDENTITY_JWT_SECRET: ${IDENTITY_JWT_SECRET:+SET}"
echo "GITHUB_CLIENT_ID: ${GITHUB_CLIENT_ID:+SET}"
echo "GITHUB_CLIENT_SECRET: ${GITHUB_CLIENT_SECRET:+SET}"
echo "GITHUB_TOKEN_ENC_KEY: ${GITHUB_TOKEN_ENC_KEY:+SET}"
echo "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:+SET}"

# Required config
echo "IDENTITY_ENVIRONMENT: ${IDENTITY_ENVIRONMENT}"  # Should be 'prod'
echo "POSTGRES_HOST: ${POSTGRES_HOST}"
echo "POSTGRES_DB: ${POSTGRES_DB}"
echo "REDIS_HOST: ${REDIS_HOST}"
echo "REDIS_TLS_ENABLED: ${REDIS_TLS_ENABLED}"  # Should be 'true'
```

### Post-Deployment Verification

After deploying the new version:

```bash
# Verify health endpoint shows correct version and healthy backends
curl -s "$SERVICE_URL/healthz" | jq .

# Expected response:
# {
#   "status": "healthy",
#   "service": "af-identity-service",
#   "version": "0.2.0",
#   "backends": {
#     "db": "ok",
#     "redis": "ok"
#   }
# }
```

### Migration Notes for v0.2.0

When upgrading from v0.1.0 to v0.2.0:

1. **In-memory to persistent storage**: Data from in-memory stores (dev mode) is not migrated. Users must re-authenticate after switching to prod mode.

2. **New environment variables required**:
   - `GITHUB_TOKEN_ENC_KEY` - 256-bit hex encryption key
   - `POSTGRES_*` - Database connection settings
   - `REDIS_*` - Redis connection settings

3. **Schema changes**: Run `python -m af_identity_service.migrations migrate` to create required tables.

4. **Rollback considerations**: If rolling back to v0.1.0, note that encrypted tokens in Postgres cannot be used by the in-memory store. Users would need to re-authenticate.

## Security Considerations

### Rotating IDENTITY_JWT_SECRET

When rotating the JWT secret for a new environment:

1. **Generate a new secret**:
   ```bash
   openssl rand -base64 32
   ```

2. **Update the environment variable** in your deployment configuration

3. **Coordinate the rotation**:
   - All existing AF JWTs will become invalid
   - Users will need to re-authenticate
   - Plan for a brief service disruption or use a rolling deployment strategy

4. **Never reuse secrets** between environments (dev, staging, production)

### GitHub Refresh Token Storage

> **⚠️ Development Warning**: The default `InMemoryGitHubTokenStore` is suitable for development only.

For production deployments:
- Replace with an encrypted backend (Redis with AES-256-GCM)
- Use a KMS for encryption key management
- Audit token access patterns

See [docs/identity/security.md](security.md) for detailed security guidance.

## Troubleshooting

### Health Check Returns 503

If `/healthz` returns `degraded` status:

1. Check the response body for failed dependencies
2. Verify database/cache connectivity if using external stores
3. Review logs for initialization errors

### Version Mismatch

If version in health response doesn't match expected:

1. Verify `af_identity_service/version.py` is updated
2. Reinstall the package: `pip install -e .`
3. Restart the service

### OAuth Flow Failures

If GitHub OAuth is not working:

1. Verify `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are correct
2. Check the OAuth App callback URL in GitHub settings
3. Review logs for `auth.github.callback.failure` events
