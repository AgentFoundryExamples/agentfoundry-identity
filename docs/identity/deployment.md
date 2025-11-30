# Production Deployment Guide

This document provides step-by-step instructions for deploying the Agent Foundry Identity Service to production environments with Google Cloud services (Cloud SQL, MemoryStore, Secret Manager, and Cloud Run).

> **⚠️ Warning**: The default in-memory stores are for development only. Production deployments **must** use encrypted Postgres (Cloud SQL) for token and user storage, and Redis (MemoryStore) for session management. See the [Security Notes](#security-notes) section for details.

## Prerequisites

Before starting, ensure you have:

1. **Google Cloud Project** with billing enabled
2. **gcloud CLI** installed and authenticated (`gcloud auth login`)
3. **Required APIs enabled**:
   - Cloud SQL Admin API
   - Cloud Memorystore for Redis API
   - Secret Manager API
   - Cloud Run API
   - Artifact Registry API
4. **GitHub OAuth App** created at https://github.com/settings/developers
5. **IAM permissions** to create Cloud SQL instances, Redis instances, secrets, and Cloud Run services

Enable required APIs:
```bash
gcloud services enable \
  sqladmin.googleapis.com \
  redis.googleapis.com \
  secretmanager.googleapis.com \
  run.googleapis.com \
  artifactregistry.googleapis.com
```

## Architecture Overview

```
┌─────────────┐     ┌─────────────────────┐
│  Cloud Run  │────▶│   Secret Manager    │
│  (Service)  │     │  (JWT/OAuth/Enc Keys)│
└──────┬──────┘     └─────────────────────┘
       │
       ├─────────────────────────────────────┐
       ▼                                     ▼
┌─────────────────────┐         ┌─────────────────────┐
│     Cloud SQL       │         │     MemoryStore     │
│   (PostgreSQL)      │         │      (Redis)        │
│  - af_users table   │         │  - Sessions         │
│  - github_tokens    │         │  - OAuth state      │
│    (encrypted)      │         │                     │
└─────────────────────┘         └─────────────────────┘
```

## Step 1: Provision Cloud SQL (PostgreSQL)

### Create Cloud SQL Instance

```bash
# Set your project ID
export PROJECT_ID="your-project-id"
export REGION="us-central1"

# Create PostgreSQL instance with encryption at rest
gcloud sql instances create af-identity-db \
  --project=$PROJECT_ID \
  --region=$REGION \
  --database-version=POSTGRES_15 \
  --tier=db-f1-micro \
  --storage-size=10GB \
  --storage-type=SSD \
  --storage-auto-increase \
  --backup-start-time=02:00 \
  --maintenance-window-day=SUN \
  --maintenance-window-hour=03 \
  --require-ssl \
  --no-assign-ip \
  --network=default

# Note: --require-ssl enforces encrypted connections
# --no-assign-ip with --network uses private IP for better security
```

### Create Database and User

```bash
# Create the database
gcloud sql databases create identity_service \
  --instance=af-identity-db \
  --project=$PROJECT_ID

# Generate a strong password
DB_PASSWORD=$(openssl rand -base64 24)

# Create database user
gcloud sql users create identity_user \
  --instance=af-identity-db \
  --password="$DB_PASSWORD" \
  --project=$PROJECT_ID

# Store password in Secret Manager (see Step 3)
echo "Generated DB password - store securely: $DB_PASSWORD"
```

### Connection Configuration

For Cloud Run deployments, use the Cloud SQL instance connection name:

```bash
# Get instance connection name
gcloud sql instances describe af-identity-db \
  --project=$PROJECT_ID \
  --format="value(connectionName)"

# Output: project-id:region:af-identity-db
```

### Database Connection Timeouts

Configure connection pooling to handle Cloud SQL connection limits:

| Setting | Recommended Value | Description |
|---------|-------------------|-------------|
| Pool Size | 5 | Max connections per instance |
| Max Overflow | 10 | Additional connections under load |
| Pool Timeout | 30s | Wait time for available connection |
| Pool Recycle | 1800s | Recycle connections every 30 min |

The service handles these settings automatically. For high-traffic deployments, consider Cloud SQL connection pooler or PgBouncer.

## Step 2: Provision MemoryStore (Redis)

### Create Redis Instance

```bash
# Create Redis instance with TLS
gcloud redis instances create af-identity-redis \
  --project=$PROJECT_ID \
  --region=$REGION \
  --tier=basic \
  --size=1 \
  --redis-version=redis_7_0 \
  --transit-encryption-mode=SERVER_AUTHENTICATION \
  --network=default

# Note: --transit-encryption-mode enables TLS
```

### Get Connection Details

```bash
# Get Redis host and port
gcloud redis instances describe af-identity-redis \
  --project=$PROJECT_ID \
  --region=$REGION \
  --format="value(host,port)"

# For TLS-enabled Redis, also get the CA certificate
gcloud redis instances describe af-identity-redis \
  --project=$PROJECT_ID \
  --region=$REGION \
  --format="value(serverCaCerts[0].cert)"
```

### Redis Fallback Guidance

If Redis becomes unavailable:

1. **Immediate impact**: New sessions cannot be created; existing JWT tokens remain valid until expiry
2. **Health endpoint**: Returns `degraded` status with `redis: unavailable`
3. **Recovery**: Service automatically reconnects when Redis is restored
4. **Scaling**: Scale to zero instances during extended Redis maintenance

> **Note**: Redis is required for production. The in-memory session store does not support distributed deployments and loses all sessions on restart.

## Step 3: Configure Secret Manager

Store all sensitive values in Secret Manager:

### Create Secrets

```bash
# Generate JWT secret (minimum 32 characters)
JWT_SECRET=$(openssl rand -base64 32)

# Generate token encryption key (256-bit = 32 bytes = 64 hex chars)
TOKEN_ENC_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Create secrets in Secret Manager
echo -n "$JWT_SECRET" | gcloud secrets create identity-jwt-secret \
  --data-file=- \
  --project=$PROJECT_ID

echo -n "$TOKEN_ENC_KEY" | gcloud secrets create github-token-enc-key \
  --data-file=- \
  --project=$PROJECT_ID

echo -n "your-github-client-id" | gcloud secrets create github-client-id \
  --data-file=- \
  --project=$PROJECT_ID

echo -n "your-github-client-secret" | gcloud secrets create github-client-secret \
  --data-file=- \
  --project=$PROJECT_ID

echo -n "$DB_PASSWORD" | gcloud secrets create postgres-password \
  --data-file=- \
  --project=$PROJECT_ID
```

### IAM Permissions

Grant the Cloud Run service account access to secrets:

```bash
# Get the default compute service account
SERVICE_ACCOUNT="${PROJECT_ID}@${PROJECT_ID}.iam.gserviceaccount.com"

# Or create a dedicated service account
gcloud iam service-accounts create af-identity-service \
  --project=$PROJECT_ID \
  --display-name="AF Identity Service"

SERVICE_ACCOUNT="af-identity-service@${PROJECT_ID}.iam.gserviceaccount.com"

# Grant Secret Manager access
for SECRET in identity-jwt-secret github-token-enc-key github-client-id github-client-secret postgres-password; do
  gcloud secrets add-iam-policy-binding $SECRET \
    --project=$PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/secretmanager.secretAccessor"
done

# Grant Cloud SQL Client role for Cloud SQL Auth Proxy
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/cloudsql.client"
```

## Step 4: Run Database Migrations

Migrations must be run before the service starts in production mode.

### Option A: Run Locally (with Cloud SQL Auth Proxy)

```bash
# Download and start Cloud SQL Auth Proxy
curl -o cloud_sql_proxy https://dl.google.com/cloudsql/cloud_sql_proxy.linux.amd64
chmod +x cloud_sql_proxy

# Start proxy in background
./cloud_sql_proxy -instances=${PROJECT_ID}:${REGION}:af-identity-db=tcp:5432 &

# Export connection variables
export POSTGRES_HOST=127.0.0.1
export POSTGRES_PORT=5432
export POSTGRES_DB=identity_service
export POSTGRES_USER=identity_user
export POSTGRES_PASSWORD="$DB_PASSWORD"

# Run migrations
python -m af_identity_service.migrations migrate

# Verify schema
python -m af_identity_service.migrations verify
```

### Option B: Run as Cloud Run Job

For operators without direct database access:

```bash
# Build and push migration job image to Artifact Registry
gcloud builds submit \
  --tag ${REGION}-docker.pkg.dev/${PROJECT_ID}/af-identity/af-identity-migrations:latest .

# Create Cloud Run job for migrations
gcloud run jobs create af-identity-migrations \
  --project=$PROJECT_ID \
  --region=$REGION \
  --image=${REGION}-docker.pkg.dev/${PROJECT_ID}/af-identity/af-identity-migrations:latest \
  --set-cloudsql-instances=${PROJECT_ID}:${REGION}:af-identity-db \
  --set-env-vars="POSTGRES_HOST=/cloudsql/${PROJECT_ID}:${REGION}:af-identity-db" \
  --set-env-vars="POSTGRES_PORT=5432" \
  --set-env-vars="POSTGRES_DB=identity_service" \
  --set-env-vars="POSTGRES_USER=identity_user" \
  --set-secrets="POSTGRES_PASSWORD=postgres-password:latest" \
  --command="python,-m,af_identity_service.migrations,migrate" \
  --service-account="${SERVICE_ACCOUNT}"

# Execute migration job
gcloud run jobs execute af-identity-migrations \
  --project=$PROJECT_ID \
  --region=$REGION \
  --wait
```

### Migration Commands

| Command | Description |
|---------|-------------|
| `migrate` | Create required tables (idempotent, safe to run multiple times) |
| `verify` | Verify schema matches expected structure |
| `status` | Show current migration status |

## Step 5: Deploy to Cloud Run

### Build Container Image

```bash
# Build and push to Artifact Registry (recommended over Container Registry)
gcloud artifacts repositories create af-identity \
  --repository-format=docker \
  --location=$REGION \
  --project=$PROJECT_ID

# Configure Docker authentication
gcloud auth configure-docker ${REGION}-docker.pkg.dev

# Build and push
gcloud builds submit \
  --tag ${REGION}-docker.pkg.dev/${PROJECT_ID}/af-identity/af-identity-service:latest \
  --project=$PROJECT_ID
```

### Deploy Service

```bash
# Get Redis host
REDIS_HOST=$(gcloud redis instances describe af-identity-redis \
  --project=$PROJECT_ID \
  --region=$REGION \
  --format="value(host)")

# Deploy to Cloud Run
gcloud run deploy af-identity-service \
  --project=$PROJECT_ID \
  --region=$REGION \
  --image=${REGION}-docker.pkg.dev/${PROJECT_ID}/af-identity/af-identity-service:latest \
  --platform=managed \
  --service-account="${SERVICE_ACCOUNT}" \
  --set-cloudsql-instances=${PROJECT_ID}:${REGION}:af-identity-db \
  --set-env-vars="IDENTITY_ENVIRONMENT=prod" \
  --set-env-vars="POSTGRES_HOST=/cloudsql/${PROJECT_ID}:${REGION}:af-identity-db" \
  --set-env-vars="POSTGRES_PORT=5432" \
  --set-env-vars="POSTGRES_DB=identity_service" \
  --set-env-vars="POSTGRES_USER=identity_user" \
  --set-env-vars="REDIS_HOST=${REDIS_HOST}" \
  --set-env-vars="REDIS_PORT=6379" \
  --set-env-vars="REDIS_TLS_ENABLED=true" \
  --set-env-vars="LOG_LEVEL=INFO" \
  --set-env-vars="LOG_FORMAT=json" \
  --set-secrets="IDENTITY_JWT_SECRET=identity-jwt-secret:latest" \
  --set-secrets="GITHUB_CLIENT_ID=github-client-id:latest" \
  --set-secrets="GITHUB_CLIENT_SECRET=github-client-secret:latest" \
  --set-secrets="GITHUB_TOKEN_ENC_KEY=github-token-enc-key:latest" \
  --set-secrets="POSTGRES_PASSWORD=postgres-password:latest" \
  --min-instances=1 \
  --max-instances=10 \
  --memory=512Mi \
  --cpu=1 \
  --timeout=60s \
  --concurrency=80 \
  --allow-unauthenticated

# Note: --min-instances=1 prevents cold starts
# Adjust --max-instances based on expected load
```

### Configure VPC Connector (for Private IP)

If using private IP for Cloud SQL and Redis:

```bash
# Create VPC connector
gcloud compute networks vpc-access connectors create af-identity-connector \
  --project=$PROJECT_ID \
  --region=$REGION \
  --network=default \
  --range=10.8.0.0/28

# Add to deployment
gcloud run deploy af-identity-service \
  --vpc-connector=af-identity-connector \
  --vpc-egress=private-ranges-only \
  ... # other flags
```

## Step 6: Verify Deployment

### Health Check

```bash
# Get service URL
SERVICE_URL=$(gcloud run services describe af-identity-service \
  --project=$PROJECT_ID \
  --region=$REGION \
  --format="value(status.url)")

# Check health
curl -s "${SERVICE_URL}/healthz" | jq .
```

**Expected Response:**
```json
{
  "status": "healthy",
  "service": "af-identity-service",
  "version": "0.1.0",
  "backends": {
    "db": "ok",
    "redis": "ok"
  }
}
```

### Smoke Tests

```bash
# Test OAuth flow initialization
curl -s -X POST "${SERVICE_URL}/v1/auth/github/start" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uri": "https://your-app.com/callback"}' | jq .

# Test authentication requirement
curl -s -X POST "${SERVICE_URL}/v1/auth/token/introspect" \
  -H "Authorization: Bearer invalid-token" | jq .
```

## Operational Tasks

### Rotating Encryption Keys

The service supports non-disruptive key rotation using dual-key mode:

1. **Set up old key**: Before rotating, set `GITHUB_TOKEN_ENC_KEY_OLD` to the current key
2. **Deploy new key**: Update `GITHUB_TOKEN_ENC_KEY` to the new key
3. **Re-encrypt tokens**: Run migration to re-encrypt existing tokens with new key
4. **Remove old key**: After all tokens are re-encrypted, remove `GITHUB_TOKEN_ENC_KEY_OLD`

```bash
# Generate new encryption key
NEW_ENC_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Get current key and set as OLD
CURRENT_KEY=$(gcloud secrets versions access latest --secret=github-token-enc-key --project=$PROJECT_ID)
echo -n "$CURRENT_KEY" | gcloud secrets create github-token-enc-key-old \
  --data-file=- \
  --project=$PROJECT_ID

# Update current secret with new key
echo -n "$NEW_ENC_KEY" | gcloud secrets versions add github-token-enc-key \
  --data-file=- \
  --project=$PROJECT_ID

# Update Cloud Run with both keys
gcloud run deploy af-identity-service \
  --set-secrets="GITHUB_TOKEN_ENC_KEY=github-token-enc-key:latest,GITHUB_TOKEN_ENC_KEY_OLD=github-token-enc-key-old:latest" \
  ... # other flags

# After re-encryption is complete, remove old key
gcloud run deploy af-identity-service \
  --update-secrets="GITHUB_TOKEN_ENC_KEY=github-token-enc-key:latest" \
  --remove-env-vars="GITHUB_TOKEN_ENC_KEY_OLD" \
  ... # other flags
```

> **Note**: Token re-encryption happens lazily when tokens are accessed (e.g., during `/v1/github/token` requests). For immediate re-encryption of all tokens, you can create a Cloud Run job that iterates through users and triggers token refresh:
>
> ```bash
> # Create a re-encryption job (requires custom script in your codebase)
> gcloud run jobs create af-identity-reencrypt \
>   --image=${REGION}-docker.pkg.dev/${PROJECT_ID}/af-identity/af-identity-service:latest \
>   --set-cloudsql-instances=${PROJECT_ID}:${REGION}:af-identity-db \
>   --set-secrets="GITHUB_TOKEN_ENC_KEY=github-token-enc-key:latest,GITHUB_TOKEN_ENC_KEY_OLD=github-token-enc-key-old:latest" \
>   --command="python,-c,from af_identity_service.migrations import reencrypt_tokens; reencrypt_tokens()"
> ```
>
> Note: The `reencrypt_tokens` function is not currently implemented. As an alternative, wait for natural token access to re-encrypt lazily, or invalidate tokens to force users to re-authenticate.

### Rotating JWT Secret

> **⚠️ Warning**: Rotating `IDENTITY_JWT_SECRET` invalidates all existing AF JWTs. Users must re-authenticate.

```bash
# Generate new JWT secret
NEW_JWT_SECRET=$(openssl rand -base64 32)

# Update secret
echo -n "$NEW_JWT_SECRET" | gcloud secrets versions add identity-jwt-secret \
  --data-file=- \
  --project=$PROJECT_ID

# Redeploy to pick up new secret
gcloud run services update af-identity-service \
  --project=$PROJECT_ID \
  --region=$REGION
```

### Monitoring and Alerting

Configure Cloud Monitoring for:

1. **Health check failures**: Alert when `/healthz` returns non-200
2. **Error rate**: Alert when 5xx responses exceed threshold
3. **Latency**: Alert when p95 latency exceeds 500ms
4. **Database connections**: Monitor Cloud SQL connection count
5. **Redis availability**: Monitor MemoryStore uptime

```bash
# Create uptime check
gcloud monitoring uptime-checks create http af-identity-health \
  --project=$PROJECT_ID \
  --display-name="AF Identity Health Check" \
  --uri="${SERVICE_URL}/healthz"
```

## Security Notes

### In-Memory Stores Are Dev-Only

> **⚠️ Critical**: In-memory stores (`IDENTITY_ENVIRONMENT=dev`) must **never** be used in production.

| Store Type | Dev Mode | Prod Mode (Required) |
|------------|----------|----------------------|
| User Storage | InMemoryUserRepository | PostgresUserRepository |
| Token Storage | InMemoryGitHubTokenStore | PostgresGitHubTokenStore (encrypted) |
| Session Storage | InMemorySessionStore | RedisSessionStore |

Dev mode limitations:
- Data is lost on service restart
- Does not support distributed deployments (multiple instances)
- No encryption at rest
- Not suitable for any real user data

### Encryption Requirements

Production deployments must ensure:

1. **Postgres encryption**:
   - Enable SSL/TLS for connections (`--require-ssl` on Cloud SQL)
   - Use private IP when possible (`--no-assign-ip`)
   - Encrypt database storage (Cloud SQL encrypts by default)

2. **Redis encryption**:
   - Enable TLS (`--transit-encryption-mode=SERVER_AUTHENTICATION`)
   - Use private IP via VPC connector
   - Set `REDIS_TLS_ENABLED=true` in environment

3. **Token encryption**:
   - Set `GITHUB_TOKEN_ENC_KEY` to a 256-bit key
   - Store key in Secret Manager (never in environment directly)
   - Rotate keys periodically (see [Rotating Encryption Keys](#rotating-encryption-keys))

### Network Security

- Deploy Cloud SQL and Redis with private IPs only
- Use VPC connector for Cloud Run to access private resources
- Configure firewall rules to restrict database access
- Enable Cloud SQL audit logging

## Troubleshooting

### Service Fails to Start

1. Check Cloud Run logs: `gcloud run services logs read af-identity-service`
2. Verify all secrets are accessible by the service account
3. Ensure migrations have been run
4. Check Cloud SQL and Redis connectivity

### Database Connection Errors

```
Error: Connection refused
```

- Verify Cloud SQL instance is running
- Check `--set-cloudsql-instances` flag is correct
- Ensure service account has `cloudsql.client` role

### Redis Connection Errors

```
Error: Redis connection timeout
```

- Verify Redis instance is running
- Check VPC connector is configured
- Ensure `REDIS_HOST` is the private IP
- Verify `REDIS_TLS_ENABLED` matches instance configuration

### Secret Access Errors

```
Error: Permission denied accessing secret
```

- Verify service account has `secretAccessor` role on each secret
- Check secret names match exactly
- Ensure secrets exist in the same project

## Quick Reference

### Environment Variables Summary

| Variable | Required | Secret Manager | Description |
|----------|----------|----------------|-------------|
| `IDENTITY_ENVIRONMENT` | Yes | No | Set to `prod` |
| `IDENTITY_JWT_SECRET` | Yes | **Yes** | JWT signing key |
| `GITHUB_CLIENT_ID` | Yes | **Yes** | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | Yes | **Yes** | GitHub OAuth client secret |
| `GITHUB_TOKEN_ENC_KEY` | Yes (prod) | **Yes** | Token encryption key |
| `POSTGRES_HOST` | Yes (prod) | No | Cloud SQL socket path |
| `POSTGRES_DB` | Yes (prod) | No | Database name |
| `POSTGRES_USER` | Yes (prod) | No | Database user |
| `POSTGRES_PASSWORD` | Yes (prod) | **Yes** | Database password |
| `REDIS_HOST` | Yes (prod) | No | Redis private IP |
| `REDIS_TLS_ENABLED` | Yes (prod) | No | Set to `true` |

### Deployment Checklist

- [ ] Cloud SQL instance created with SSL required
- [ ] Redis instance created with TLS enabled
- [ ] All secrets stored in Secret Manager
- [ ] Service account created with correct IAM roles
- [ ] Database migrations executed successfully
- [ ] VPC connector configured (if using private IPs)
- [ ] Cloud Run service deployed
- [ ] Health check returns `healthy` status
- [ ] Smoke tests pass
- [ ] Monitoring and alerting configured
