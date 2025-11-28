# File Summaries

Heuristic summaries of source files based on filenames, extensions, and paths.

Schema Version: 2.0

Total files: 45

## af_identity_service/__init__.py
**Language:** Python  
**Role:** module-init  
**Role Justification:** module initialization file '__init__'  
**Size:** 1.14 KB  
**LOC:** 6  
**TODOs/FIXMEs:** 0  

## af_identity_service/app.py
**Language:** Python  
**Role:** entry-point  
**Role Justification:** common entry point name 'app'  
**Size:** 11.68 KB  
**LOC:** 245  
**TODOs/FIXMEs:** 0  
**Declarations:** 4  
**Top-level declarations:**
  - class RequestIDMiddleware
  - function create_health_router
  - function create_app
  - function main
**External Dependencies:**
  - **Stdlib:** `typing.Any`, `uuid`
  - **Third-party:** `fastapi.APIRouter`, `fastapi.FastAPI`, `fastapi.responses.JSONResponse`, `uvicorn`

## af_identity_service/config.py
**Language:** Python  
**Role:** configuration  
**Role Justification:** configuration file name 'config'  
**Size:** 12.60 KB  
**LOC:** 279  
**TODOs/FIXMEs:** 0  
**Declarations:** 4  
**Top-level declarations:**
  - class Settings
  - class ConfigurationError
  - function validate_prod_settings
  - function get_settings
**External Dependencies:**
  - **Stdlib:** `functools.lru_cache`, `typing.Literal`
  - **Third-party:** `pydantic.Field`, `pydantic.SecretStr`, `pydantic.field_validator`, `pydantic_settings.BaseSettings`, `pydantic_settings.SettingsConfigDict`

## af_identity_service/dependencies.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 21.89 KB  
**LOC:** 467  
**TODOs/FIXMEs:** 0  
**Declarations:** 7  
**Top-level declarations:**
  - class SessionStore
  - class InMemorySessionStore
  - class GitHubDriver
  - class PlaceholderGitHubDriver
  - class DependencyContainer
  - function get_dependencies
  - function reset_dependencies
**External Dependencies:**
  - **Stdlib:** `abc.ABC`, `abc.abstractmethod`, `typing.Any`, `typing.TYPE_CHECKING`

## af_identity_service/github/__init__.py
**Language:** Python  
**Role:** module-init  
**Role Justification:** module initialization file '__init__'  
**Size:** 1.16 KB  
**LOC:** 8  
**TODOs/FIXMEs:** 0  

## af_identity_service/github/driver.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 7.36 KB  
**LOC:** 151  
**TODOs/FIXMEs:** 0  
**Declarations:** 3  
**Top-level declarations:**
  - class GitHubOAuthDriverError
  - class GitHubOAuthDriver
  - class StubGitHubOAuthDriver
**External Dependencies:**
  - **Stdlib:** `abc.ABC`, `abc.abstractmethod`, `datetime.datetime`, `datetime.timedelta`, `datetime.timezone`
  - **Third-party:** `structlog`

## af_identity_service/logging.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 5.81 KB  
**LOC:** 104  
**TODOs/FIXMEs:** 0  
**Declarations:** 4  
**Top-level declarations:**
  - function add_service_context
  - function add_request_context
  - function configure_logging
  - function get_logger
**External Dependencies:**
  - **Stdlib:** `contextvars.ContextVar`, `logging`, `sys`, `typing.Any`
  - **Third-party:** `structlog`

## af_identity_service/migrations/__init__.py
**Language:** Python  
**Role:** module-init  
**Role Justification:** module initialization file '__init__'  
**Size:** 10.08 KB  
**LOC:** 223  
**TODOs/FIXMEs:** 0  
**Declarations:** 5  
**Top-level declarations:**
  - function get_connection_string
  - function run_migrate
  - function run_verify
  - function run_status
  - function main
**External Dependencies:**
  - **Stdlib:** `argparse`, `os`, `sys`
  - **Third-party:** `sqlalchemy.URL`, `sqlalchemy.create_engine`, `sqlalchemy.text`, `structlog`

## af_identity_service/migrations/__main__.py
**Language:** Python  
**Role:** entry-point  
**Role Justification:** common entry point name '__main__'  
**Size:** 1.11 KB  
**LOC:** 7  
**TODOs/FIXMEs:** 0  
**External Dependencies:**
  - **Stdlib:** `sys`

## af_identity_service/migrations/user_schema.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 6.59 KB  
**LOC:** 128  
**TODOs/FIXMEs:** 0  
**Declarations:** 2  
**Top-level declarations:**
  - function create_af_users_table
  - function verify_af_users_schema
**External Dependencies:**
  - **Third-party:** `sqlalchemy.BigInteger`, `sqlalchemy.Column`, `sqlalchemy.DateTime`, `sqlalchemy.Index`, `sqlalchemy.String`
    _(and 6 more)_

## af_identity_service/models/__init__.py
**Language:** Python  
**Role:** module-init  
**Role Justification:** module initialization file '__init__'  
**Size:** 1.48 KB  
**LOC:** 16  
**TODOs/FIXMEs:** 0  

## af_identity_service/models/github.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 3.63 KB  
**LOC:** 66  
**TODOs/FIXMEs:** 0  
**Declarations:** 2  
**Top-level declarations:**
  - class GitHubIdentity
  - class GitHubOAuthResult
**External Dependencies:**
  - **Stdlib:** `dataclasses.dataclass`, `datetime.datetime`, `datetime.timezone`
  - **Third-party:** `pydantic.BaseModel`, `pydantic.Field`

## af_identity_service/models/session.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 4.45 KB  
**LOC:** 84  
**TODOs/FIXMEs:** 0  
**Declarations:** 1  
**Top-level declarations:**
  - class Session
**External Dependencies:**
  - **Stdlib:** `datetime.datetime`, `datetime.timezone`, `uuid.UUID`, `uuid.uuid4`
  - **Third-party:** `pydantic.BaseModel`, `pydantic.Field`, `pydantic.field_validator`

## af_identity_service/models/token.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 3.23 KB  
**LOC:** 57  
**TODOs/FIXMEs:** 0  
**Declarations:** 1  
**Top-level declarations:**
  - class AFTokenIntrospection
**External Dependencies:**
  - **Stdlib:** `datetime.datetime`, `datetime.timezone`, `uuid.UUID`
  - **Third-party:** `pydantic.BaseModel`, `pydantic.Field`, `pydantic.field_validator`

## af_identity_service/models/user.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 2.91 KB  
**LOC:** 49  
**TODOs/FIXMEs:** 0  
**Declarations:** 1  
**Top-level declarations:**
  - class AFUser
**External Dependencies:**
  - **Stdlib:** `datetime.datetime`, `datetime.timezone`, `uuid.UUID`, `uuid.uuid4`
  - **Third-party:** `pydantic.BaseModel`, `pydantic.Field`

## af_identity_service/routes/__init__.py
**Language:** Python  
**Role:** module-init  
**Role Justification:** module initialization file '__init__'  
**Size:** 1.30 KB  
**LOC:** 11  
**TODOs/FIXMEs:** 0  

## af_identity_service/routes/admin.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 6.21 KB  
**LOC:** 126  
**TODOs/FIXMEs:** 0  
**Declarations:** 4  
**Top-level declarations:**
  - class SessionInfo
  - class UserSessionsResponse
  - class ErrorResponse
  - function create_admin_router
**External Dependencies:**
  - **Stdlib:** `uuid.UUID`
  - **Third-party:** `fastapi.APIRouter`, `fastapi.Depends`, `fastapi.HTTPException`, `pydantic.BaseModel`, `pydantic.Field`
    _(and 1 more)_

## af_identity_service/routes/auth_github.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 6.54 KB  
**LOC:** 144  
**TODOs/FIXMEs:** 0  
**Declarations:** 7  
**Top-level declarations:**
  - class StartRequest
  - class StartResponse
  - class CallbackRequest
  - class CallbackUserResponse
  - class CallbackResponse
  - class ErrorResponse
  - function create_auth_github_router
**External Dependencies:**
  - **Third-party:** `fastapi.APIRouter`, `fastapi.HTTPException`, `fastapi.responses.JSONResponse`, `pydantic.BaseModel`, `pydantic.Field`
    _(and 1 more)_

## af_identity_service/routes/github_token.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 6.36 KB  
**LOC:** 142  
**TODOs/FIXMEs:** 0  
**Declarations:** 4  
**Top-level declarations:**
  - class GitHubTokenRequest
  - class GitHubTokenResponse
  - class ErrorResponse
  - function create_github_token_router
**External Dependencies:**
  - **Third-party:** `fastapi.APIRouter`, `fastapi.Depends`, `fastapi.HTTPException`, `pydantic.BaseModel`, `pydantic.Field`
    _(and 1 more)_

## af_identity_service/routes/me.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 4.53 KB  
**LOC:** 102  
**TODOs/FIXMEs:** 0  
**Declarations:** 3  
**Top-level declarations:**
  - class MeResponse
  - class ErrorResponse
  - function create_me_router
**External Dependencies:**
  - **Third-party:** `fastapi.APIRouter`, `fastapi.Depends`, `pydantic.BaseModel`, `pydantic.Field`, `structlog`

## af_identity_service/routes/session.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 6.71 KB  
**LOC:** 146  
**TODOs/FIXMEs:** 0  
**Declarations:** 4  
**Top-level declarations:**
  - class RevokeSessionRequest
  - class RevokeSessionResponse
  - class ErrorResponse
  - function create_session_router
**External Dependencies:**
  - **Third-party:** `fastapi.APIRouter`, `fastapi.HTTPException`, `fastapi.Header`, `pydantic.BaseModel`, `pydantic.Field`
    _(and 1 more)_

## af_identity_service/routes/token.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 4.92 KB  
**LOC:** 97  
**TODOs/FIXMEs:** 0  
**Declarations:** 2  
**Top-level declarations:**
  - class ErrorResponse
  - function create_token_router
**External Dependencies:**
  - **Third-party:** `fastapi.APIRouter`, `fastapi.HTTPException`, `fastapi.Header`, `pydantic.BaseModel`, `pydantic.Field`
    _(and 1 more)_

## af_identity_service/security/__init__.py
**Language:** Python  
**Role:** module-init  
**Role Justification:** module initialization file '__init__'  
**Size:** 2.01 KB  
**LOC:** 44  
**TODOs/FIXMEs:** 0  

## af_identity_service/security/auth.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 13.43 KB  
**LOC:** 311  
**TODOs/FIXMEs:** 0  
**Declarations:** 10  
**Top-level declarations:**
  - class AuthenticationError
  - class InvalidTokenError
  - class SessionNotFoundError
  - class MissingAuthorizationError
  - class SessionOwnershipError
  - class AuthenticatedContext
  - function parse_authorization_header
  - async function authenticate_request
  - async function revoke_session
  - function create_auth_dependency
**External Dependencies:**
  - **Stdlib:** `dataclasses.dataclass`, `datetime.datetime`, `datetime.timezone`, `typing.Annotated`, `typing.Callable`
    _(and 2 more)_
  - **Third-party:** `fastapi.Depends`, `fastapi.HTTPException`, `fastapi.Header`, `structlog`

## af_identity_service/security/jwt.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 8.90 KB  
**LOC:** 209  
**TODOs/FIXMEs:** 0  
**Declarations:** 9  
**Top-level declarations:**
  - class JWTMintError
  - class JWTValidationError
  - class JWTExpiredError
  - function _base64url_decode
  - function _base64url_encode
  - function _create_signature
  - function mint_af_jwt
  - class JWTClaims
  - function validate_af_jwt
**External Dependencies:**
  - **Stdlib:** `base64`, `datetime.datetime`, `datetime.timezone`, `hmac`, `json`
    _(and 1 more)_
  - **Third-party:** `structlog`

## af_identity_service/services/__init__.py
**Language:** Python  
**Role:** module-init  
**Role Justification:** module initialization file '__init__'  
**Size:** 1.23 KB  
**LOC:** 15  
**TODOs/FIXMEs:** 0  

## af_identity_service/services/github_tokens.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 6.48 KB  
**LOC:** 134  
**TODOs/FIXMEs:** 0  
**Declarations:** 5  
**Top-level declarations:**
  - class GitHubTokenServiceError
  - class RefreshTokenMissingError
  - class TokenRefreshError
  - class GitHubAccessTokenResult
  - class GitHubTokenService
**External Dependencies:**
  - **Stdlib:** `dataclasses.dataclass`, `datetime.datetime`, `uuid.UUID`
  - **Third-party:** `structlog`

## af_identity_service/services/oauth.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 11.81 KB  
**LOC:** 256  
**TODOs/FIXMEs:** 0  
**Declarations:** 9  
**Top-level declarations:**
  - class OAuthServiceError
  - class InvalidStateError
  - class GitHubDriverError
  - class StateStore
  - class _StateEntry
  - class InMemoryStateStore
  - class OAuthStartResult
  - class OAuthCallbackResult
  - class OAuthService
**External Dependencies:**
  - **Stdlib:** `abc.ABC`, `abc.abstractmethod`, `dataclasses.dataclass`, `datetime.datetime`, `datetime.timedelta`
    _(and 4 more)_
  - **Third-party:** `structlog`

## af_identity_service/stores/__init__.py
**Language:** Python  
**Role:** module-init  
**Role Justification:** module initialization file '__init__'  
**Size:** 1.48 KB  
**LOC:** 18  
**TODOs/FIXMEs:** 0  

## af_identity_service/stores/github_token_store.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 12.39 KB  
**LOC:** 260  
**TODOs/FIXMEs:** 0  
**Declarations:** 5  
**Top-level declarations:**
  - class GitHubTokenStoreError
  - class RefreshTokenNotFoundError
  - class GitHubTokenStore
  - class _StoredTokens
  - class InMemoryGitHubTokenStore
**External Dependencies:**
  - **Stdlib:** `abc.ABC`, `abc.abstractmethod`, `datetime.datetime`, `datetime.timedelta`, `datetime.timezone`
    _(and 2 more)_
  - **Third-party:** `structlog`

## af_identity_service/stores/postgres_user_repository.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 10.80 KB  
**LOC:** 208  
**TODOs/FIXMEs:** 0  
**Declarations:** 3  
**Top-level declarations:**
  - class DuplicateGitHubUserError
  - class DatabaseConnectionError
  - class PostgresUserRepository
**External Dependencies:**
  - **Stdlib:** `datetime.datetime`, `datetime.timezone`, `uuid.UUID`, `uuid.uuid4`
  - **Third-party:** `sqlalchemy.dialects.postgresql.insert`, `sqlalchemy.engine.Engine`, `sqlalchemy.exc.IntegrityError`, `sqlalchemy.exc.OperationalError`, `sqlalchemy.select`
    _(and 1 more)_

## af_identity_service/stores/session_store.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 8.06 KB  
**LOC:** 184  
**TODOs/FIXMEs:** 0  
**Declarations:** 2  
**Top-level declarations:**
  - class SessionStore
  - class InMemorySessionStore
**External Dependencies:**
  - **Stdlib:** `abc.ABC`, `abc.abstractmethod`, `datetime.datetime`, `datetime.timezone`, `threading`
    _(and 1 more)_
  - **Third-party:** `structlog`

## af_identity_service/stores/user_store.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 7.01 KB  
**LOC:** 150  
**TODOs/FIXMEs:** 0  
**Declarations:** 2  
**Top-level declarations:**
  - class AFUserRepository
  - class InMemoryUserRepository
**External Dependencies:**
  - **Stdlib:** `abc.ABC`, `abc.abstractmethod`, `datetime.datetime`, `datetime.timezone`, `threading`
    _(and 1 more)_
  - **Third-party:** `structlog`

## af_identity_service/version.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 1.47 KB  
**LOC:** 17  
**TODOs/FIXMEs:** 0  

## tests/__init__.py
**Language:** Python  
**Role:** test  
**Role Justification:** located in 'tests' directory  
**Size:** 0.93 KB  
**LOC:** 1  
**TODOs/FIXMEs:** 0  

## tests/test_app.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 5.32 KB  
**LOC:** 95  
**TODOs/FIXMEs:** 0  
**Declarations:** 6  
**Top-level declarations:**
  - function valid_settings
  - function client
  - class TestHealthEndpoint
  - class TestRequestIDMiddleware
  - class TestAppFactory
  - class TestAPIDocumentation
**External Dependencies:**
  - **Stdlib:** `uuid`
  - **Third-party:** `fastapi.FastAPI`, `fastapi.testclient.TestClient`, `pytest`

## tests/test_auth_github_routes.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 23.29 KB  
**LOC:** 505  
**TODOs/FIXMEs:** 0  
**Declarations:** 17  
**Top-level declarations:**
  - function valid_settings
  - function stub_github_driver
  - function user_repository
  - function session_store
  - function token_store
  - function state_store
  - function oauth_service
  - function test_client
  - class TestMintAfJwt
  - class TestInMemoryStateStore
  - ... and 7 more
**External Dependencies:**
  - **Stdlib:** `datetime.datetime`, `datetime.timedelta`, `datetime.timezone`, `unittest.mock.AsyncMock`, `uuid.uuid4`
  - **Third-party:** `fastapi.FastAPI`, `fastapi.testclient.TestClient`, `pytest`

## tests/test_config.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 21.45 KB  
**LOC:** 441  
**TODOs/FIXMEs:** 0  
**Declarations:** 3  
**Top-level declarations:**
  - class TestSettings
  - class TestValidateProdSettings
  - class TestGetSettings
**External Dependencies:**
  - **Stdlib:** `unittest.mock`
  - **Third-party:** `pydantic.SecretStr`, `pydantic.ValidationError`, `pytest`

## tests/test_dependencies.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 9.72 KB  
**LOC:** 196  
**TODOs/FIXMEs:** 0  
**Declarations:** 6  
**Top-level declarations:**
  - function valid_settings
  - class TestInMemorySessionStore
  - class TestPlaceholderGitHubDriver
  - class TestDependencyContainer
  - class TestGetDependencies
  - class TestDependencyContainerEnvironment
**External Dependencies:**
  - **Third-party:** `pytest`

## tests/test_github_driver.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 3.77 KB  
**LOC:** 57  
**TODOs/FIXMEs:** 0  
**Declarations:** 1  
**Top-level declarations:**
  - class TestStubGitHubOAuthDriver
**External Dependencies:**
  - **Stdlib:** `datetime.datetime`, `datetime.timezone`
  - **Third-party:** `pytest`

## tests/test_github_token_route.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 27.56 KB  
**LOC:** 570  
**TODOs/FIXMEs:** 0  
**Declarations:** 10  
**Top-level declarations:**
  - function valid_settings
  - function session_store
  - function user_repository
  - function token_store
  - function jwt_secret
  - class TestGitHubTokenService
  - class TestGitHubTokenRoute
  - class TestAppIntegration
  - class TestMeRoute
  - class TestAdminRoute
**External Dependencies:**
  - **Stdlib:** `datetime.datetime`, `datetime.timedelta`, `datetime.timezone`, `unittest.mock.AsyncMock`
  - **Third-party:** `fastapi.FastAPI`, `fastapi.testclient.TestClient`, `pytest`

## tests/test_models.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 10.75 KB  
**LOC:** 214  
**TODOs/FIXMEs:** 0  
**Declarations:** 5  
**Top-level declarations:**
  - class TestAFUser
  - class TestGitHubIdentity
  - class TestGitHubOAuthResult
  - class TestSession
  - class TestAFTokenIntrospection
**External Dependencies:**
  - **Stdlib:** `dataclasses.is_dataclass`, `datetime.datetime`, `datetime.timedelta`, `datetime.timezone`, `uuid.UUID`
    _(and 1 more)_
  - **Third-party:** `pydantic.ValidationError`, `pytest`

## tests/test_postgres_user_repository.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 7.56 KB  
**LOC:** 145  
**TODOs/FIXMEs:** 0  
**Declarations:** 2  
**Top-level declarations:**
  - class TestPostgresUserRepository
  - class TestPostgresUserRepositoryIntegration
**External Dependencies:**
  - **Stdlib:** `datetime.timedelta`, `os`, `urllib.parse.quote_plus`, `uuid.uuid4`
  - **Third-party:** `pytest`, `sqlalchemy.create_engine`, `sqlalchemy.text`

## tests/test_stores.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 15.97 KB  
**LOC:** 358  
**TODOs/FIXMEs:** 0  
**Declarations:** 3  
**Top-level declarations:**
  - class TestInMemoryUserRepository
  - class TestInMemorySessionStore
  - class TestInMemoryGitHubTokenStore
**External Dependencies:**
  - **Stdlib:** `datetime.datetime`, `datetime.timedelta`, `datetime.timezone`, `uuid.uuid4`
  - **Third-party:** `pytest`

## tests/test_token_and_session_routes.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 28.46 KB  
**LOC:** 636  
**TODOs/FIXMEs:** 0  
**Declarations:** 8  
**Top-level declarations:**
  - function valid_settings
  - function session_store
  - function user_repository
  - function jwt_secret
  - class TestJWTValidation
  - class TestTokenIntrospectionRoute
  - class TestSessionRevocationRoute
  - class TestAppIntegrationWithNewRoutes
**External Dependencies:**
  - **Stdlib:** `datetime.datetime`, `datetime.timedelta`, `datetime.timezone`, `uuid.uuid4`
  - **Third-party:** `fastapi.FastAPI`, `fastapi.testclient.TestClient`, `pytest`
