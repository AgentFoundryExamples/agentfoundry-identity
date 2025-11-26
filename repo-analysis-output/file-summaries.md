# File Summaries

Heuristic summaries of source files based on filenames, extensions, and paths.

Schema Version: 2.0

Total files: 23

## af_identity_service/__init__.py
**Language:** Python  
**Role:** module-init  
**Role Justification:** module initialization file '__init__'  
**Size:** 1.06 KB  
**LOC:** 5  
**TODOs/FIXMEs:** 0  

## af_identity_service/app.py
**Language:** Python  
**Role:** entry-point  
**Role Justification:** common entry point name 'app'  
**Size:** 8.85 KB  
**LOC:** 191  
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
**Size:** 6.54 KB  
**LOC:** 142  
**TODOs/FIXMEs:** 0  
**Declarations:** 3  
**Top-level declarations:**
  - class Settings
  - class ConfigurationError
  - function get_settings
**External Dependencies:**
  - **Stdlib:** `functools.lru_cache`, `typing.Literal`
  - **Third-party:** `pydantic.Field`, `pydantic.field_validator`, `pydantic_settings.BaseSettings`, `pydantic_settings.SettingsConfigDict`

## af_identity_service/dependencies.py
**Language:** Python  
**Role:** implementation  
**Role Justification:** general implementation file (default classification)  
**Size:** 11.15 KB  
**LOC:** 254  
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
  - **Stdlib:** `abc.ABC`, `abc.abstractmethod`, `typing.Any`

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
**Size:** 7.59 KB  
**LOC:** 157  
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
**Size:** 5.27 KB  
**LOC:** 98  
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
**Size:** 9.47 KB  
**LOC:** 200  
**TODOs/FIXMEs:** 0  
**Declarations:** 5  
**Top-level declarations:**
  - class GitHubTokenStoreError
  - class RefreshTokenNotFoundError
  - class GitHubTokenStore
  - class _StoredTokens
  - class InMemoryGitHubTokenStore
**External Dependencies:**
  - **Stdlib:** `abc.ABC`, `abc.abstractmethod`, `datetime.datetime`, `datetime.timezone`, `threading`
    _(and 1 more)_
  - **Third-party:** `structlog`

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

## tests/test_config.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 9.31 KB  
**LOC:** 184  
**TODOs/FIXMEs:** 0  
**Declarations:** 2  
**Top-level declarations:**
  - class TestSettings
  - class TestGetSettings
**External Dependencies:**
  - **Stdlib:** `unittest.mock`
  - **Third-party:** `pydantic.ValidationError`, `pytest`

## tests/test_dependencies.py
**Language:** Python  
**Role:** test  
**Role Justification:** filename starts with 'test_'  
**Size:** 6.75 KB  
**LOC:** 132  
**TODOs/FIXMEs:** 0  
**Declarations:** 5  
**Top-level declarations:**
  - function valid_settings
  - class TestInMemorySessionStore
  - class TestPlaceholderGitHubDriver
  - class TestDependencyContainer
  - class TestGetDependencies
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
