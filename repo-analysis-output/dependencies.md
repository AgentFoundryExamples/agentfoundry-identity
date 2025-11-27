# Dependency Graph

Intra-repository dependency analysis for Python and JavaScript/TypeScript files.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 40
- **Intra-repo dependencies**: 123
- **External stdlib dependencies**: 27
- **External third-party dependencies**: 17

## External Dependencies

### Standard Library / Core Modules

Total: 27 unique modules

- `abc.ABC`
- `abc.abstractmethod`
- `base64`
- `contextvars.ContextVar`
- `dataclasses.dataclass`
- `dataclasses.is_dataclass`
- `datetime.datetime`
- `datetime.timedelta`
- `datetime.timezone`
- `functools.lru_cache`
- `hmac`
- `json`
- `logging`
- `secrets`
- `sys`
- `threading`
- `typing.Annotated`
- `typing.Any`
- `typing.Callable`
- `typing.Literal`
- ... and 7 more (see JSON for full list)

### Third-Party Packages

Total: 17 unique packages

- `fastapi.APIRouter`
- `fastapi.Depends`
- `fastapi.FastAPI`
- `fastapi.HTTPException`
- `fastapi.Header`
- `fastapi.responses.JSONResponse`
- `fastapi.testclient.TestClient`
- `pydantic.BaseModel`
- `pydantic.Field`
- `pydantic.SecretStr`
- `pydantic.ValidationError`
- `pydantic.field_validator`
- `pydantic_settings.BaseSettings`
- `pydantic_settings.SettingsConfigDict`
- `pytest`
- `structlog`
- `uvicorn`

## Most Depended Upon Files (Intra-Repo)

- `af_identity_service/stores/session_store.py` (13 dependents)
- `af_identity_service/stores/user_store.py` (13 dependents)
- `af_identity_service/config.py` (9 dependents)
- `af_identity_service/logging.py` (8 dependents)
- `af_identity_service/github/driver.py` (7 dependents)
- `af_identity_service/stores/github_token_store.py` (7 dependents)
- `af_identity_service/models/session.py` (7 dependents)
- `af_identity_service/dependencies.py` (6 dependents)
- `af_identity_service/models/github.py` (6 dependents)
- `af_identity_service/security/auth.py` (6 dependents)

## Files with Most Dependencies (Intra-Repo)

- `tests/test_github_token_route.py` (12 dependencies)
- `tests/test_auth_github_routes.py` (11 dependencies)
- `af_identity_service/app.py` (10 dependencies)
- `tests/test_token_and_session_routes.py` (9 dependencies)
- `af_identity_service/dependencies.py` (8 dependencies)
- `af_identity_service/services/oauth.py` (7 dependencies)
- `af_identity_service/security/auth.py` (6 dependencies)
- `af_identity_service/routes/github_token.py` (5 dependencies)
- `af_identity_service/routes/token.py` (5 dependencies)
- `tests/test_stores.py` (5 dependencies)
