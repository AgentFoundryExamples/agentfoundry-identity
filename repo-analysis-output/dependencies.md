# Dependency Graph

Intra-repository dependency analysis for Python and JavaScript/TypeScript files.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 34
- **Intra-repo dependencies**: 91
- **External stdlib dependencies**: 27
- **External third-party dependencies**: 16

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

Total: 16 unique packages

- `fastapi.APIRouter`
- `fastapi.Depends`
- `fastapi.FastAPI`
- `fastapi.HTTPException`
- `fastapi.Header`
- `fastapi.responses.JSONResponse`
- `fastapi.testclient.TestClient`
- `pydantic.BaseModel`
- `pydantic.Field`
- `pydantic.ValidationError`
- `pydantic.field_validator`
- `pydantic_settings.BaseSettings`
- `pydantic_settings.SettingsConfigDict`
- `pytest`
- `structlog`
- `uvicorn`

## Most Depended Upon Files (Intra-Repo)

- `af_identity_service/stores/session_store.py` (9 dependents)
- `af_identity_service/stores/user_store.py` (9 dependents)
- `af_identity_service/config.py` (8 dependents)
- `af_identity_service/models/session.py` (6 dependents)
- `af_identity_service/dependencies.py` (5 dependents)
- `af_identity_service/logging.py` (5 dependents)
- `af_identity_service/stores/github_token_store.py` (5 dependents)
- `af_identity_service/github/driver.py` (5 dependents)
- `af_identity_service/models/github.py` (5 dependents)
- `af_identity_service/security/jwt.py` (5 dependents)

## Files with Most Dependencies (Intra-Repo)

- `tests/test_auth_github_routes.py` (11 dependencies)
- `tests/test_token_and_session_routes.py` (9 dependencies)
- `af_identity_service/app.py` (7 dependencies)
- `af_identity_service/dependencies.py` (7 dependencies)
- `af_identity_service/services/oauth.py` (7 dependencies)
- `af_identity_service/security/auth.py` (6 dependencies)
- `af_identity_service/routes/token.py` (5 dependencies)
- `tests/test_stores.py` (5 dependencies)
- `af_identity_service/models/__init__.py` (4 dependencies)
- `af_identity_service/routes/session.py` (4 dependencies)
