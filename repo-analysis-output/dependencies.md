# Dependency Graph

Intra-repository dependency analysis for Python and JavaScript/TypeScript files.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 30
- **Intra-repo dependencies**: 62
- **External stdlib dependencies**: 25
- **External third-party dependencies**: 14

## External Dependencies

### Standard Library / Core Modules

Total: 25 unique modules

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
- `typing.Any`
- `typing.Literal`
- `typing.TYPE_CHECKING`
- `unittest.mock`
- ... and 5 more (see JSON for full list)

### Third-Party Packages

Total: 14 unique packages

- `fastapi.APIRouter`
- `fastapi.FastAPI`
- `fastapi.HTTPException`
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

- `af_identity_service/config.py` (7 dependents)
- `af_identity_service/stores/github_token_store.py` (5 dependents)
- `af_identity_service/stores/user_store.py` (5 dependents)
- `af_identity_service/github/driver.py` (5 dependents)
- `af_identity_service/stores/session_store.py` (5 dependents)
- `af_identity_service/models/github.py` (5 dependents)
- `af_identity_service/dependencies.py` (4 dependents)
- `af_identity_service/services/oauth.py` (4 dependents)
- `af_identity_service/models/session.py` (4 dependents)
- `af_identity_service/__init__.py` (3 dependents)

## Files with Most Dependencies (Intra-Repo)

- `tests/test_auth_github_routes.py` (11 dependencies)
- `af_identity_service/dependencies.py` (7 dependencies)
- `af_identity_service/services/oauth.py` (7 dependencies)
- `af_identity_service/app.py` (5 dependencies)
- `tests/test_stores.py` (5 dependencies)
- `af_identity_service/models/__init__.py` (4 dependencies)
- `tests/test_app.py` (4 dependencies)
- `af_identity_service/stores/__init__.py` (3 dependencies)
- `af_identity_service/logging.py` (2 dependencies)
- `tests/test_dependencies.py` (2 dependencies)
