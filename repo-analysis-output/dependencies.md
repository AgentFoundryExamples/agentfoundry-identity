# Dependency Graph

Intra-repository dependency analysis for Python and JavaScript/TypeScript files.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 23
- **Intra-repo dependencies**: 34
- **External stdlib dependencies**: 18
- **External third-party dependencies**: 13

## External Dependencies

### Standard Library / Core Modules

Total: 18 unique modules

- `abc.ABC`
- `abc.abstractmethod`
- `contextvars.ContextVar`
- `dataclasses.dataclass`
- `dataclasses.is_dataclass`
- `datetime.datetime`
- `datetime.timedelta`
- `datetime.timezone`
- `functools.lru_cache`
- `logging`
- `sys`
- `threading`
- `typing.Any`
- `typing.Literal`
- `unittest.mock`
- `uuid`
- `uuid.UUID`
- `uuid.uuid4`

### Third-Party Packages

Total: 13 unique packages

- `fastapi.APIRouter`
- `fastapi.FastAPI`
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

- `af_identity_service/config.py` (6 dependents)
- `af_identity_service/models/github.py` (4 dependents)
- `af_identity_service/__init__.py` (3 dependents)
- `af_identity_service/dependencies.py` (3 dependents)
- `af_identity_service/models/session.py` (3 dependents)
- `af_identity_service/logging.py` (2 dependents)
- `af_identity_service/github/driver.py` (2 dependents)
- `af_identity_service/models/user.py` (2 dependents)
- `af_identity_service/stores/github_token_store.py` (2 dependents)
- `af_identity_service/stores/session_store.py` (2 dependents)

## Files with Most Dependencies (Intra-Repo)

- `tests/test_stores.py` (5 dependencies)
- `af_identity_service/app.py` (4 dependencies)
- `af_identity_service/models/__init__.py` (4 dependencies)
- `tests/test_app.py` (4 dependencies)
- `af_identity_service/stores/__init__.py` (3 dependencies)
- `af_identity_service/dependencies.py` (2 dependencies)
- `af_identity_service/logging.py` (2 dependencies)
- `tests/test_dependencies.py` (2 dependencies)
- `af_identity_service/github/__init__.py` (1 dependencies)
- `af_identity_service/github/driver.py` (1 dependencies)
