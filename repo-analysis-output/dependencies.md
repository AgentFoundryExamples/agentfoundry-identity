# Dependency Graph

Intra-repository dependency analysis for Python and JavaScript/TypeScript files.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 9
- **Intra-repo dependencies**: 15
- **External stdlib dependencies**: 10
- **External third-party dependencies**: 12

## External Dependencies

### Standard Library / Core Modules

Total: 10 unique modules

- `abc.ABC`
- `abc.abstractmethod`
- `contextvars.ContextVar`
- `functools.lru_cache`
- `logging`
- `sys`
- `typing.Any`
- `typing.Literal`
- `unittest.mock`
- `uuid`

### Third-Party Packages

Total: 12 unique packages

- `fastapi.APIRouter`
- `fastapi.FastAPI`
- `fastapi.responses.JSONResponse`
- `fastapi.testclient.TestClient`
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
- `af_identity_service/__init__.py` (3 dependents)
- `af_identity_service/dependencies.py` (3 dependents)
- `af_identity_service/logging.py` (2 dependents)
- `af_identity_service/app.py` (1 dependents)

## Files with Most Dependencies (Intra-Repo)

- `af_identity_service/app.py` (4 dependencies)
- `tests/test_app.py` (4 dependencies)
- `af_identity_service/dependencies.py` (2 dependencies)
- `af_identity_service/logging.py` (2 dependencies)
- `tests/test_dependencies.py` (2 dependencies)
- `tests/test_config.py` (1 dependencies)
