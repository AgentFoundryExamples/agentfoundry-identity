# Dependency Graph

Intra-repository dependency analysis for Python and JavaScript/TypeScript files.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 52
- **Intra-repo dependencies**: 147
- **External stdlib dependencies**: 33
- **External third-party dependencies**: 38

## External Dependencies

### Standard Library / Core Modules

Total: 33 unique modules

- `abc.ABC`
- `abc.abstractmethod`
- `argparse`
- `base64`
- `contextlib.asynccontextmanager`
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
- `os`
- `secrets`
- `sys`
- `threading`
- `typing.Annotated`
- ... and 13 more (see JSON for full list)

### Third-Party Packages

Total: 38 unique packages

- `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
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
- `redis.asyncio`
- `sqlalchemy.BigInteger`
- `sqlalchemy.Column`
- `sqlalchemy.DateTime`
- ... and 18 more (see JSON for full list)

## Most Depended Upon Files (Intra-Repo)

- `af_identity_service/stores/session_store.py` (14 dependents)
- `af_identity_service/stores/user_store.py` (14 dependents)
- `af_identity_service/config.py` (9 dependents)
- `af_identity_service/stores/github_token_store.py` (9 dependents)
- `af_identity_service/models/session.py` (9 dependents)
- `af_identity_service/logging.py` (8 dependents)
- `af_identity_service/models/github.py` (8 dependents)
- `af_identity_service/github/driver.py` (7 dependents)
- `af_identity_service/dependencies.py` (6 dependents)
- `af_identity_service/security/auth.py` (6 dependents)

## Files with Most Dependencies (Intra-Repo)

- `tests/test_github_token_route.py` (12 dependencies)
- `tests/test_auth_github_routes.py` (11 dependencies)
- `af_identity_service/app.py` (10 dependencies)
- `af_identity_service/dependencies.py` (9 dependencies)
- `tests/test_token_and_session_routes.py` (9 dependencies)
- `af_identity_service/services/oauth.py` (7 dependencies)
- `af_identity_service/security/auth.py` (6 dependencies)
- `af_identity_service/routes/github_token.py` (5 dependencies)
- `af_identity_service/routes/token.py` (5 dependencies)
- `tests/test_stores.py` (5 dependencies)
