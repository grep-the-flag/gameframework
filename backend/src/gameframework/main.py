from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, contextmanager

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from gameframework.api.auth import router as auth_router
from gameframework.api.errors import ProblemError, problem_error_handler
from gameframework.api.health import router as health_router
from gameframework.api.info import router as info_router
from gameframework.api.middleware import RequestIdMiddleware
from gameframework.api.security import router as security_router
from gameframework.api.users import router as users_router
from gameframework.config import get_settings
from gameframework.db.session import get_session
from gameframework.services.bootstrap import ensure_initial_admin
from gameframework.services.secrets import ensure_signing_key


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    ensure_signing_key(settings)
    # `app.dependency_overrides` is a FastAPI request-handling mechanism, not
    # something a plain lifespan function consults on its own. Resolving it
    # by hand here is what lets the test client's `db_session` override
    # reach this call too, so a test's own transaction (rolled back at
    # teardown) is where the mint lands, rather than the real configured
    # database — the same session Depends(get_session) would hand a route.
    session_factory = app.dependency_overrides.get(get_session, get_session)
    with contextmanager(session_factory)() as db:
        ensure_initial_admin(db, settings)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Gameframework", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_origin],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestIdMiddleware)
    app.add_exception_handler(ProblemError, problem_error_handler)
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(info_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(security_router, prefix="/api/v1")
    app.include_router(users_router, prefix="/api/v1")
    return app


app = create_app()
