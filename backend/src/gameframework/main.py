from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from gameframework.api.auth import router as auth_router
from gameframework.api.errors import ProblemError, problem_error_handler
from gameframework.api.health import router as health_router
from gameframework.api.info import router as info_router
from gameframework.api.middleware import RequestIdMiddleware
from gameframework.config import get_settings
from gameframework.services.secrets import ensure_signing_key


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    ensure_signing_key(get_settings())
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
    return app


app = create_app()
