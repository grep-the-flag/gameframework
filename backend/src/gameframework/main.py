from fastapi import FastAPI

from gameframework.api.health import router as api_router


def create_app() -> FastAPI:
    app = FastAPI(title="Gameframework", version="0.1.0")
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
