FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS base
WORKDIR /app
ENV UV_LINK_MODE=copy
COPY pyproject.toml uv.lock ./

FROM base AS dev
RUN uv sync --frozen
COPY src/ src/
CMD ["uv", "run", "uvicorn", "gameframework.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

FROM base AS prod
RUN uv sync --frozen --no-dev
COPY src/ src/
CMD ["uv", "run", "--no-dev", "uvicorn", "gameframework.main:app", "--host", "0.0.0.0", "--port", "8000"]
