FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS base
WORKDIR /app
ENV UV_LINK_MODE=copy
COPY pyproject.toml uv.lock ./

FROM base AS dev
RUN uv sync --frozen --no-install-project
COPY src/ src/
RUN uv sync --frozen
CMD ["uv", "run", "uvicorn", "gameframework.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

FROM base AS prod
RUN uv sync --frozen --no-dev --no-install-project
COPY src/ src/
RUN uv sync --frozen --no-dev \
    && groupadd --gid 10001 appuser \
    && useradd --no-create-home --uid 10001 --gid appuser appuser \
    && chown -R appuser:appuser /app
ENV PATH="/app/.venv/bin:${PATH}"
USER appuser
CMD ["uvicorn", "gameframework.main:app", "--host", "0.0.0.0", "--port", "8000"]
