FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58 AS base
# The digest pin freezes the Debian snapshot, so security fixes published
# after the pin (openssl, krb5, gnutls, ...) only arrive via an upgrade here.
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*
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
