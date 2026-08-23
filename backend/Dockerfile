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
# git: gameframework-sdk is a [tool.uv.sources] git dependency (pinned to a
# tag, never a branch), so `uv sync` needs it to resolve. Unlike prod, dev
# is never scanned or shipped, so installing it directly in this stage is
# unremarkable.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git \
    && rm -rf /var/lib/apt/lists/*
RUN uv sync --frozen --no-install-project
COPY src/ src/
RUN uv sync --frozen
CMD ["uv", "run", "uvicorn", "gameframework.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

FROM base AS builder
# Same git dependency as dev's stage, but isolated to this builder: prod
# below never installs it, so the shipped, Trivy-scanned image (ADR-0016)
# carries no build tooling with no runtime purpose.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git \
    && rm -rf /var/lib/apt/lists/*
RUN uv sync --frozen --no-dev --no-install-project
COPY src/ src/
RUN uv sync --frozen --no-dev

FROM base AS prod
# UV_LINK_MODE=copy (base) means .venv holds real files, not links back
# into a cache outside this stage, so copying it whole is safe. The root
# package inside it is an editable install pointing at /app/src, which is
# why src/ is copied here too, at the same path the builder used.
COPY --from=builder /app/.venv /app/.venv
COPY src/ src/
RUN groupadd --gid 10001 appuser \
    && useradd --no-create-home --uid 10001 --gid appuser appuser \
    && chown -R appuser:appuser /app
ENV PATH="/app/.venv/bin:${PATH}"
USER appuser
CMD ["uvicorn", "gameframework.main:app", "--host", "0.0.0.0", "--port", "8000"]
