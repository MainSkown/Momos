# Stage 1: Base - Python, uv and the locked dependency manifests
FROM python:3.12-slim AS base

# The venv lives outside /app so the ./backend:/app bind mount can't hide it
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    UV_PYTHON_DOWNLOADS=never \
    PATH="/opt/venv/bin:$PATH"

COPY --from=ghcr.io/astral-sh/uv:0.12.21 /uv /usr/local/bin/uv

WORKDIR /opt/pysetup
COPY pyproject.toml uv.lock ./


# Stage 2: Development - Installs ALL dependencies (including dev)
FROM base AS dev

RUN uv sync --frozen --no-install-project

# Set working directory for application code
WORKDIR /app

# The command is handled by docker-compose.override.yml for hot-reloading
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]


# Stage 3: Production - Installs only main dependencies and copies code
FROM base AS prod

RUN uv sync --frozen --no-install-project --no-dev

WORKDIR /app
COPY . /app

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
