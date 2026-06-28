# Stage 1: Base - Setup Python and Poetry environment variables
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    PYSETUP_PATH="/opt/pysetup" \
    VENV_PATH="/opt/pysetup/.venv"

# Add Poetry and Virtualenv to PATH
ENV PATH="$POETRY_HOME/bin:$VENV_PATH/bin:$PATH"

# Install system dependencies needed for building packages or interacting with Docker
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

# Set up working directory for dependencies
WORKDIR $PYSETUP_PATH
COPY poetry.lock pyproject.toml ./


# Stage 2: Development - Installs ALL dependencies (including dev)
FROM base AS dev
WORKDIR $PYSETUP_PATH

# Install all dependencies
RUN poetry install --no-root

# Set working directory for application code
WORKDIR /app

# The command is handled by docker-compose.override.yml for hot-reloading
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]


# Stage 3: Production - Installs only main dependencies and copies code
FROM base AS prod
WORKDIR $PYSETUP_PATH

# Install only production dependencies
RUN poetry install --only main --no-root

WORKDIR /app
COPY . /app

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]