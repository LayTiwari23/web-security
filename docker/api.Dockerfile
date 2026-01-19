# docker/api.Dockerfile

# -----------------------------
# Base image
# -----------------------------
FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files & enable unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
# ✅ UPDATED: Added Pango, Cairo, and Glib for WeasyPrint/PDFs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    curl \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# Dependencies layer
# -----------------------------
FROM base AS deps

# Copy dependency files
COPY requirements.txt .

# Install dependencies (handle requirements.txt or pyproject.toml)
RUN if [ -f "pyproject.toml" ]; then \
      pip install --no-cache-dir poetry && \
      poetry config virtualenvs.create false && \
      poetry install --no-interaction --no-ansi; \
    elif [ -f "requirements.txt" ]; then \
      pip install --no-cache-dir -r requirements.txt; \
    else \
      echo "No dependency file found (pyproject.toml or requirements.txt)" && exit 1; \
    fi

# -----------------------------
# Final runtime image
# -----------------------------
FROM base AS runtime

# Create non-root user
RUN groupadd -r app && useradd -r -g app app
USER app

WORKDIR /app

# Copy installed dependencies from deps image
COPY --from=deps /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=deps /usr/local/bin /usr/local/bin

# Copy application source
COPY src ./src
COPY alembic ./alembic
COPY .env.example .

# Expose FastAPI port
EXPOSE 8000

# Environment variable to distinguish envs
ENV APP_ENV=production

# Default command
CMD ["uvicorn", "src.app.main:app", "--host", "0.0.0.0", "--port", "8000"]