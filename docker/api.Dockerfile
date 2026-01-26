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
# ✅ FIX: --fix-missing handles network/mirror issues common in internship environments
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    curl \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libglib2.0-0 \
    nmap && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# -----------------------------
# Dependencies layer
# -----------------------------
FROM base AS deps

# Copy dependency files
COPY requirements.txt .

# Install dependencies (ensure python-nmap is in your requirements.txt)
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

# Use root for worker nmap privileges; Nmap requires raw socket access
RUN groupadd -r app && useradd -r -g app app

WORKDIR /app

# Copy installed dependencies from deps image
COPY --from=deps /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=deps /usr/local/bin /usr/local/bin

# ✅ THE FIX: Point to the correct source locations
COPY src ./src
COPY alembic ./alembic
COPY .env.example .

# ✅ THE FIX: Correct source path for UI assets
# Maps src/static on your PC to /app/static in the container
COPY src/static ./static 

# Note: Templates are inside src/app/templates, handled by 'COPY src ./src'

# Expose FastAPI port
EXPOSE 8000

# Set PYTHONPATH to ensure internal imports work correctly
ENV PYTHONPATH=/app
ENV APP_ENV=production

# Default command to run the API
CMD ["uvicorn", "src.app.main:app", "--host", "0.0.0.0", "--port", "8000"]