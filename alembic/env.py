from __future__ import annotations
import os
import sys
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
from pathlib import Path

# 1. Setup paths
BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))

# 2. Setup logging
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# 3. FORCE THE URL (The Docker Fix)
# We use 'db' as the hostname because that is your service name in docker-compose
database_url = os.getenv(
    "DATABASE_URL", 
    "postgresql+psycopg2://postgres:postgres@db:5432/websec_db"
)

# Ensure the driver is correct
if database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg2://", 1)

# 4. Target Metadata
try:
    from src.db.base import Base
    target_metadata = Base.metadata
except ImportError:
    target_metadata = None

def run_migrations_online() -> None:
    # Inject the URL directly into the configuration
    connectable = engine_from_config(
        {"sqlalchemy.url": database_url}, 
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata,
            compare_type=True
        )
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    context.configure(url=database_url)
    with context.begin_transaction():
        context.run_migrations()
else:
    run_migrations_online()