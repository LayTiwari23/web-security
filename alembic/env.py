# alembic/env.py

from __future__ import annotations

import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Add project root to sys.path so "src.app" can be imported when running Alembic
from pathlib import Path
import sys
import os

# Add the project root to Python's path so we can find 'src'
sys.path.append(os.getcwd())
BASE_DIR = Path(__file__).resolve().parents[1]  # points to project root (web-security-compliance-checker/)
if str(BASE_DIR) not in sys.path:
    sys.path.append(str(BASE_DIR))

# Now we can import our app modules
from src.core.settings import Settings  # type: ignore
from src.db.base import Base  # type: ignore

# Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Get DB URL from our settings
settings = Settings()
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    # ✅ FIX 1: Added str() here
    url = str(settings.DATABASE_URL)
    
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    configuration = config.get_section(config.config_ini_section) or {}
    
    # ✅ FIX 2: Added str() here
    configuration["sqlalchemy.url"] = str(settings.DATABASE_URL)

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()