# Makefile
# Helper commands for development

PYTHON := python
PIP := pip

APP_MODULE := src.app.main:app
UVICORN := uvicorn

.PHONY: help install run dev worker beat lint format test testcov migrate upgrade downgrade makemigration clean docker-up docker-down

help:
	@echo "Common commands:"
	@echo "  make install         - Install dependencies"
	@echo "  make run             - Run FastAPI app (uvicorn)"
	@echo "  make dev             - Run app with reload"
	@echo "  make worker          - Run Celery worker"
	@echo "  make beat            - Run Celery beat"
	@echo "  make test            - Run tests"
	@echo "  make migrate         - Create new Alembic revision (name=msg)"
	@echo "  make upgrade         - Apply DB migrations"
	@echo "  make downgrade       - Downgrade DB (rev=-1 or specific rev)"
	@echo "  make docker-up       - Start dev stack with Docker"
	@echo "  make docker-down     - Stop dev stack"

install:
	$(PIP) install -r requirements.txt

run:
	$(UVICORN) $(APP_MODULE) --host 0.0.0.0 --port 8000

dev:
	$(UVICORN) $(APP_MODULE) --host 0.0.0.0 --port 8000 --reload

worker:
	celery -A src.app.workers.celery_app.celery_app worker --loglevel=INFO

beat:
	celery -A src.app.workers.celery_app.celery_app beat --loglevel=INFO

test:
	pytest

# Alembic helpers
migrate:
	@if [ -z "$(name)" ]; then \
		echo "Usage: make migrate name=add_something"; \
		exit 1; \
	fi
	alembic revision -m "$(name)"

upgrade:
	alembic upgrade head

downgrade:
	@if [ -z "$(rev)" ]; then \
		echo "Usage: make downgrade rev=-1 (or specific revision id)"; \
		exit 1; \
	fi
	alembic downgrade $(rev)

# Docker helpers
docker-up:
	cd compose && docker compose -f docker-compose.dev.yml up --build

docker-down:
	cd compose && docker compose -f docker-compose.dev.yml down