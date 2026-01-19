# src/workers/celery_app.py

from __future__ import annotations
from celery import Celery
from src.core.settings import get_settings

settings = get_settings()

celery_app = Celery(
    "worker",
    broker=str(settings.CELERY_BROKER_URL),
    backend=str(settings.CELERY_RESULT_BACKEND)
)

celery_app.conf.update(
    # ✅ FIX: Match your actual folder structure (src -> workers)
    include=[
        "src.workers.tasks_scans",
        "src.workers.tasks_reports",
    ],
    task_ignore_result=False,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True 
)

@celery_app.task(name="ping")
def ping():
    return "pong"