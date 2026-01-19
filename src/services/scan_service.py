# src/app/services/scan_service.py

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session, joinedload

from src.db.models.scan import Finding, Scan
from src.db.models.target import Target
from src.db.models.user import User


def create_scan_for_target(db: Session, user: User, target: Target) -> Scan:
    """
    Create a new Scan row for a given user + target.
    """
    scan = Scan(
        user_id=user.id,
        target_id=target.id,
        status="pending",
        created_at=datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def mark_scan_started(db: Session, scan: Scan) -> Scan:
    scan.status = "running"
    scan.started_at = datetime.utcnow()
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def mark_scan_completed(
    db: Session,
    scan: Scan,
    summary: str | None = None,
    extra_data: dict | None = None,
) -> Scan:
    scan.status = "completed"
    scan.finished_at = datetime.utcnow()
    if summary is not None:
        scan.summary = summary
    if extra_data is not None:
        scan.extra_data = extra_data
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def mark_scan_failed(
    db: Session,
    scan: Scan,
    error_message: str | None = None,
    extra_data: dict | None = None,
) -> Scan:
    scan.status = "failed"
    scan.finished_at = datetime.utcnow()
    if error_message:
        scan.summary = error_message
    if extra_data is not None:
        scan.extra_data = extra_data
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def list_user_scans(db: Session, user_id: int) -> List[Scan]:
    """
    Return all scans for a given user, newest first.
    """
    return (
        db.query(Scan)
        .filter(Scan.user_id == user_id)
        .order_by(Scan.created_at.desc())
        .all()
    )


def get_scan_with_findings(
    db: Session,
    scan_id: int,
    user_id: int,
) -> Optional[Scan]:
    """
    Fetch a specific scan for a user, including findings.
    """
    return (
        db.query(Scan)
        .options(joinedload(Scan.findings))
        .filter(Scan.id == scan_id, Scan.user_id == user_id)
        .first()
    )


def add_finding(
    db: Session,
    scan: Scan,
    *,
    check_type: str,
    name: str,
    severity: str,
    description: str | None = None,
    recommendation: str | None = None,
    raw_data: dict | None = None,
) -> Finding:
    """
    Create and attach a Finding to the given scan.
    """
    finding = Finding(
        scan_id=scan.id,
        check_type=check_type,
        name=name,
        severity=severity,
        description=description,
        recommendation=recommendation,
        raw_data=raw_data,
        created_at=datetime.utcnow(),
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding