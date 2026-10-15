from __future__ import annotations

import logging
from datetime import UTC, datetime

import requests
from sqlalchemy.exc import SQLAlchemyError

from app.config import Config
from app.extensions import db
from app.models.kev import CISA_KEV_SOURCE, KEVEntry
from app.models.sync_log import SyncLog

logger = logging.getLogger(__name__)


def fetch_kev_feed(url: str | None = None) -> list:
    final_url = url or Config.KEV_API_URL
    response = requests.get(final_url, timeout=10)
    response.raise_for_status()
    payload = response.json()
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("vulnerabilities"), list)
    ):
        raise ValueError("Unexpected KEV payload shape.")
    return payload["vulnerabilities"]


def sync_kev_catalog(url: str | None = None) -> int:
    started_at = datetime.now(UTC).replace(tzinfo=None)
    sync_log = SyncLog(
        source="kev",
        status="running",
        details=f"Source: {url or Config.KEV_API_URL}",
        records_processed=0,
        started_at=started_at,
    )
    db.session.add(sync_log)
    db.session.commit()
    sync_log_id = sync_log.id

    try:
        entries = fetch_kev_feed(url)
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError("KEV feed entries must be JSON objects.")
            cve_id = item.get("cveID")
            if not isinstance(cve_id, str) or not cve_id.strip():
                raise ValueError("KEV feed entry is missing a valid cveID.")
            cve_id = cve_id.strip()
            record = KEVEntry.query.filter_by(cve_id=cve_id).first()
            if record is None:
                record = KEVEntry(cve_id=cve_id)
            record.vendor_project = item.get("vendorProject", "unknown")
            record.product = item.get("product", "unknown")
            record.short_description = item.get("shortDescription")
            record.required_action = item.get("requiredAction")
            due_date = item.get("dueDate")
            record.due_date = (
                datetime.strptime(due_date, "%Y-%m-%d").date() if due_date else None
            )
            record.source = CISA_KEV_SOURCE
            db.session.add(record)

        sync_log = db.session.get(SyncLog, sync_log_id)
        if sync_log is None:
            raise RuntimeError("The CISA KEV sync record disappeared.")
        sync_log.status = "success"
        sync_log.records_processed = len(entries)
        sync_log.completed_at = datetime.now(UTC).replace(tzinfo=None)
        sync_log.details = (
            f"Source: {url or Config.KEV_API_URL}; "
            f"KEV entries received: {len(entries)}"
        )
        db.session.commit()
    except (requests.RequestException, ValueError, SQLAlchemyError) as error:
        db.session.rollback()
        logger.exception("CISA KEV synchronization failed.")
        failed_log = db.session.get(SyncLog, sync_log_id)
        if failed_log is not None:
            failed_log.status = "failed"
            failed_log.completed_at = datetime.now(UTC).replace(tzinfo=None)
            failed_log.details = (
                f"Source: {url or Config.KEV_API_URL}; "
                f"{type(error).__name__}: {error}"
            )
            db.session.commit()
        raise
    return len(entries)
