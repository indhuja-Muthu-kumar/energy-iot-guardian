from __future__ import annotations

from datetime import datetime

import requests

from app.config import Config
from app.extensions import db
from app.models.kev import KEVEntry


def fetch_kev_feed(url: str | None = None):
    final_url = url or Config.KEV_API_URL
    response = requests.get(final_url, timeout=10)
    response.raise_for_status()
    payload = response.json()
    if "vulnerabilities" not in payload:
        raise ValueError("Unexpected KEV payload shape.")
    return payload["vulnerabilities"]


def sync_kev_catalog(url: str | None = None) -> int:
    entries = fetch_kev_feed(url)
    for item in entries:
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        record = KEVEntry.query.filter_by(cve_id=cve_id).first()
        if record is None:
            record = KEVEntry(cve_id=cve_id)
        record.vendor_project = item.get("vendorProject", "unknown")
        record.product = item.get("product", "unknown")
        record.short_description = item.get("shortDescription")
        record.required_action = item.get("requiredAction")
        due_date = item.get("dueDate")
        if due_date:
            record.due_date = datetime.strptime(due_date, "%Y-%m-%d").date()
        record.source = "CISA KEV"
        db.session.add(record)
    db.session.commit()
    return len(entries)
