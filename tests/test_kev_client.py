from __future__ import annotations

import requests
import pytest

from app import create_app
from app.extensions import db
from app.models.kev import KEVEntry
from app.models.sync_log import SyncLog
from app.services import kev_client


def make_app():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.create_all()
    return app


def test_sync_kev_catalog_records_success_and_saved_entries(monkeypatch):
    app = make_app()
    monkeypatch.setattr(
        kev_client,
        "fetch_kev_feed",
        lambda _url: [
            {
                "cveID": "CVE-2025-12345",
                "vendorProject": "Example",
                "product": "Controller",
                "dueDate": "2025-12-31",
            },
        ],
    )

    with app.app_context():
        assert kev_client.sync_kev_catalog("https://example.test/kev") == 1

        entry = KEVEntry.query.one()
        log = SyncLog.query.one()
        assert entry.cve_id == "CVE-2025-12345"
        assert entry.vendor_project == "Example"
        assert entry.source == "CISA KEV"
        assert log.source == "kev"
        assert log.status == "success"
        assert log.records_processed == 1
        assert log.completed_at is not None


def test_sync_kev_catalog_upserts_duplicate_feed_entries(monkeypatch):
    app = make_app()
    monkeypatch.setattr(
        kev_client,
        "fetch_kev_feed",
        lambda _url: [
            {
                "cveID": "CVE-2025-12345",
                "vendorProject": "Example",
                "product": "Old Name",
            },
            {
                "cveID": "CVE-2025-12345",
                "vendorProject": "Example",
                "product": "Current Name",
            },
        ],
    )

    with app.app_context():
        assert kev_client.sync_kev_catalog("https://example.test/kev") == 2
        assert KEVEntry.query.count() == 1
        assert KEVEntry.query.one().product == "Current Name"


def test_sync_kev_catalog_records_failure_and_preserves_exception(monkeypatch):
    app = make_app()
    with app.app_context():
        db.session.add(
            KEVEntry(
                cve_id="CVE-2024-00001",
                vendor_project="Existing",
                product="Saved entry",
            )
        )
        db.session.commit()

    def fail_fetch(_url):
        raise requests.ConnectionError("feed unavailable")

    monkeypatch.setattr(kev_client, "fetch_kev_feed", fail_fetch)

    with app.app_context():
        with pytest.raises(requests.ConnectionError, match="feed unavailable"):
            kev_client.sync_kev_catalog("https://example.test/kev")

        log = SyncLog.query.one()
        assert log.source == "kev"
        assert log.status == "failed"
        assert log.completed_at is not None
        assert "ConnectionError" in log.details
        assert KEVEntry.query.count() == 1
        assert KEVEntry.query.one().product == "Saved entry"


def test_sync_kev_catalog_rejects_malformed_entries_and_records_failure(monkeypatch):
    app = make_app()
    monkeypatch.setattr(
        kev_client,
        "fetch_kev_feed",
        lambda _url: [{"cveID": "CVE-2025-12345"}, None],
    )

    with app.app_context():
        with pytest.raises(ValueError, match="entries must be JSON objects"):
            kev_client.sync_kev_catalog("https://example.test/kev")

        log = SyncLog.query.one()
        assert log.status == "failed"
        assert KEVEntry.query.count() == 0
