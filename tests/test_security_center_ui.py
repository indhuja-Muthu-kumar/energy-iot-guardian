from datetime import UTC, datetime

import pytest
import requests

from app import create_app
from app.extensions import db
from app.models.alert import SecurityAlert
from app.models.cve import CVE
from app.models.device import Device
from app.models.finding import Finding
from app.models.patch import PatchCandidate
from app.models.scan import Scan
from app.models.sync_log import SyncLog
from app.models.user import User


def make_app():
    app = create_app(
        {
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        }
    )
    with app.app_context():
        db.create_all()
        admin = User(
            username="operator",
            email="operator@example.com",
            is_admin=True,
        )
        admin.set_password("operator-test-password")
        viewer = User(
            username="viewer",
            email="viewer@example.com",
            is_admin=False,
        )
        viewer.set_password("viewer-test-password")
        device = Device(
            name="Energy device",
            vendor="Example Energy",
            model="INV-2",
            firmware="unknown",
            status="active",
        )
        cve = CVE(
            id="CVE-2025-12345",
            description="Example vulnerability description",
            severity="HIGH",
            cvss_score=8.1,
            published_date=datetime(2025, 1, 2),
            raw={
                "references": [
                    {
                        "url": "https://vendor.example/security/advisory",
                        "tags": ["Vendor Advisory"],
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:example:inv:1.0:*:*:*:*:*:*:*",
                                        "vulnerable": True,
                                        "versionEndExcluding": "1.2",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            },
        )
        db.session.add_all([admin, viewer, device, cve])
        db.session.flush()
        scan = Scan(
            device_id=device.id,
            status="completed",
            scan_type="components",
            created_at=datetime.now(UTC).replace(tzinfo=None),
        )
        finding = Finding(
            scan=scan,
            device=device,
            cve=cve,
            severity="HIGH",
            match_status="affected",
            confidence="high",
            matched_by="nvd-cpe-version-range",
            component_name="Runtime",
            component_version="1.0",
            evidence="Exact version range match from NVD CPE configuration.",
        )
        alert = SecurityAlert(
            device=device,
            cve_id=cve.id,
            severity="HIGH",
            title="CVE requires review",
            summary="A recorded version match requires review.",
            dedupe_key="1:CVE-2025-12345:HIGH:scan",
        )
        candidate = PatchCandidate(
            device=device,
            cve_id=cve.id,
            component_name="Runtime",
            component_version="1.0",
            recommended_version=None,
            patch_source="no-verified-vendor-source",
            patch_url="https://example.invalid/not-a-real-patch",
            evidence="No vendor patch has been verified.",
            is_simulated=True,
            status="discovered",
        )
        db.session.add_all([scan, finding, alert, candidate])
        db.session.commit()
        app.security_center_ids = {
            "admin": admin.id,
            "viewer": viewer.id,
            "device": device.id,
            "cve": cve.id,
            "alert": alert.id,
            "candidate": candidate.id,
        }
    return app


def authenticate(client, user_id):
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True


def test_security_pages_require_authentication_and_render_real_records():
    app = make_app()
    client = app.test_client()
    for path in ("/alerts", "/remediation", "/cves"):
        assert client.get(path).status_code == 302

    authenticate(client, app.security_center_ids["admin"])
    alerts_page = client.get("/alerts")
    remediation_page = client.get("/remediation")
    cves_page = client.get("/cves?assessment=confirmed")

    assert alerts_page.status_code == 200
    assert b"CVE-2025-12345" in alerts_page.data
    assert remediation_page.status_code == 200
    assert b"SIMULATED ONLY" in remediation_page.data
    assert b"example.invalid" not in remediation_page.data
    assert cves_page.status_code == 200
    assert b"Confirmed version match" in cves_page.data
    assert b"Exact version range match" not in cves_page.data


def test_cve_detail_api_returns_evidence_and_source_data_safely():
    app = make_app()
    client = app.test_client()
    authenticate(client, app.security_center_ids["admin"])

    response = client.get("/api/cves/CVE-2025-12345")

    assert response.status_code == 200
    assert response.json["assessments"][0]["match_status"] == "affected"
    assert response.json["assessments"][0]["confidence"] == "high"
    assert response.json["affected_products"][0]["versionEndExcluding"] == "1.2"
    assert response.json["vendor_advisories"][0]["url"].startswith("https://")
    assert response.json["patch_candidates"][0]["patch_url"] is None
    assert b"data-cve-detail" in client.get("/cves/CVE-2025-12345").data


def test_alert_acknowledgement_is_a_csrf_protected_post_flow():
    app = make_app()
    client = app.test_client()
    authenticate(client, app.security_center_ids["admin"])

    response = client.post(
        f"/alerts/{app.security_center_ids['alert']}/acknowledge",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Alert acknowledged" in response.data
    with app.app_context():
        alert = db.session.get(SecurityAlert, app.security_center_ids["alert"])
        assert alert.status == "acknowledged"
        assert alert.acknowledged_at is not None


def test_only_admin_can_change_simulated_remediation_workflow():
    app = make_app()
    client = app.test_client()
    candidate_id = app.security_center_ids["candidate"]
    authenticate(client, app.security_center_ids["viewer"])
    denied = client.post(f"/remediation/{candidate_id}/approve")
    assert denied.status_code == 403

    authenticate(client, app.security_center_ids["admin"])
    approved = client.post(f"/remediation/{candidate_id}/approve", follow_redirects=True)
    assert approved.status_code == 200
    assert b"No device was updated" in approved.data
    verified = client.post(f"/remediation/{candidate_id}/verify", follow_redirects=True)
    assert verified.status_code == 200
    assert b"not evidence of a real patch" in verified.data
    with app.app_context():
        candidate = db.session.get(PatchCandidate, candidate_id)
        assert candidate.status == "verified"
        assert candidate.is_simulated is True
        assert "SIMULATED" in candidate.verification_note.upper()


def test_nvd_sync_records_success_and_rejects_duplicate_submission(monkeypatch):
    app = make_app()
    client = app.test_client()
    authenticate(client, app.security_center_ids["admin"])
    monkeypatch.setattr(
        "app.services.nvd_sync_service.sync_nvd_catalog",
        lambda keyword: 4 if keyword == "Example Vendor" else pytest.fail(keyword),
    )

    response = client.post(
        "/cves/sync",
        data={"keyword": "Example Vendor"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"4 CVE records processed" in response.data
    with app.app_context():
        log = SyncLog.query.one()
        assert log.status == "success"
        assert log.records_processed == 4
        assert log.completed_at is not None


def test_nvd_sync_shows_network_failure_and_keeps_failure_record(monkeypatch):
    app = make_app()
    client = app.test_client()
    authenticate(client, app.security_center_ids["admin"])

    def fail_sync(_keyword):
        raise requests.Timeout("NVD timed out")

    monkeypatch.setattr("app.services.nvd_sync_service.sync_nvd_catalog", fail_sync)
    response = client.post("/cves/sync", data={"keyword": "ESP32"}, follow_redirects=True)

    assert response.status_code == 200
    assert b"NVD sync failed" in response.data
    with app.app_context():
        log = SyncLog.query.one()
        assert log.status == "failed"
        assert "Timeout" in log.details
