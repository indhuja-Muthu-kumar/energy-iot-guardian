from __future__ import annotations

from app import create_app
from app.extensions import db
from app.models.alert import SecurityAlert
from app.models.cve import CVE
from app.models.device import Device
from app.models.finding import Finding
from app.models.patch import PatchCandidate
from app.models.scan import Scan
from app.services.alert_service import create_alerts_from_findings
from app.services.nvd_sync_service import sync_nvd_catalog
from app.services.patch_service import approve_patch, discover_patch_candidates, verify_patch


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
        device = Device(
            name="SolarGuard-01",
            telemetry_device_id="SolarGuard-01",
            vendor="SMA Solar Technology",
            model="Sunny Boy TL-21",
            firmware="unknown",
            firmware_version="1.0.0",
            status="active",
        )
        db.session.add(device)
        db.session.commit()
        device_id = device.id
    return app, device_id


class FakeNVDClient:
    def fetch_cves(self, keyword, page_size=10, start_index=0):
        return {
            "totalResults": 2,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2025-1001",
                        "descriptions": [{"lang": "en", "value": "Example issue 1"}],
                        "published": "2025-01-01T00:00:00Z",
                        "lastModified": "2025-01-02T00:00:00Z",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.1,
                                        "baseSeverity": "CRITICAL",
                                        "vectorString": (
                                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                        ),
                                        "attackVector": "NETWORK",
                                    }
                                }
                            ]
                        },
                        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2025-1002",
                        "descriptions": [{"lang": "en", "value": "Example issue 2"}],
                        "published": "2025-02-01T00:00:00Z",
                        "lastModified": "2025-02-02T00:00:00Z",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH",
                                        "vectorString": (
                                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
                                        ),
                                        "attackVector": "NETWORK",
                                    }
                                }
                            ]
                        },
                        "weaknesses": [{"description": [{"value": "CWE-89"}]}],
                    }
                },
            ],
        }


def test_nvd_sync_catalog_persists_and_deduplicates_cves():
    app, _device_id = make_app()
    with app.app_context():
        count = sync_nvd_catalog("Espressif ESP32", client=FakeNVDClient())
        assert count == 2
        assert CVE.query.count() == 2
        assert CVE.query.get("CVE-2025-1001").severity == "CRITICAL"


def test_nvd_sync_fetches_all_complete_result_pages():
    app, _device_id = make_app()

    class PagedNVDClient:
        def __init__(self):
            self.start_indices = []

        def fetch_cves(self, keyword, page_size=10, start_index=0):
            assert keyword == "Example runtime"
            assert page_size == 100
            self.start_indices.append(start_index)
            total = 102
            count = min(page_size, total - start_index)
            return {
                "totalResults": total,
                "vulnerabilities": [
                    {"cve": {"id": f"CVE-2025-{10000 + index}"}}
                    for index in range(start_index, start_index + count)
                ],
            }

    client = PagedNVDClient()
    with app.app_context():
        count = sync_nvd_catalog("Example runtime", client=client)
        assert count == 102
        assert client.start_indices == [0, 100]
        assert CVE.query.count() == 102


def test_alerts_are_deduplicated_for_repeated_findings():
    app, device_id = make_app()
    with app.app_context():
        scan = Scan(device_id=device_id, status="completed", summary="demo", scan_type="components")
        db.session.add(scan)
        db.session.commit()

        finding = Finding(
            scan_id=scan.id,
            device_id=device_id,
            cve_id="CVE-2025-1001",
            severity="HIGH",
            score=8.8,
            summary="High-risk issue",
            evidence="NVD exact version match",
            match_status="affected",
            confidence="high",
            component_name="ESP-IDF",
            component_version="v5.5.2",
        )
        duplicate = Finding(
            scan_id=scan.id,
            device_id=device_id,
            cve_id="CVE-2025-1001",
            severity="HIGH",
            score=8.8,
            summary="High-risk issue",
            evidence="NVD exact version match",
            match_status="affected",
            confidence="high",
            component_name="ESP-IDF",
            component_version="v5.5.2",
        )

        alerts = create_alerts_from_findings(device_id, [finding, duplicate])
        assert len(alerts) == 2
        assert SecurityAlert.query.count() == 1
        assert alerts[0].status == "open"


def test_patch_workflow_is_labeled_simulated_and_verifiable():
    app, device_id = make_app()
    with app.app_context():
        patch = discover_patch_candidates(device_id, cve_id="CVE-2025-1001")[0]
        assert isinstance(patch, PatchCandidate)
        assert patch.is_simulated is True
        assert patch.status == "discovered"

        approved = approve_patch(patch.id, approver="ops-demo")
        verified = verify_patch(patch.id, verifier="security-demo")

        assert approved.status == "approved"
        assert verified.status == "verified"
        assert "SIMULATED" in (verified.verification_note or "").upper()
