import requests
import pytest

from app import create_app
from app.extensions import db
from app.models.cve import CVE
from app.models.device import Device
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.services.scan_service import run_scan_for_device


def make_cve(cve_id, description="SMA Solar Technology Sunny Boy TL-21 issue"):
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
        }
    }


@pytest.fixture
def device_id():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.create_all()
        admin = User(username="admin", email="admin@example.com")
        admin.set_password("test-password")
        device = Device(
            name="Test inverter",
            vendor="SMA Solar Technology",
            model="Sunny Boy TL-21",
            firmware="unknown",
        )
        db.session.add_all([admin, device])
        db.session.commit()
        yield device.id


def test_empty_nvd_result_completes_without_creating_records(monkeypatch, device_id):
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 0,
            "vulnerabilities": [],
        },
    )

    scan = run_scan_for_device(device_id)

    assert scan.status == "completed"
    assert CVE.query.count() == 0
    assert Finding.query.count() == 0


def test_scan_saves_cve_metadata_and_affected_version_evidence(
    monkeypatch,
    device_id,
):
    device = db.session.get(Device, device_id)
    device.firmware_version = "1.5.0"
    db.session.commit()
    cve_data = {
        "id": "cve-2025-1234",
        "published": "2025-01-01T00:00:00.000Z",
        "lastModified": "2025-01-02T00:00:00.000Z",
        "descriptions": [
            {"lang": "fr", "value": "Description française"},
            {"lang": "en", "value": "English SMA Sunny Boy advisory."},
        ],
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {
                    "baseScore": 8.8,
                    "baseSeverity": "HIGH",
                    "attackVector": "NETWORK",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
            }],
        },
        "weaknesses": [{
            "description": [{"lang": "en", "value": "CWE-79"}],
        }],
        "references": [{
            "url": "https://example.test/advisory",
            "tags": ["Vendor Advisory"],
        }],
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": (
                        "cpe:2.3:a:sma:sunny_boy_tl_21:*:*:*:*:*:*:*:*"
                    ),
                    "versionStartIncluding": "1.0",
                    "versionEndExcluding": "2.0",
                }],
            }],
        }],
    }
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 1,
            "vulnerabilities": [{"cve": cve_data}],
        },
    )

    scan = run_scan_for_device(device_id)

    cve = db.session.get(CVE, "CVE-2025-1234")
    finding = Finding.query.one()
    assert scan.status == "completed"
    assert cve.description == "English SMA Sunny Boy advisory."
    assert cve.severity == "HIGH"
    assert cve.cvss_score == 8.8
    assert cve.cvss_vector.startswith("CVSS:3.1/")
    assert cve.attack_vector == "NETWORK"
    assert cve.cwe == "CWE-79"
    assert cve.raw["references"][0]["url"] == "https://example.test/advisory"
    assert finding.cve_id == "CVE-2025-1234"
    assert finding.match_status == "affected"
    assert finding.matched_by == "nvd-cpe-version-range"
    assert "1.5.0" in finding.evidence
    assert "not independently verified" in finding.evidence


def test_scan_handles_cve_records_with_incomplete_optional_fields(
    monkeypatch,
    device_id,
):
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 1,
            "vulnerabilities": [{"cve": {"id": "CVE-2025-6789"}}],
        },
    )

    scan = run_scan_for_device(device_id)

    cve = db.session.get(CVE, "CVE-2025-6789")
    assert scan.status == "completed"
    assert cve is not None
    assert cve.description == ""
    assert cve.severity is None
    assert cve.cvss_score is None
    assert cve.cvss_vector is None
    assert cve.raw == {"id": "CVE-2025-6789"}
    assert Finding.query.count() == 0


def test_invalid_cve_identifiers_are_ignored(monkeypatch, device_id):
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 2,
            "vulnerabilities": [
                {"cve": {"id": "not-a-cve", "descriptions": []}},
                {"cve": {"id": "CVE-2025-12", "descriptions": []}},
            ]
        },
    )

    scan = run_scan_for_device(device_id)

    assert scan.status == "completed"
    assert CVE.query.count() == 0
    assert Finding.query.count() == 0


def test_upstream_error_fails_scan_without_returning_raw_exception(
    monkeypatch, device_id
):
    def raise_timeout(*_args, **_kwargs):
        raise requests.Timeout("sensitive upstream details")

    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        raise_timeout,
    )

    scan = run_scan_for_device(device_id)

    assert scan.status == "failed"
    assert "sensitive upstream details" not in scan.summary
    assert Scan.query.count() == 1


def test_malformed_entry_mid_scan_rolls_back_partial_cve_and_findings(
    monkeypatch, device_id
):
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 2,
            "vulnerabilities": [make_cve("CVE-2025-1234"), None],
        },
    )

    scan = run_scan_for_device(device_id)

    assert scan.status == "failed"
    assert "No partial findings were saved" in scan.summary
    assert CVE.query.count() == 0
    assert Finding.query.count() == 0


def test_malformed_nvd_pagination_metadata_fails_scan(monkeypatch, device_id):
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {"vulnerabilities": []},
    )

    scan = run_scan_for_device(device_id)

    assert scan.status == "failed"
    assert "invalid response" in scan.summary
    assert CVE.query.count() == 0
    assert Finding.query.count() == 0


def test_unexpected_error_mid_scan_rolls_back_all_changes(monkeypatch, device_id):
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 2,
            "vulnerabilities": [
                make_cve("CVE-2025-1234"),
                make_cve("CVE-2025-5678"),
            ]
        },
    )
    calls = 0

    def fail_on_second_assessment(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("internal matching failure")
        return None

    monkeypatch.setattr(
        "app.services.scan_service.assess_cpe_match",
        fail_on_second_assessment,
    )

    scan = run_scan_for_device(device_id)

    assert scan.status == "failed"
    assert "internal error" in scan.summary
    assert CVE.query.count() == 0
    assert Finding.query.count() == 0


def test_duplicate_cve_entries_create_one_potential_finding(
    monkeypatch, device_id
):
    entry = make_cve("CVE-2025-1234")
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 2,
            "vulnerabilities": [entry, entry],
        },
    )

    scan = run_scan_for_device(device_id)
    finding = Finding.query.one()

    assert scan.status == "completed"
    assert Finding.query.count() == 1
    assert finding.score is None
    assert finding.severity == "unknown"
    assert finding.matched_by == "nvd-vendor-model-keyword"
    assert "potential match only" in finding.evidence
    assert "duplicate CVE entries were ignored" in scan.summary


def test_unknown_firmware_cpe_match_remains_potential(monkeypatch, device_id):
    cve = make_cve("CVE-2025-1234")
    cve["cve"]["configurations"] = [{
        "nodes": [{
            "operator": "OR",
            "cpeMatch": [{
                "vulnerable": True,
                "criteria": (
                    "cpe:2.3:a:sma:sunny_boy_tl_21:*:*:*:*:*:*:*:*"
                ),
                "versionStartIncluding": "1.0",
                "versionEndIncluding": "2.0",
            }],
        }]
    }]
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 1,
            "vulnerabilities": [cve],
        },
    )

    scan = run_scan_for_device(device_id)
    finding = Finding.query.one()

    assert scan.status == "completed"
    assert finding.matched_by == "nvd-cpe-product-potential"
    assert "firmware is unknown" in finding.evidence


def test_result_pages_are_fetched_before_scan_can_complete(monkeypatch, device_id):
    monkeypatch.setattr("app.services.scan_service.NVD_PAGE_SIZE", 1)
    requested_indices = []

    def fetch_page(_client, _keyword, page_size, start_index=0):
        requested_indices.append((page_size, start_index))
        entry = make_cve(f"CVE-2025-{1234 + start_index}")
        return {"totalResults": 2, "vulnerabilities": [entry]}

    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        fetch_page,
    )

    scan = run_scan_for_device(device_id)

    assert scan.status == "completed"
    assert requested_indices == [(1, 0), (1, 1)]
    assert CVE.query.count() == 2
    assert Finding.query.count() == 2


def test_failure_fetching_later_page_does_not_save_first_page_results(
    monkeypatch, device_id
):
    monkeypatch.setattr("app.services.scan_service.NVD_PAGE_SIZE", 1)
    calls = 0

    def fail_second_page(_client, _keyword, page_size, start_index=0):
        nonlocal calls
        calls += 1
        if start_index:
            raise requests.Timeout("temporary timeout")
        return {
            "totalResults": 2,
            "vulnerabilities": [make_cve("CVE-2025-1234")],
        }

    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        fail_second_page,
    )

    scan = run_scan_for_device(device_id)

    assert calls == 2
    assert scan.status == "failed"
    assert CVE.query.count() == 0
    assert Finding.query.count() == 0


def test_database_commit_failure_rolls_back_findings_and_marks_scan_failed(
    monkeypatch, device_id
):
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 1,
            "vulnerabilities": [make_cve("CVE-2025-1234")],
        },
    )
    real_commit = db.session.commit
    commit_count = 0

    def fail_scan_commit_once():
        nonlocal commit_count
        commit_count += 1
        if commit_count == 2:
            raise RuntimeError("simulated transaction commit failure")
        real_commit()

    monkeypatch.setattr(db.session, "commit", fail_scan_commit_once)

    scan = run_scan_for_device(device_id)

    assert scan.status == "failed"
    assert Finding.query.count() == 0
    assert "No partial findings were saved" in scan.summary


def test_interrupted_scan_is_saved_as_failed_before_interrupt_propagates(
    monkeypatch, device_id
):
    def interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        interrupt,
    )

    with pytest.raises(KeyboardInterrupt):
        run_scan_for_device(device_id)

    scan = Scan.query.one()
    assert scan.status == "failed"
    assert "interrupted" in scan.summary
    assert Finding.query.count() == 0
