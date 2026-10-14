from __future__ import annotations

from app import create_app
from app.extensions import db
from app.models.cve import CVE
from app.models.device import Device
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User


def make_dashboard_app():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.create_all()
        user = User(username="dashboard", email="dashboard@example.com")
        user.set_password("dashboard-password")
        db.session.add(user)
        db.session.commit()
        app.dashboard_user_id = user.id
    return app


def authenticate(client, user_id):
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True


def add_device(name, firmware="unknown", firmware_version=None):
    device = Device(
        name=name,
        vendor="SMA Solar Technology",
        model="Sunny Boy TL-21",
        firmware=firmware,
        firmware_version=firmware_version,
    )
    db.session.add(device)
    db.session.flush()
    return device


def cpe_data(version_start="1.0", version_end="2.0"):
    return {
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": (
                        "cpe:2.3:a:sma:sunny_boy_tl_21:*:*:*:*:*:*:*:*"
                    ),
                    "versionStartIncluding": version_start,
                    "versionEndIncluding": version_end,
                }],
            }],
        }],
    }


def add_finding(
    device,
    scan,
    cve_id,
    severity,
    matched_by,
    score=None,
    raw=None,
):
    cve = CVE(
        id=cve_id,
        severity=severity,
        cvss_score=score,
        raw=raw,
    )
    db.session.add(cve)
    db.session.flush()
    db.session.add(
        Finding(
            scan_id=scan.id,
            device_id=device.id,
            cve_id=cve.id,
            severity=severity or "unknown",
            score=score,
            matched_by=matched_by,
        )
    )


def completed_scan(device):
    scan = Scan(device_id=device.id, status="completed")
    db.session.add(scan)
    db.session.flush()
    return scan


def test_dashboard_severity_summary_separates_evaluated_and_potential():
    app = make_dashboard_app()
    with app.app_context():
        device = add_device("Severity device", firmware="1.2.3")
        scan = completed_scan(device)
        for index, severity in enumerate(
            ("CRITICAL", "HIGH", "MEDIUM", "LOW"),
            start=1,
        ):
            add_finding(
                device,
                scan,
                f"CVE-2025-{1000 + index}",
                severity,
                "nvd-cpe-version-range",
                score=9.0 - index,
                raw=cpe_data(),
            )
        add_finding(
            device,
            scan,
            "CVE-2025-2001",
            "HIGH",
            "nvd-vendor-model-keyword",
            score=7.5,
        )
        add_finding(
            device,
            scan,
            "CVE-2025-2002",
            None,
            "nvd-cpe-product-potential",
        )
        db.session.commit()

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    response = client.get("/api/dashboard")

    assert response.status_code == 200
    summary = response.json["vulnerability_summary"]
    for severity in ("critical", "high", "medium", "low"):
        assert summary["severity"][severity]["evaluated"] == 1
    assert summary["severity"]["high"]["potential"] == 1
    assert summary["unknown_severity"] == {"evaluated": 0, "potential": 1}


def test_dashboard_counts_same_cves_per_device_by_stored_nvd_severity():
    app = make_dashboard_app()
    with app.app_context():
        devices = [
            add_device("Device 1"),
            add_device("Device 2"),
        ]
        scans = [completed_scan(device) for device in devices]
        severities = (
            ["CRITICAL"] * 8
            + ["HIGH"] * 5
            + ["LOW"]
        )

        for index, severity in enumerate(severities, start=9851):
            cve_id = f"CVE-2017-{index}"
            cve = CVE(id=cve_id, severity=severity)
            db.session.add(cve)
            db.session.flush()
            for device, scan in zip(devices, scans, strict=True):
                db.session.add(
                    Finding(
                        scan_id=scan.id,
                        device_id=device.id,
                        cve_id=cve_id,
                        severity=severity,
                        matched_by="nvd-vendor-model-keyword",
                    )
                )
        db.session.commit()

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    response = client.get("/api/dashboard")

    assert response.status_code == 200
    summary = response.json["vulnerability_summary"]
    assert summary["severity"] == {
        "critical": {"evaluated": 0, "potential": 16},
        "high": {"evaluated": 0, "potential": 10},
        "medium": {"evaluated": 0, "potential": 0},
        "low": {"evaluated": 0, "potential": 2},
    }
    assert summary["unknown_severity"] == {"evaluated": 0, "potential": 0}
    assert summary["devices_with_completed_latest_scan"] == 2


def test_dashboard_distinguishes_all_potential_findings_from_top_risk_total():
    app = make_dashboard_app()
    with app.app_context():
        devices = [
            add_device("Device 1"),
            add_device("Device 2"),
        ]
        scans = [completed_scan(device) for device in devices]
        severities = ["CRITICAL"] * 8 + ["HIGH"] * 5 + ["LOW"]

        for index, severity in enumerate(severities, start=9851):
            cve_id = f"CVE-2017-{index}"
            cve = CVE(id=cve_id, severity=severity)
            db.session.add(cve)
            db.session.flush()
            for device, scan in zip(devices, scans, strict=True):
                db.session.add(
                    Finding(
                        scan_id=scan.id,
                        device_id=device.id,
                        cve_id=cve_id,
                        severity=severity,
                        matched_by="nvd-vendor-model-keyword",
                    )
                )
        db.session.commit()

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    response = client.get("/dashboard")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert html.count("14 potential</span>") == 2
    assert html.count("13 C/H") == 2
    assert html.count("<small>14 total potential</small>") == 2


def test_dashboard_does_not_fall_back_to_finding_severity():
    app = make_dashboard_app()
    with app.app_context():
        device = add_device("Unknown CVE severity device")
        scan = completed_scan(device)
        cve = CVE(id="CVE-2025-6001", severity=None)
        db.session.add(cve)
        db.session.flush()
        db.session.add(
            Finding(
                scan_id=scan.id,
                device_id=device.id,
                cve_id=cve.id,
                severity="CRITICAL",
                matched_by="nvd-vendor-model-keyword",
            )
        )
        db.session.commit()

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    summary = client.get("/api/dashboard").json["vulnerability_summary"]
    assert summary["severity"]["critical"]["potential"] == 0
    assert summary["unknown_severity"] == {"evaluated": 0, "potential": 1}


def test_dashboard_panels_use_latest_database_activity_and_potential_counts():
    app = make_dashboard_app()
    with app.app_context():
        device = add_device("Dashboard inverter", firmware="1.5.0")
        scan = completed_scan(device)
        add_finding(
            device,
            scan,
            "CVE-2025-6101",
            "CRITICAL",
            "nvd-vendor-model-keyword",
        )
        add_finding(
            device,
            scan,
            "CVE-2025-6102",
            "HIGH",
            "nvd-cpe-version-range",
            raw=cpe_data(),
        )
        db.session.commit()
        scan_id = scan.id
        device_id = device.id

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    response = client.get("/dashboard")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Potential Critical" in html
    assert "Dashboard inverter" in html
    assert "SMA Solar Technology" in html
    assert f'href="/scans/{scan_id}">#{scan_id}</a>' in html
    assert f'href="/devices/{device_id}">Dashboard inverter</a>' in html
    assert "1 potential</span>" in html
    assert "Potential / indeterminate latest-scan matches" in html
    assert f"#{scan_id}" in html
    assert "not confirmed vulnerabilities" in html
    assert "recent completed scans" in html


def test_dashboard_includes_clearly_labeled_simulated_telemetry():
    app = make_dashboard_app()
    client = app.test_client()
    authenticate(client, app.dashboard_user_id)

    response = client.get("/dashboard")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Simulated solar telemetry" in html
    assert "SolarGuard-01" in html
    assert "SMA Solar Technology" in html
    assert "Sunny Boy TL-21" in html
    assert "SIMULATED" in html
    assert "Readings come from the Wokwi ESP32 simulation through MQTT" in html
    assert "not verified SMA hardware measurements or inverter firmware" in html
    assert "Voltage" in html
    assert "Current" in html
    assert "Calculated power" in html
    assert "Demo status" in html
    assert "Waiting for telemetry" in html
    assert "Recent simulated readings" in html
    assert "Updates every 3 seconds" in html
    assert "Potential / indeterminate latest-scan matches" in html
    assert "Potential and indeterminate matches are not confirmed vulnerabilities." in html


def test_dashboard_handles_missing_device_relationship_in_recent_scans():
    app = make_dashboard_app()
    with app.app_context():
        scan = Scan(device_id=99999, status="completed")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert f'href="/scans/{scan_id}">#{scan_id}</a>' in response.get_data(as_text=True)
    assert b"Unknown device" in response.data


def test_dashboard_uses_latest_scan_firmware_result_and_legacy_fallback(monkeypatch):
    app = make_dashboard_app()
    with app.app_context():
        device = add_device("Legacy device", firmware="1.5.0")
        db.session.commit()
        device_id = device.id

    cve = {
        "cve": {
            "id": "CVE-2025-3001",
            "descriptions": [{"lang": "en", "value": "Test firmware issue."}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"},
                }],
            },
            "configurations": [{
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
                }],
            }],
        },
    }
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 1,
            "vulnerabilities": [cve],
        },
    )
    with app.app_context():
        from app.services.scan_service import run_scan_for_device

        scan = run_scan_for_device(device_id)
        assert scan.status == "completed"

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    summary = client.get("/api/dashboard").json["vulnerability_summary"]
    assert summary["severity"]["high"]["evaluated"] == 1


def test_dashboard_prefers_current_firmware_version_for_applicability():
    app = make_dashboard_app()
    with app.app_context():
        device = add_device(
            "Preferred firmware device",
            firmware="1.5.0",
            firmware_version="2.5.0",
        )
        scan = completed_scan(device)
        add_finding(
            device,
            scan,
            "CVE-2025-3003",
            "HIGH",
            "nvd-cpe-version-range",
            raw=cpe_data(),
        )
        db.session.commit()

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    summary = client.get("/api/dashboard").json["vulnerability_summary"]
    assert summary["severity"]["high"]["evaluated"] == 0
    assert summary["severity"]["high"]["potential"] == 0


def test_dashboard_unknown_firmware_is_potential_not_evaluated(monkeypatch):
    app = make_dashboard_app()
    with app.app_context():
        device = add_device("Unknown firmware device")
        db.session.commit()
        device_id = device.id

    cve = {
        "cve": {
            "id": "CVE-2025-3002",
            "descriptions": [{
                "lang": "en",
                "value": "SMA Solar Technology Sunny Boy TL-21 issue.",
            }],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 8.0, "baseSeverity": "HIGH"},
                }],
            },
            "configurations": [{
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
                }],
            }],
        },
    }
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 1,
            "vulnerabilities": [cve],
        },
    )
    with app.app_context():
        from app.services.scan_service import run_scan_for_device

        scan = run_scan_for_device(device_id)
        assert scan.status == "completed"

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    summary = client.get("/api/dashboard").json["vulnerability_summary"]
    assert summary["severity"]["high"]["evaluated"] == 0
    assert summary["severity"]["high"]["potential"] == 1


def test_dashboard_counts_duplicate_cves_once_per_device_and_scan():
    app = make_dashboard_app()
    with app.app_context():
        device = add_device("Duplicate device", firmware="1.5.0")
        scan = completed_scan(device)
        add_finding(
            device,
            scan,
            "CVE-2025-4001",
            "CRITICAL",
            "nvd-cpe-version-range",
            raw=cpe_data(),
        )
        duplicate = Finding(
            scan_id=scan.id,
            device_id=device.id,
            cve_id="CVE-2025-4001",
            severity="CRITICAL",
            matched_by="nvd-cpe-version-range",
        )
        db.session.add(duplicate)
        db.session.commit()

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    summary = client.get("/api/dashboard").json["vulnerability_summary"]
    assert summary["severity"]["critical"]["evaluated"] == 1


def test_dashboard_uses_newest_completed_scan_per_device():
    app = make_dashboard_app()
    with app.app_context():
        device = add_device("Latest completed device")
        older_scan = completed_scan(device)
        add_finding(
            device,
            older_scan,
            "CVE-2025-4501",
            "HIGH",
            "nvd-cpe-version-range",
        )
        newest_scan = completed_scan(device)
        add_finding(
            device,
            newest_scan,
            "CVE-2025-4502",
            "LOW",
            "nvd-vendor-model-keyword",
        )
        db.session.commit()

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    summary = client.get("/api/dashboard").json["vulnerability_summary"]
    assert summary["severity"]["high"]["evaluated"] == 0
    assert summary["severity"]["low"]["potential"] == 1


def test_dashboard_omits_old_results_after_new_failed_or_incomplete_scan():
    app = make_dashboard_app()
    with app.app_context():
        failed_device = add_device("Failed latest device")
        old_scan = completed_scan(failed_device)
        add_finding(
            failed_device,
            old_scan,
            "CVE-2025-5001",
            "HIGH",
            "nvd-cpe-version-range",
        )
        failed_scan = Scan(device_id=failed_device.id, status="failed")
        db.session.add(failed_scan)

        running_device = add_device("Running latest device")
        old_running_scan = completed_scan(running_device)
        add_finding(
            running_device,
            old_running_scan,
            "CVE-2025-5002",
            "CRITICAL",
            "nvd-cpe-version-range",
        )
        running_scan = Scan(device_id=running_device.id, status="running")
        db.session.add(running_scan)

        add_device("No scan device")
        db.session.commit()

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    summary = client.get("/api/dashboard").json["vulnerability_summary"]
    assert summary["severity"]["high"]["evaluated"] == 0
    assert summary["severity"]["critical"]["evaluated"] == 0
    assert summary["devices_with_failed_latest_scan"] == 1
    assert summary["devices_with_incomplete_latest_scan"] == 1
    assert summary["devices_without_scans"] == 1
    assert summary["devices_with_completed_latest_scan"] == 0


def test_dashboard_empty_state_and_page_scope_are_clear():
    app = make_dashboard_app()
    client = app.test_client()
    authenticate(client, app.dashboard_user_id)

    page = client.get("/dashboard")
    assert page.status_code == 200
    assert b"No devices are registered yet" in page.data
    assert b"newest scan by creation time" in page.data

    with app.app_context():
        add_device("No scans device")
        db.session.commit()
    no_scans_page = client.get("/dashboard")
    assert b"No device has a completed latest scan yet" in no_scans_page.data
