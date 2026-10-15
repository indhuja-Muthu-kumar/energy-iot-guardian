from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from app import create_app
from app.extensions import db
from app.models.alert import SecurityAlert
from app.models.cve import CVE
from app.models.device import Device
from app.models.finding import Finding
from app.models.patch import PatchCandidate
from app.models.scan import Scan
from app.models.sync_log import SyncLog
from app.models.telemetry import TelemetryReading
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


def add_device(
    name,
    firmware="unknown",
    firmware_version=None,
    firmware_verification_status="UNKNOWN",
):
    device = Device(
        name=name,
        vendor="SMA Solar Technology",
        model="Sunny Boy TL-21",
        firmware=firmware,
        firmware_version=firmware_version,
        firmware_verification_status=firmware_verification_status,
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
        device = add_device(
            "Severity device",
            firmware="1.2.3",
            firmware_verification_status="VERIFIED",
        )
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
    assert "Espressif" in html
    assert "ESP32 development-board simulation" in html
    assert "Represented inverter product firmware:" in html
    assert "Unknown; no physical inverter or exact model is identified." in html
    assert "SIMULATED" in html
    assert "SIMULATED DEVICE · TELEMETRY" in html
    assert "public, unauthenticated broker" in html
    assert "cannot independently prove the sender is Wokwi" in html
    assert "local demo uses fixed synthetic values" in html
    assert "not verified SMA measurements or inverter firmware" in html
    assert "data-telemetry-source" in html
    assert "Voltage" in html


def test_dashboard_has_distinct_telemetry_loading_and_recovery_states():
    app = make_dashboard_app()
    client = app.test_client()
    authenticate(client, app.dashboard_user_id)

    response = client.get("/dashboard")
    html = response.get_data(as_text=True)
    script = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "static"
        / "js"
        / "dashboard.js"
    ).read_text(encoding="utf-8")

    assert response.status_code == 200
    assert "Loading telemetry…" in html
    assert 'data-stale-after-seconds="10"' in html
    assert 'data-telemetry-age' in html
    assert 'data-telemetry-error role="status" hidden' in html
    assert 'data-telemetry-session hidden' in html
    assert 'href="/auth/login?next=/dashboard"' in html
    assert "No telemetry received yet." in script
    assert "response.status === 401" in script
    assert "Telemetry API returned HTTP ${response.status}." in script
    assert "Last known: ${lastKnownStatus}" in script
    assert "window.setTimeout(pollTelemetry, nextDelay)" in script
    assert "Math.min(retryDelayMs * 2, 30000)" in script
    assert "Stale · SIMULATED · last reading is ${age}" in script
    assert "Stale reading · last known ${lastKnownStatus}" in script
    assert "renderWaiting(\"Telemetry service unavailable; retrying…\")" not in script


def test_dashboard_distinguishes_kev_last_success_from_failed_latest_attempt():
    app = make_dashboard_app()
    now = datetime.now(UTC).replace(tzinfo=None)
    with app.app_context():
        db.session.add_all([
            SyncLog(
                source="kev",
                status="success",
                records_processed=100,
                started_at=now - timedelta(days=3),
                completed_at=now - timedelta(days=3),
            ),
            SyncLog(
                source="kev",
                status="failed",
                details="ConnectionError",
                records_processed=0,
                started_at=now,
                completed_at=now,
            ),
        ])
        db.session.commit()

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    response = client.get("/dashboard")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "older than 24h" in html
    assert "latest attempt failed" in html
    assert "last success" in html
    assert "Current" in html
    assert "Calculated power" in html
    assert "Telemetry status" in html
    assert "Loading telemetry…" in html
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


def test_dashboard_does_not_confirm_legacy_firmware_without_evidence(monkeypatch):
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
    assert summary["severity"]["high"]["evaluated"] == 0
    assert summary["severity"]["high"]["potential"] == 1


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
    assert summary["severity"]["high"]["potential"] == 1


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
    assert summary["severity"]["critical"]["evaluated"] == 0
    assert summary["severity"]["critical"]["potential"] == 1


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


def test_dashboard_workflow_sections_use_saved_open_alerts_and_candidates():
    app = make_dashboard_app()
    with app.app_context():
        user = db.session.get(User, app.dashboard_user_id)
        user.is_admin = True
        device = add_device("Workflow inverter")
        now = datetime.now(UTC).replace(tzinfo=None)
        open_alert = SecurityAlert(
            device_id=device.id,
            cve_id="CVE-2026-1001",
            severity="high",
            title="Open workflow alert",
            summary="Stored open alert",
            dedupe_key="workflow-open",
            status="open",
            created_at=now,
        )
        resolved_alert = SecurityAlert(
            device_id=device.id,
            cve_id="CVE-2026-1002",
            severity="medium",
            title="Resolved workflow alert",
            summary="Stored resolved alert",
            dedupe_key="workflow-resolved",
            status="resolved",
            created_at=now,
        )
        pending_candidate = PatchCandidate(
            device_id=device.id,
            cve_id="CVE-2026-1001",
            component_name="Unverified component",
            patch_source="no-verified-vendor-source",
            evidence="Simulated candidate awaiting review",
            status="discovered",
            is_simulated=True,
            created_at=now,
            updated_at=now,
        )
        approved_candidate = PatchCandidate(
            device_id=device.id,
            cve_id="CVE-2026-1003",
            component_name="Unverified component",
            patch_source="no-verified-vendor-source",
            evidence="Simulated approval is not installation",
            status="approved",
            is_simulated=True,
            created_at=now,
            updated_at=now,
        )
        sync = SyncLog(
            source="kev",
            status="failed",
            details="Network failure",
            records_processed=0,
            started_at=now,
            completed_at=now,
        )
        reading = TelemetryReading(
            device_id=device.id,
            source_message_id="workflow-telemetry-1",
            voltage=230.0,
            current=2.0,
            power=460.0,
            timestamp=now,
            received_at=now,
            ingest_source="mqtt",
            telemetry_status="SIMULATED",
            chip_model="ESP32",
            chip_revision=1,
            arduino_core_version="3.0.0",
            esp_idf_version="5.1.0",
        )
        scan = Scan(
            device_id=device.id,
            status="failed",
            scan_type="device",
            summary="NVD request failed",
            created_at=now,
            started_at=now,
            completed_at=now,
        )
        db.session.add_all([
            open_alert,
            resolved_alert,
            pending_candidate,
            approved_candidate,
            sync,
            reading,
            scan,
        ])
        db.session.commit()
        pending_candidate_id = pending_candidate.id
        open_alert_id = open_alert.id

    client = app.test_client()
    authenticate(client, app.dashboard_user_id)
    response = client.get("/dashboard")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'data-open-alert-count="1">1</strong>' in html
    assert 'data-pending-review-count="1">1</strong>' in html
    open_panel = html.split('id="open-alerts-panel"', 1)[1].split(
        "</article>", 1
    )[0]
    assert "Open workflow alert" in open_panel
    assert "High" in open_panel
    assert "Workflow inverter" in open_panel
    assert "Open" in open_panel
    assert "Resolved workflow alert" not in open_panel
    assert 'href="/alerts?status=open"' in html
    assert f'href="/alerts/{open_alert_id}"' in open_panel

    review_panel = html.split('id="awaiting-review-panel"', 1)[1].split(
        "</article>", 1
    )[0]
    assert "CVE-2026-1001" in review_panel
    assert "CVE-2026-1003" not in review_panel
    assert f'action="/remediation/{pending_candidate_id}/approve"' in review_panel
    assert f'action="/remediation/{pending_candidate_id}/reject"' in review_panel

    activity_panel = html.split('id="recent-activity-panel"', 1)[1].split(
        "</article>", 1
    )[0]
    assert "NVD CVE sync" not in activity_panel
    assert "CISA KEV sync" in activity_panel
    assert "Failed" in activity_panel
    assert "Simulated telemetry received" in activity_panel
    assert "Device scan" in activity_panel
    assert "Open workflow alert" in activity_panel
    assert "SIMULATED remediation" in activity_panel

    remediation_panel = html.split('id="remediation-panel"', 1)[1].split(
        "</article>", 1
    )[0]
    assert "SIMULATED · Approved" in remediation_panel
    assert "SIMULATED · Discovered" in remediation_panel
    assert "not proof of a device update" in remediation_panel


def test_dashboard_workflow_sections_show_empty_states():
    app = make_dashboard_app()
    client = app.test_client()
    authenticate(client, app.dashboard_user_id)

    response = client.get("/dashboard")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "No open alerts." in html
    assert "No discovered candidates are awaiting review." in html
    assert "No scan, sync, telemetry, alert, or remediation activity" in html
    assert "No remediation candidates are recorded." in html
