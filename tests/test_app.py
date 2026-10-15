import re

import pytest

from app import create_app
from app.extensions import db
from app.models.cve import CVE
from app.models.device import Device
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User


def make_test_app():
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"})
    with app.app_context():
        db.create_all()
        admin = User(username="admin", email="admin@example.com")
        admin.set_password("secret")
        db.session.add(admin)
        db.session.commit()
    return app


def csrf_token(response):
    return re.search(
        r'<meta name="csrf-token" content="([^"]+)"',
        response.get_data(as_text=True),
    ).group(1)


def test_create_app_works_in_test_mode():
    app = make_test_app()
    with app.app_context():
        saved = User.query.filter_by(username="admin").first()
        assert saved is not None
        assert saved.check_password("secret")


def test_scans_page_shows_device_details_and_unknown_device_fallback():
    app = make_test_app()
    with app.app_context():
        device = Device(
            name="Sunny Boy",
            vendor="SMA",
            model="Sunny Boy TL-21",
            firmware="1.2.3",
        )
        db.session.add(device)
        db.session.flush()
        scan = Scan(
            device_id=device.id,
            status="completed",
            summary="Scan finished.",
        )
        db.session.add(scan)
        db.session.flush()
        missing_device_scan = Scan(
            device_id=99999,
            status="failed",
            summary="Device record is unavailable.",
        )
        db.session.add(missing_device_scan)
        db.session.commit()
        scan_id = scan.id
        device_id = device.id
        missing_scan_id = missing_device_scan.id

    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True

    response = client.get("/scans")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "<th>Device</th>" in html
    assert f'href="/scans/{scan_id}">#{scan_id}</a>' in html
    assert f'href="/devices/{device_id}">Sunny Boy</a>' in html
    assert "SMA" in html
    assert "Sunny Boy TL-21" in html
    assert f'href="/scans/{missing_scan_id}">#{missing_scan_id}</a>' in html
    assert "Unknown device" in html
    assert "completed" in html
    assert "Scan finished." in html
    assert "Timestamp" in html
    device_details = client.get(f"/devices/{device_id}").get_data(as_text=True)
    assert "Run Scan" in device_details
    assert 'data-device-form' in device_details
    assert "Manufacturer firmware reference" in device_details
    assert "does not verify the firmware installed on this asset" in device_details.lower()
    assert "Selecting the PV Inverter guide" in device_details


def test_authenticated_pages_render_inside_shared_theme_shell():
    app = make_test_app()
    with app.app_context():
        user = User.query.filter_by(username="admin").first()
        user.is_admin = True
        device = Device(
            name="Theme test inverter",
            vendor="Example Energy",
            model="INV-2",
            firmware="unknown",
        )
        db.session.add(device)
        db.session.flush()
        scan = Scan(device_id=device.id, status="completed")
        cve = CVE(id="CVE-2025-7654", severity="HIGH", description="Theme test CVE.")
        db.session.add_all([scan, cve])
        db.session.commit()
        device_id = device.id
        scan_id = scan.id

    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True

    paths = (
        "/",
        "/auth/login",
        "/dashboard",
        "/devices",
        f"/devices/{device_id}",
        "/scans",
        "/scans/new",
        f"/scans/{scan_id}",
        "/cves",
        "/cves/CVE-2025-7654",
        "/reports",
        "/settings",
        "/admin/users",
    )
    for path in paths:
        response = client.get(path)
        assert response.status_code == 200, path
        assert b'class="app-shell"' in response.data, path
        assert b'class="nav"' in response.data, path
        assert b"theme.css" in response.data, path


def test_production_rejects_example_secret():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app({"ENV": "production", "SECRET_KEY": "change-this-secret-key"})


def test_production_disables_debug_and_uses_secure_session_cookies():
    app = create_app({
        "ENV": "production",
        "SECRET_KEY": "a-strong-test-secret-that-is-not-used",
        "DEBUG": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })

    assert app.config["DEBUG"] is False
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True


def test_login_form_csrf_token_allows_login():
    app = make_test_app()
    client = app.test_client()
    page = client.get("/auth/login")
    token = re.search(
        r'name="csrf_token" value="([^"]+)"',
        page.get_data(as_text=True),
    ).group(1)

    response = client.post(
        "/auth/login",
        data={"username": "admin", "password": "secret", "csrf_token": token},
    )

    assert response.status_code == 302


@pytest.mark.parametrize(
    ("password", "expected_output", "should_create_user"),
    [
        ("p" * 13, "Password must be at least 14 characters.", False),
        ("p" * 14, "Admin created: new-admin", True),
    ],
)
def test_create_admin_requires_at_least_14_characters(
    monkeypatch,
    password,
    expected_output,
    should_create_user,
):
    app = make_test_app()
    inputs = iter(["new-admin", "new-admin@example.com"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(inputs))
    passwords = iter([password, password])
    monkeypatch.setattr("app.getpass", lambda _prompt: next(passwords))

    result = app.test_cli_runner().invoke(args=["create-admin"])

    assert result.exit_code == 0
    assert expected_output in result.output
    with app.app_context():
        user = User.query.filter_by(username="new-admin").first()
        assert (user is not None) is should_create_user
        if user is not None:
            assert user.check_password(password)


def test_login_still_accepts_existing_shorter_password():
    app = make_test_app()
    client = app.test_client()
    page = client.get("/auth/login")
    token = re.search(
        r'name="csrf_token" value="([^"]+)"',
        page.get_data(as_text=True),
    ).group(1)

    response = client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "secret",
            "csrf_token": token,
        },
    )

    assert response.status_code == 302


def test_logout_requires_csrf_protected_post():
    app = make_test_app()
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True

    page = client.get("/dashboard")
    token = re.search(
        r'name="csrf_token" value="([^"]+)"',
        page.get_data(as_text=True),
    ).group(1)

    assert client.get("/auth/logout").status_code == 405
    assert client.post("/auth/logout").status_code == 400
    response = client.post("/auth/logout", data={"csrf_token": token})
    assert response.status_code == 302
    assert client.get("/dashboard").status_code == 302


def test_scan_api_runs_nvd_query_and_creates_single_scan(monkeypatch):
    app = make_test_app()
    with app.app_context():
        db.session.add(
            Device(
                name="Sunny Boy",
                vendor="SMA",
                model="Sunny Boy TL-21",
                firmware="1.2.3",
            )
        )
        db.session.commit()
        device_id = Device.query.first().id

    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda _client, keyword, page_size: {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2025-1234",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "SMA Sunny Boy TL-21 vulnerability.",
                            }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 8.1,
                                        "baseSeverity": "HIGH",
                                        "attackVector": "NETWORK",
                                    }
                                }
                            ]
                        },
                        "published": "2025-01-01T00:00:00.000",
                        "lastModified": "2025-01-02T00:00:00.000",
                        "weaknesses": [],
                    }
                }
            ]
        },
    )
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    device_profile = client.get(f"/devices/{device_id}").get_data(as_text=True)
    assert "Run Scan" in device_profile
    assert f'name="device_id" value="{device_id}"' in device_profile
    assert "data-device-form" in device_profile
    token = csrf_token(client.get("/scans/new"))

    response = client.post(
        "/api/scans",
        json={"device_id": device_id},
        headers={"X-CSRFToken": token},
    )

    assert response.status_code == 201
    assert response.json["status"] == "completed"
    assert response.json["id"]
    assert "potential matches" in response.json["summary"]
    assert client.get("/dashboard").status_code == 200
    report = client.get("/api/reports/csv")
    assert report.status_code == 200
    assert "CVE-2025-1234" in report.get_data(as_text=True)
    scan_report = client.get(f"/api/reports/csv?scan_id={response.json['id']}")
    assert scan_report.status_code == 200
    assert "Potential keyword match" in scan_report.get_data(as_text=True)
    assert "NVD description keyword match" in scan_report.get_data(as_text=True)
    assert client.get("/api/reports/csv?scan_id=invalid").status_code == 400
    assert client.get("/api/reports/csv?scan_id=").status_code == 400
    assert client.get("/api/reports/csv?scan_id=999").status_code == 404
    scan_page = client.get(f"/scans/{response.json['id']}")
    assert scan_page.status_code == 200
    assert b"Potential keyword match" in scan_page.data
    assert b"NVD description keyword match" in scan_page.data
    assert b"CVE-2025-1234" in scan_page.data
    assert b"NVD source not specified" in scan_page.data
    with app.app_context():
        empty_scan = Scan(device_id=device_id, status="completed")
        db.session.add(empty_scan)
        db.session.commit()
        empty_scan_id = empty_scan.id
    empty_report = client.get(f"/api/reports/csv?scan_id={empty_scan_id}")
    assert empty_report.status_code == 200
    assert "CVE-2025-1234" not in empty_report.get_data(as_text=True)
    assert "match_status" in empty_report.get_data(as_text=True)
    with app.app_context():
        failed_scan = Scan(
            device_id=device_id,
            status="failed",
            summary="The upstream request failed.",
        )
        db.session.add(failed_scan)
        db.session.commit()
        failed_scan_id = failed_scan.id
    failed_scan_page = client.get(f"/scans/{failed_scan_id}")
    assert failed_scan_page.status_code == 200
    assert b"not a clean scan result" in failed_scan_page.data
    with app.app_context():
        assert Scan.query.count() == 3
        assert Finding.query.count() == 1


def test_inventory_api_creates_device_and_admin_routes_require_admin():
    app = make_test_app()
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    token = csrf_token(client.get("/devices"))

    response = client.post(
        "/api/devices",
        json={
            "name": "Solar inverter",
            "vendor": "Example Energy",
            "model": "INV-1",
            "firmware_version": "1.0",
            "asset_tag": "ASSET-001",
            "site": "North field",
        },
        headers={"X-CSRFToken": token},
    )
    assert response.status_code == 201
    assert response.json["name"] == "Solar inverter"
    assert response.json["firmware_version"] == "1.0"
    assert response.json["asset_tag"] == "ASSET-001"
    assert response.json["site"] == "North field"
    too_long_vendor = client.post(
        "/api/devices",
        json={
            "name": "Too-long vendor",
            "vendor": "V" * 121,
            "model": "INV-2",
        },
        headers={"X-CSRFToken": token},
    )
    assert too_long_vendor.status_code == 400
    too_long_firmware_version = client.post(
        "/api/devices",
        json={
            "name": "Too-long firmware version",
            "vendor": "Example Energy",
            "model": "INV-3",
            "firmware_version": "V" * 121,
        },
        headers={"X-CSRFToken": token},
    )
    assert too_long_firmware_version.status_code == 400
    too_long_asset_tag = client.post(
        "/api/devices",
        json={
            "name": "Too-long asset tag",
            "vendor": "Example Energy",
            "model": "INV-4",
            "asset_tag": "A" * 81,
        },
        headers={"X-CSRFToken": token},
    )
    assert too_long_asset_tag.status_code == 400
    assert client.get("/admin/users").status_code == 403
    assert client.get("/api/admin/users").status_code == 403


def test_admin_can_archive_device_without_losing_history_or_other_device():
    app = make_test_app()
    with app.app_context():
        admin = db.session.get(User, 1)
        admin.is_admin = True
        archived = Device(
            name="SMA Sunny Boy TL-21 Demo",
            vendor="SMA Solar Technology",
            model="Sunny Boy TL-21",
        )
        active = Device(
            name="SMA Sunny Boy TL-21 Test Device",
            vendor="SMA Solar Technology",
            model="Sunny Boy TL-21",
        )
        cve = CVE(id="CVE-2025-4321", description="Historical test finding")
        db.session.add_all([archived, active, cve])
        db.session.flush()
        scan = Scan(
            device_id=archived.id,
            status="completed",
            summary="Historical scan to retain.",
        )
        db.session.add(scan)
        db.session.flush()
        finding = Finding(
            scan_id=scan.id,
            device_id=archived.id,
            cve_id=cve.id,
            severity="HIGH",
            summary="Historical finding to retain.",
        )
        db.session.add(finding)
        db.session.commit()
        archived_id = archived.id
        active_id = active.id
        scan_id = scan.id
        finding_id = finding.id

    assert archived_id == 1
    assert active_id == 2

    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    token = csrf_token(client.get("/devices"))

    response = client.post(
        f"/devices/{archived_id}/archive",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Device archived." in response.data
    inventory = client.get("/devices").get_data(as_text=True)
    assert "SMA Sunny Boy TL-21 Demo" not in inventory
    assert "SMA Sunny Boy TL-21 Test Device" in inventory
    api_devices = client.get("/api/devices").json["items"]
    assert [device["id"] for device in api_devices] == [active_id]
    scan_page = client.get("/scans/new").get_data(as_text=True)
    assert f'value="{active_id}"' in scan_page
    assert f'value="{archived_id}"' not in scan_page

    detail = client.get(f"/devices/{archived_id}")
    assert detail.status_code == 200
    assert b"Archived" in detail.data
    assert b"Historical scan to retain." in detail.data
    assert b"data-device-edit" not in detail.data
    reports = client.get("/reports")
    assert reports.status_code == 200
    assert b"SMA Sunny Boy TL-21 Demo" in reports.data
    exported = client.get(f"/api/reports/csv?scan_id={scan_id}")
    assert exported.status_code == 200
    assert b"CVE-2025-4321" in exported.data
    assert b"Historical finding to retain." in exported.data

    scan_token = csrf_token(client.get("/scans/new"))
    rejected_scan = client.post(
        "/api/scans",
        json={"device_id": archived_id},
        headers={"X-CSRFToken": scan_token},
    )
    assert rejected_scan.status_code == 409

    with app.app_context():
        archived_record = db.session.get(Device, archived_id)
        active_record = db.session.get(Device, active_id)
        assert archived_record.status == "archived"
        assert active_record.status == "active"
        assert db.session.get(Scan, scan_id) is not None
        assert db.session.get(Finding, finding_id) is not None
        assert Scan.query.count() == 1
        assert Finding.query.count() == 1


def test_archiving_requires_admin_and_csrf_and_device_api_cannot_bypass_it():
    app = make_test_app()
    with app.app_context():
        device = Device(
            name="Protected inverter",
            vendor="Example Energy",
            model="INV-PROTECTED",
        )
        db.session.add(device)
        db.session.commit()
        device_id = device.id

    anonymous_client = app.test_client()
    assert anonymous_client.get(f"/devices/{device_id}/archive").status_code == 405
    anonymous_token = csrf_token(anonymous_client.get("/auth/login"))
    anonymous_response = anonymous_client.post(
        f"/devices/{device_id}/archive",
        data={"csrf_token": anonymous_token},
    )
    assert anonymous_response.status_code == 302
    assert "/auth/login" in anonymous_response.headers["Location"]

    teammate_client = app.test_client()
    with teammate_client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    token = csrf_token(teammate_client.get("/devices"))
    assert teammate_client.post(
        f"/devices/{device_id}/archive",
        data={"csrf_token": token},
    ).status_code == 403
    status_update = teammate_client.patch(
        f"/api/devices/{device_id}",
        json={"status": "archived"},
        headers={"X-CSRFToken": token},
    )
    assert status_update.status_code == 403
    assert teammate_client.post(f"/devices/{device_id}/archive").status_code == 400

    with app.app_context():
        device = db.session.get(Device, device_id)
        assert device.status == "active"


def test_admin_can_delete_device_without_history_and_inventory_has_actions():
    app = make_test_app()
    with app.app_context():
        admin = db.session.get(User, 1)
        admin.is_admin = True
        removable = Device(
            name="Removable inverter",
            vendor="Example Energy",
            model="INV-REMOVE",
        )
        unrelated = Device(
            name="Unrelated inverter",
            vendor="Example Energy",
            model="INV-KEEP",
        )
        cve = CVE(id="CVE-2025-1234", description="Preserve this CVE")
        db.session.add_all([removable, unrelated, cve])
        db.session.flush()
        scan = Scan(device_id=unrelated.id, status="completed")
        db.session.add(scan)
        db.session.flush()
        db.session.add(
            Finding(
                scan_id=scan.id,
                device_id=unrelated.id,
                cve_id=cve.id,
                severity="LOW",
            )
        )
        db.session.commit()
        removable_id = removable.id
        unrelated_id = unrelated.id

    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    inventory = client.get("/devices")
    token = csrf_token(inventory)
    html = inventory.get_data(as_text=True)
    assert "<th>Actions</th>" in html
    assert "Delete this device?" in html
    assert f'action="/devices/{removable_id}/delete"' in html

    response = client.post(
        f"/devices/{removable_id}/delete",
        data={"csrf_token": token},
    )

    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Device, removable_id) is None
        assert db.session.get(Device, unrelated_id) is not None
        assert Scan.query.filter_by(device_id=unrelated_id).count() == 1
        assert Finding.query.filter_by(device_id=unrelated_id).count() == 1
        assert db.session.get(CVE, "CVE-2025-1234") is not None


@pytest.mark.parametrize("history_kind", ["scan", "finding"])
def test_admin_cannot_delete_device_with_history(history_kind):
    app = make_test_app()
    with app.app_context():
        admin = db.session.get(User, 1)
        admin.is_admin = True
        device = Device(
            name="Historical inverter",
            vendor="Example Energy",
            model="INV-HISTORY",
        )
        other_device = Device(
            name="Other inverter",
            vendor="Example Energy",
            model="INV-OTHER",
        )
        cve = CVE(id="CVE-2025-5678")
        db.session.add_all([device, other_device, cve])
        db.session.flush()
        scan = Scan(
            device_id=device.id if history_kind == "scan" else other_device.id,
            status="completed",
            summary="Historical scan must remain.",
        )
        db.session.add(scan)
        db.session.flush()
        if history_kind == "finding":
            db.session.add(
                Finding(
                    scan_id=scan.id,
                    device_id=device.id,
                    cve_id=cve.id,
                    severity="HIGH",
                    summary="Historical finding must remain.",
                )
            )
        db.session.commit()
        device_id = device.id
        scan_id = scan.id

    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    token = csrf_token(client.get("/devices"))

    response = client.post(
        f"/devices/{device_id}/delete",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"cannot be deleted because it has scan or finding history" in response.data
    with app.app_context():
        assert db.session.get(Device, device_id) is not None
        assert db.session.get(Scan, scan_id) is not None
        assert Finding.query.filter_by(device_id=device_id).count() == (
            1 if history_kind == "finding" else 0
        )
        assert db.session.get(CVE, "CVE-2025-5678") is not None


def test_device_deletion_requires_admin_authentication_and_csrf():
    app = make_test_app()
    with app.app_context():
        device = Device(
            name="Protected inverter",
            vendor="Example Energy",
            model="INV-PROTECTED",
        )
        db.session.add(device)
        db.session.commit()
        device_id = device.id

    anonymous_client = app.test_client()
    assert anonymous_client.get(f"/devices/{device_id}/delete").status_code == 405
    anonymous_token = csrf_token(anonymous_client.get("/auth/login"))
    anonymous_post = anonymous_client.post(
        f"/devices/{device_id}/delete",
        data={"csrf_token": anonymous_token},
    )
    assert anonymous_post.status_code == 302
    assert "/auth/login" in anonymous_post.headers["Location"]

    teammate_client = app.test_client()
    with teammate_client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    token = csrf_token(teammate_client.get("/devices"))
    assert teammate_client.post(
        f"/devices/{device_id}/delete",
        data={"csrf_token": token},
    ).status_code == 403

    with app.app_context():
        admin = db.session.get(User, 1)
        admin.is_admin = True
        db.session.commit()
    admin_client = app.test_client()
    with admin_client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    assert admin_client.post(f"/devices/{device_id}/delete").status_code == 400
    with app.app_context():
        assert db.session.get(Device, device_id) is not None


def test_firmware_version_can_be_created_edited_and_displayed():
    app = make_test_app()
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    token = csrf_token(client.get("/devices"))

    created = client.post(
        "/api/devices",
        json={
            "name": "Versioned inverter",
            "vendor": "Example Energy",
            "model": "INV-2",
            "firmware_version": "2.4.1",
            "asset_tag": "INV-002",
            "site": "Solar farm",
        },
        headers={"X-CSRFToken": token},
    )
    assert created.status_code == 201
    device_id = created.json["id"]
    assert created.json["firmware_version"] == "2.4.1"
    assert created.json["firmware"] == "2.4.1"
    assert created.json["firmware_verification_status"] == "REPORTED"
    assert created.json["firmware_confidence"] == "low"
    assert created.json["firmware_evidence_source"] == "Operator entry"
    assert created.json["firmware_evidence_method"] == "Manual inventory entry"
    assert created.json["firmware_evidence_collected_at"] is not None
    assert created.json["asset_tag"] == "INV-002"
    assert created.json["site"] == "Solar farm"

    details = client.get(f"/devices/{device_id}")
    assert b"2.4.1" in details.data
    assert b"INV-002" in details.data
    assert b"Solar farm" in details.data
    assert b'name="name" required maxlength="150" value="Versioned inverter"' in details.data
    assert b'name="vendor" required maxlength="120" value="Example Energy"' in details.data
    assert b'name="model" required maxlength="120" value="INV-2"' in details.data
    inventory = client.get("/devices")
    assert b"Firmware version" in inventory.data
    assert b"2.4.1" in inventory.data

    forged_verification = client.patch(
        f"/api/devices/{device_id}",
        json={
            "firmware_version": "2.5.0",
            "firmware_verification_status": "VERIFIED",
        },
        headers={"X-CSRFToken": token},
    )
    assert forged_verification.status_code == 400

    updated = client.patch(
        f"/api/devices/{device_id}",
        json={
            "name": "Renamed inverter",
            "vendor": "Updated Energy",
            "model": "INV-2B",
            "firmware_version": "2.5.0",
            "firmware_evidence_source": "Authenticated device interface",
            "firmware_evidence_method": "Read from device status page",
            "firmware_evidence_note": "Read during authorized local inspection.",
            "asset_tag": "INV-002B",
            "site": "West field",
        },
        headers={"X-CSRFToken": token},
    )
    assert updated.status_code == 200
    assert updated.json["name"] == "Renamed inverter"
    assert updated.json["vendor"] == "Updated Energy"
    assert updated.json["model"] == "INV-2B"
    assert updated.json["firmware_version"] == "2.5.0"
    assert updated.json["firmware"] == "2.5.0"
    assert updated.json["firmware_verification_status"] == "REPORTED"
    assert updated.json["firmware_confidence"] == "low"
    assert updated.json["firmware_evidence_source"] == "Authenticated device interface"
    assert updated.json["firmware_evidence_method"] == "Read from device status page"
    assert updated.json["firmware_evidence_note"] == (
        "Read during authorized local inspection."
    )
    assert updated.json["asset_tag"] == "INV-002B"
    assert updated.json["site"] == "West field"
    assert b"2.5.0" in client.get(f"/devices/{device_id}").data
    assert b"REPORTED" in client.get(f"/devices/{device_id}").data
    assert b"not independently verify product firmware" in client.get(
        f"/devices/{device_id}"
    ).data

    invalid_update = client.patch(
        f"/api/devices/{device_id}",
        json={"asset_tag": "A" * 81},
        headers={"X-CSRFToken": token},
    )
    assert invalid_update.status_code == 400
    assert invalid_update.json["errors"]["asset_tag"]
    current = client.get(f"/api/devices/{device_id}")
    assert current.json["asset_tag"] == "INV-002B"

    unknown = client.post(
        "/api/devices",
        json={
            "name": "Unknown version inverter",
            "vendor": "Example Energy",
            "model": "INV-3",
        },
        headers={"X-CSRFToken": token},
    )
    assert unknown.status_code == 201
    assert unknown.json["firmware_version"] is None
    assert unknown.json["firmware"] == "unknown"
    assert unknown.json["firmware_verification_status"] == "UNKNOWN"
    assert unknown.json["firmware_confidence"] == "none"
    assert b"Unknown" in client.get(
        f"/devices/{unknown.json['id']}"
    ).data


def test_legacy_firmware_displays_and_can_be_edited_without_losing_history():
    app = make_test_app()
    with app.app_context():
        device = Device(
            name="Legacy inverter",
            vendor="Example Energy",
            model="INV-LEGACY",
            firmware="3.2.1",
            firmware_version=None,
            asset_tag="LEGACY-1",
            site="Old site",
        )
        cve = CVE(id="CVE-2025-4321", description="Test CVE")
        db.session.add_all([device, cve])
        db.session.flush()
        scan = Scan(device_id=device.id, status="completed", summary="Historical scan")
        db.session.add(scan)
        db.session.flush()
        finding = Finding(
            scan_id=scan.id,
            device_id=device.id,
            cve_id=cve.id,
            severity="unknown",
            summary="Historical finding",
            evidence="Test evidence",
        )
        db.session.add(finding)
        db.session.commit()
        device_id = device.id

    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    token = csrf_token(client.get("/devices"))

    inventory = client.get("/devices")
    details = client.get(f"/devices/{device_id}")
    assert b"3.2.1" in inventory.data
    assert b"3.2.1" in details.data
    assert b'value="3.2.1"' in details.data

    response = client.patch(
        f"/api/devices/{device_id}",
        json={
            "name": "Edited legacy inverter",
            "vendor": "Example Energy",
            "model": "INV-LEGACY",
            "firmware_version": "3.3.0",
            "asset_tag": "LEGACY-2",
            "site": "New site",
        },
        headers={"X-CSRFToken": token},
    )
    assert response.status_code == 200

    with app.app_context():
        assert Scan.query.filter_by(device_id=device_id).count() == 1
        assert Finding.query.filter_by(device_id=device_id).count() == 1

    deletion = client.delete(
        f"/api/devices/{device_id}",
        headers={"X-CSRFToken": token},
    )
    assert deletion.status_code == 405
    with app.app_context():
        assert Device.query.filter_by(id=device_id).count() == 1
        assert Scan.query.filter_by(device_id=device_id).count() == 1
        assert Finding.query.filter_by(device_id=device_id).count() == 1


def test_device_edit_requires_authentication_and_csrf():
    app = make_test_app()
    with app.app_context():
        device = Device(
            name="Protected inverter",
            vendor="Example Energy",
            model="INV-PROTECTED",
        )
        db.session.add(device)
        db.session.commit()
        device_id = device.id

    client = app.test_client()
    login_page = client.get("/auth/login")
    token = csrf_token(login_page)

    anonymous_edit = client.patch(
        f"/api/devices/{device_id}",
        json={"name": "Unauthorized change"},
        headers={"X-CSRFToken": token},
    )
    assert anonymous_edit.status_code == 302
    assert "/auth/login" in anonymous_edit.headers["Location"]

    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    missing_csrf = client.patch(
        f"/api/devices/{device_id}",
        json={"name": "No token change"},
    )
    assert missing_csrf.status_code == 400
    with app.app_context():
        assert db.session.get(Device, device_id).name == "Protected inverter"


def test_scan_records_nvd_cpe_version_match_without_claiming_device_verification(
    monkeypatch,
):
    app = make_test_app()
    with app.app_context():
        device = Device(
            name="Sunny Boy",
            vendor="SMA Solar Technology",
            model="Sunny Boy TL-21",
            firmware="1.5.0",
        )
        db.session.add(device)
        db.session.commit()
        device_id = device.id

    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda _client, keyword, page_size: {
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2025-5678",
                    "descriptions": [{
                        "lang": "en",
                        "value": "A firmware issue in a solar inverter.",
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
                                "versionEndIncluding": "2.0",
                            }],
                        }],
                    }],
                },
            }],
        },
    )
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True
    token = csrf_token(client.get("/scans/new"))

    response = client.post(
        "/api/scans",
        json={"device_id": device_id},
        headers={"X-CSRFToken": token},
    )

    assert response.status_code == 201
    with app.app_context():
        finding = Finding.query.one()
        assert finding.match_status == "potential"
        assert finding.matched_by == "nvd-cpe-product-potential"
        assert "1.5.0" in finding.evidence
        assert "not verified" in finding.evidence
        assert "cannot be confirmed or ruled out" in finding.evidence
    scan_page = client.get(f"/scans/{response.json['id']}")
    assert b"Potential CPE product match" in scan_page.data
