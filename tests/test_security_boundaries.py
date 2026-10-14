from __future__ import annotations

import re
from pathlib import Path

import pytest
from flask import abort

from app import create_app
from app.extensions import db
from app.models.cve import CVE
from app.models.device import Device
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.services.report_service import _spreadsheet_safe


def make_security_app():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.create_all()
        admin = User(username="admin", email="admin@example.com", is_admin=True)
        admin.set_password("team-password")
        teammate = User(
            username="teammate",
            email="teammate@example.com",
            is_admin=False,
        )
        teammate.set_password("team-password")
        device = Device(
            name="Team inverter",
            vendor="SMA Solar Technology",
            model="Sunny Boy TL-21",
            firmware="unknown",
        )
        db.session.add_all([admin, teammate, device])
        db.session.commit()
        app.test_admin_id = admin.id
        app.test_teammate_id = teammate.id
        app.test_device_id = device.id
    return app


def authenticate(client, user_id):
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True


def csrf_token(response):
    match = re.search(
        r'<meta name="csrf-token" content="([^"]+)"',
        response.get_data(as_text=True),
    )
    assert match is not None
    return match.group(1)


@pytest.mark.parametrize(
    "path",
    [
        "/dashboard",
        "/devices",
        "/devices/1",
        "/scans",
        "/scans/new",
        "/scans/1",
        "/cves",
        "/cves/CVE-2025-1234",
        "/reports",
        "/settings",
        "/admin/users",
        "/api/devices",
        "/api/devices/1",
        "/api/scans",
        "/api/cves",
        "/api/cves/CVE-2025-1234",
        "/api/dashboard",
        "/api/kev",
        "/api/reports/csv",
        "/api/reports/summary",
        "/api/admin/users",
    ],
)
def test_protected_pages_and_apis_redirect_anonymous_users(path):
    app = make_security_app()
    response = app.test_client().get(path)

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_invalid_login_does_not_authenticate_or_reveal_account_existence():
    app = make_security_app()
    client = app.test_client()
    login_page = client.get("/auth/login")
    token_match = re.search(
        r'name="csrf_token" value="([^"]+)"',
        login_page.get_data(as_text=True),
    )
    assert token_match is not None
    token = token_match.group(1)

    known_user_response = client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "incorrect",
            "csrf_token": token,
        },
    )
    unknown_user_response = client.post(
        "/auth/login",
        data={
            "username": "not-a-user",
            "password": "incorrect",
            "csrf_token": token,
        },
    )

    assert "Invalid username or password." in known_user_response.get_data(as_text=True)
    assert "Invalid username or password." in unknown_user_response.get_data(as_text=True)
    assert client.get("/dashboard").status_code == 302


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/api/devices",
            {
                "name": "No-CSRF device",
                "vendor": "Example Energy",
                "model": "INV-1",
            },
        ),
        ("/api/scans", {"device_id": 1}),
    ],
)
def test_state_changing_apis_reject_missing_csrf_token(
    monkeypatch,
    path,
    payload,
):
    app = make_security_app()
    client = app.test_client()
    authenticate(client, app.test_admin_id)
    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: pytest.fail("NVD must not be called"),
    )

    response = client.post(path, json=payload)

    assert response.status_code == 400
    with app.app_context():
        assert Device.query.count() == 1
        assert Scan.query.count() == 0


def test_scan_detail_escapes_untrusted_device_and_finding_text():
    app = make_security_app()
    payload = "<script>window.securityTest=1</script>"
    with app.app_context():
        device = db.session.get(Device, app.test_device_id)
        device.name = payload
        cve = CVE(id="CVE-2025-1234", description=payload)
        scan = Scan(
            device_id=device.id,
            status="completed",
            summary=payload,
        )
        db.session.add_all([cve, scan])
        db.session.flush()
        db.session.add(
            Finding(
                scan_id=scan.id,
                device_id=device.id,
                cve_id=cve.id,
                severity="unknown",
                summary=payload,
                evidence=payload,
            )
        )
        db.session.commit()
        scan_id = scan.id

    client = app.test_client()
    authenticate(client, app.test_admin_id)
    response = client.get(f"/scans/{scan_id}")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert payload not in html
    assert "&lt;script&gt;window.securityTest=1&lt;/script&gt;" in html


def test_cve_search_inserts_external_descriptions_as_text():
    script_path = Path(__file__).resolve().parents[1] / "app" / "static" / "js" / "cves.js"
    script = script_path.read_text(encoding="utf-8")

    assert "title.textContent = item.id" in script
    assert "description.textContent =" in script
    assert "severity.textContent =" in script
    assert "innerHTML" not in script


@pytest.mark.parametrize(
    "value",
    [
        "=1+1",
        "+SUM(A1:A2)",
        "-1+2",
        "@SUM(A1:A2)",
        "\t=1+1",
        "\r=1+1",
        " \t@SUM(A1:A2)",
    ],
)
def test_csv_formula_prefixes_are_neutralized(value):
    assert _spreadsheet_safe(value) == f"'{value}"


def test_csv_safe_values_are_preserved():
    assert _spreadsheet_safe("Sunny Boy inverter") == "Sunny Boy inverter"
    assert _spreadsheet_safe(None) is None
    assert _spreadsheet_safe(8.1) == 8.1


def test_second_authenticated_teammate_can_access_shared_device_scan_and_report(
    monkeypatch,
):
    app = make_security_app()
    actor_client = app.test_client()
    authenticate(actor_client, app.test_admin_id)

    device_token = csrf_token(actor_client.get("/devices"))
    create_device_response = actor_client.post(
        "/api/devices",
        json={
            "name": "Shared team inverter",
            "vendor": "SMA Solar Technology",
            "model": "Sunny Boy TL-21",
            "firmware": "unknown",
        },
        headers={"X-CSRFToken": device_token},
    )
    assert create_device_response.status_code == 201
    device_id = create_device_response.json["id"]

    monkeypatch.setattr(
        "app.services.scan_service.NVDClient.fetch_cves",
        lambda *_args, **_kwargs: {
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2025-1234",
                    "descriptions": [{
                        "lang": "en",
                        "value": "SMA Solar Technology Sunny Boy TL-21 issue",
                    }],
                },
            }],
        },
    )
    scan_token = csrf_token(actor_client.get("/scans/new"))
    scan_response = actor_client.post(
        "/api/scans",
        json={"device_id": device_id},
        headers={"X-CSRFToken": scan_token},
    )
    assert scan_response.status_code == 201
    scan_id = scan_response.json["id"]

    teammate_client = app.test_client()
    authenticate(teammate_client, app.test_teammate_id)

    assert teammate_client.get(f"/devices/{device_id}").status_code == 200
    assert teammate_client.get(f"/api/devices/{device_id}").status_code == 200
    assert teammate_client.get(f"/scans/{scan_id}").status_code == 200
    report = teammate_client.get(f"/api/reports/csv?scan_id={scan_id}")
    assert report.status_code == 200
    assert "CVE-2025-1234" in report.get_data(as_text=True)


def test_missing_scan_detail_is_not_found_and_error_page_hides_exception():
    app = make_security_app()
    client = app.test_client()
    authenticate(client, app.test_admin_id)

    @app.get("/_test/unexpected-error")
    def unexpected_error():
        abort(500, description="private internal detail")

    app.config["PROPAGATE_EXCEPTIONS"] = False
    assert client.get("/scans/999").status_code == 404
    response = client.get("/_test/unexpected-error")

    assert response.status_code == 500
    assert b"An unexpected server error occurred." in response.data
    assert b"private internal detail" not in response.data
