from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from werkzeug.exceptions import HTTPException

from app import create_app
from app.extensions import db
from app.models.cve import CVE
from app.models.device import Device
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.telemetry import TelemetryReading
from app.models.user import User
from app.services.component_scan_service import run_component_scan
from app.services.dashboard_service import build_vulnerability_summary
from app.services.telemetry_service import (
    TelemetryDeviceError,
    TelemetryValidationError,
    ingest_telemetry_message,
    validate_telemetry_payload,
)
from app.services.telemetry_mqtt import run_telemetry_subscriber


MQTT_TOPIC = (
    "energy-iot-cve-monitor/477780562303197185/SolarGuard-01/telemetry"
)


def make_app(csrf_enabled=False):
    app = create_app(
        {
            "TESTING": True,
            "WTF_CSRF_ENABLED": csrf_enabled,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        }
    )
    with app.app_context():
        db.create_all()
        device = Device(
            name="SolarGuard-01",
            vendor="SMA Solar Technology",
            model="Sunny Boy TL-21",
            firmware="unknown",
            status="active",
        )
        user = User(
            username="admin",
            email="telemetry-admin@example.com",
            is_admin=True,
        )
        user.set_password("telemetry-test-password")
        db.session.add_all([device, user])
        db.session.commit()
        app.telemetry_device_id = device.id
        app.telemetry_user_id = user.id
    return app


def payload(**overrides):
    result = {
        "message_id": "boot1234-1",
        "device_id": "SolarGuard-01",
        "manufacturer": "SMA Solar Technology",
        "model": "Sunny Boy TL-21",
        "voltage": 230.0,
        "current": 4.0,
        "power": 920.0,
        "timestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "telemetry_status": "SIMULATED",
        "chip_model": "ESP32-D0WD-V3",
        "chip_revision": 3,
        "arduino_core_version": "3.3.6",
        "esp_idf_version": "v5.5.2",
    }
    result.update(overrides)
    return result


def encoded_payload(**overrides):
    return json.dumps(payload(**overrides)).encode("utf-8")


def add_reading(device_id, **overrides):
    now = datetime.now(UTC).replace(tzinfo=None)
    values = {
        "device_id": device_id,
        "source_message_id": "boot1234-1",
        "voltage": 230.0,
        "current": 4.0,
        "power": 920.0,
        "timestamp": now,
        "received_at": now,
        "telemetry_status": "SIMULATED",
        "chip_model": "ESP32-D0WD-V3",
        "chip_revision": 3,
        "arduino_core_version": "3.3.6",
        "esp_idf_version": "v5.5.2",
    }
    values.update(overrides)
    reading = TelemetryReading(**values)
    db.session.add(reading)
    db.session.commit()
    return reading


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"voltage": -1}, "voltage is outside"),
        ({"current": True}, "current must be numeric"),
        ({"power": 1000}, "power does not agree"),
        ({"telemetry_status": "REAL"}, "labelled SIMULATED"),
        ({"timestamp": "2026-01-01T00:00:00"}, "include a timezone"),
        ({"chip_revision": True}, "chip_revision must be an integer"),
        ({"device_id": "2"}, "Unknown telemetry device_id"),
    ],
)
def test_invalid_telemetry_payloads_are_rejected(updates, message):
    app = make_app()
    with app.app_context():
        with pytest.raises(TelemetryValidationError, match=message):
            validate_telemetry_payload(
                encoded_payload(**updates),
                datetime.now(UTC),
            )


def test_oversized_and_malformed_messages_are_rejected():
    app = make_app()
    with app.app_context():
        with pytest.raises(TelemetryValidationError, match="too large"):
            validate_telemetry_payload(
                b" " * 2049,
                datetime.now(UTC),
            )
        with pytest.raises(TelemetryValidationError, match="valid JSON"):
            validate_telemetry_payload("{", datetime.now(UTC))


def test_ingestion_checks_topic_device_and_deduplicates():
    app = make_app()
    with app.app_context():
        with pytest.raises(TelemetryValidationError, match="Unexpected MQTT topic"):
            ingest_telemetry_message("wrong/topic", encoded_payload())

        assert ingest_telemetry_message(MQTT_TOPIC, encoded_payload()) is True
        assert ingest_telemetry_message(MQTT_TOPIC, encoded_payload()) is False
        assert TelemetryReading.query.count() == 1


def test_unknown_and_archived_devices_cannot_ingest_messages():
    app = make_app()
    with app.app_context():
        Device.query.filter_by(name="SolarGuard-01").delete()
        db.session.commit()
        with pytest.raises(TelemetryDeviceError, match="not registered"):
            ingest_telemetry_message(MQTT_TOPIC, encoded_payload())

        device = Device(
            name="SolarGuard-01",
            vendor="SMA Solar Technology",
            model="Sunny Boy TL-21",
            firmware="unknown",
            status="archived",
        )
        db.session.add(device)
        db.session.commit()
        with pytest.raises(TelemetryDeviceError, match="Archived"):
            ingest_telemetry_message(MQTT_TOPIC, encoded_payload())


def test_authenticated_telemetry_api_reports_waiting_stale_and_history():
    app = make_app()
    client = app.test_client()
    response = client.get("/api/dashboard/telemetry")
    assert response.status_code == 302
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True

    response = client.get("/api/dashboard/telemetry")
    assert response.status_code == 200
    assert response.json["state"] == "waiting"

    with app.app_context():
        reading = add_reading(app.telemetry_device_id)
        response = client.get("/api/dashboard/telemetry")
        assert response.status_code == 200
        assert response.json["state"] == "connected"
        reading.received_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(
            seconds=60
        )
        db.session.commit()

    response = client.get("/api/dashboard/telemetry")
    assert response.status_code == 200
    assert response.json["state"] == "stale"
    assert response.json["latest"]["telemetry_status"] == "SIMULATED"
    assert response.json["runtime"]["esp_idf_version"] == "v5.5.2"
    assert response.json["firmware_inventory_complete"] is False
    assert len(response.json["history"]) == 1
    with app.app_context():
        Device.query.filter_by(name="SolarGuard-01").update(
            {"status": "archived"}
        )
        db.session.commit()
    response = client.get("/api/dashboard/telemetry")
    assert response.status_code == 200
    assert response.json["state"] == "archived"
    assert len(response.json["history"]) == 1


def test_authenticated_telemetry_api_reports_archived_device_without_history():
    app = make_app()
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True

    with app.app_context():
        device = db.session.get(Device, app.telemetry_device_id)
        device.status = "archived"
        db.session.commit()

    response = client.get("/api/dashboard/telemetry")

    assert response.status_code == 200
    assert response.json["state"] == "archived"
    assert response.json["history"] == []
    assert "archived" in response.json["message"].lower()


def test_device_with_telemetry_history_cannot_be_deleted():
    app = make_app()
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True
    with app.app_context():
        add_reading(app.telemetry_device_id)

    response = client.post(
        f"/devices/{app.telemetry_device_id}/delete",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"stored telemetry history" in response.data
    with app.app_context():
        assert db.session.get(Device, app.telemetry_device_id) is not None
        assert TelemetryReading.query.filter_by(
            device_id=app.telemetry_device_id
        ).count() == 1


def cpe_candidate(name, title):
    return {
        "cpe": {
            "cpeName": name,
            "titles": [{"title": title, "lang": "en"}],
        }
    }


def cve_entry(cve_id, start, end):
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": "ESP-IDF vulnerability."}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 8.8,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    }
                ]
            },
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": (
                                        "cpe:2.3:a:espressif:esp_idf:*:*:*:*:*:*:*:*"
                                    ),
                                    "versionStartIncluding": start,
                                    "versionEndExcluding": end,
                                }
                            ],
                        }
                    ]
                }
            ],
        }
    }


class FakeComponentNVD:
    def __init__(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities
        self.queries = []

    def fetch_cpe(self, vendor, product, results_per_page, start_index=0):
        self.queries.append((vendor, product, results_per_page, start_index))
        if product == "ESP-IDF":
            return {
                "totalResults": 1,
                "products": [
                    cpe_candidate(
                        "cpe:2.3:a:espressif:esp_idf:*:*:*:*:*:*:*:*",
                        "Espressif ESP-IDF",
                    )
                ]
            }
        return {"totalResults": 0, "products": []}

    def fetch_cves_by_cpe(self, cpe_name, page_size, start_index):
        return {
            "totalResults": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
        }


def test_component_scan_uses_exact_cpe_version_ranges_and_preserves_metadata():
    app = make_app()
    with app.app_context():
        add_reading(app.telemetry_device_id)
        nvd = FakeComponentNVD(
            [cve_entry("CVE-2025-1234", "5.0", "6.0")]
        )
        scan = run_component_scan(app.telemetry_device_id, nvd)

        assert scan.status == "completed"
        assert scan.scan_type == "components"
        finding = scan.findings[0]
        assert finding.match_status == "affected"
        assert finding.component_name == "ESP-IDF"
        assert finding.component_version == "v5.5.2"
        assert finding.confidence == "high"
        assert finding.cve.cvss_vector.startswith("CVSS:3.1/")
        assert finding.cve.source == "nvd"
        assert nvd.queries[0][3] == 0
        assert "Runtime component identity" in finding.evidence
        assert "incomplete" in scan.summary.lower()
        summary = build_vulnerability_summary()
        assert summary["severity"]["high"] == {"evaluated": 1, "potential": 0}


def test_component_scan_saves_not_applicable_and_unknown_mapping_results():
    app = make_app()
    with app.app_context():
        add_reading(app.telemetry_device_id)
        nvd = FakeComponentNVD(
            [cve_entry("CVE-2025-4321", "6.0", "7.0")]
        )
        scan = run_component_scan(app.telemetry_device_id, nvd)

        assert scan.status == "completed"
        assert scan.findings[0].match_status == "not_applicable"
        assert scan.findings[0].matched_by == "nvd-cpe-not-applicable"
        assert "Arduino ESP32 core" in scan.summary
        assert len(nvd.queries) == 2
        summary = build_vulnerability_summary()
        assert summary["severity"]["high"] == {"evaluated": 0, "potential": 0}


def test_component_scan_records_missing_cpe_configuration_as_potential():
    app = make_app()
    with app.app_context():
        add_reading(app.telemetry_device_id)
        cve_without_config = {
            "cve": {
                "id": "CVE-2025-9876",
                "descriptions": [
                    {"lang": "en", "value": "A possible ESP-IDF issue."}
                ],
            }
        }
        scan = run_component_scan(
            app.telemetry_device_id,
            FakeComponentNVD([cve_without_config]),
        )

        assert scan.status == "completed"
        assert scan.findings[0].match_status == "potential"
        assert scan.findings[0].confidence == "low"
        assert "potential match only" in scan.findings[0].evidence


def test_admin_only_component_scan_form_and_regular_scan_separation(monkeypatch):
    app = make_app()
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True

    response = client.get("/scans/new")
    assert response.status_code == 200
    assert "Scan reported ESP32 components" in response.get_data(as_text=True)

    response = client.post("/scans/components")
    assert response.status_code == 409
    assert "No ESP32 runtime inventory" in response.get_data(as_text=True)

    with app.app_context():
        add_reading(app.telemetry_device_id)

    monkeypatch.setattr(
        "app.services.component_scan_service.NVDClient.fetch_cpe",
        lambda *_args, **_kwargs: {"totalResults": 0, "products": []},
    )
    monkeypatch.setattr(
        "app.services.component_scan_service.NVDClient.fetch_cves_by_cpe",
        lambda *_args, **_kwargs: {"totalResults": 0, "vulnerabilities": []},
    )
    response = client.post("/scans/components")
    assert response.status_code == 302
    with app.app_context():
        assert Scan.query.count() == 1


def test_component_scan_rejects_non_solar_device_and_archived_device():
    app = make_app()
    with app.app_context():
        other = Device(
            name="Other device",
            vendor="Other",
            model="Other model",
            firmware="unknown",
        )
        db.session.add(other)
        db.session.commit()
        with pytest.raises(HTTPException) as error:
            run_component_scan(other.id, FakeComponentNVD([]))
        assert error.value.code == 400

        device = db.session.get(Device, app.telemetry_device_id)
        device.status = "archived"
        db.session.commit()
        with pytest.raises(HTTPException) as error:
            run_component_scan(device.id, FakeComponentNVD([]))
        assert error.value.code == 409


def test_setup_cli_is_idempotent_and_does_not_modify_archived_devices():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        }
    )
    with app.app_context():
        db.create_all()
        archived = [
            Device(
                id=device_id,
                name=f"Archived device {device_id}",
                vendor="SMA Solar Technology",
                model="Sunny Boy TL-21",
                firmware="unknown",
                status="archived",
            )
            for device_id in (1, 2)
        ]
        user = User(
            username="history-admin",
            email="history-admin@example.com",
            is_admin=True,
        )
        user.set_password("unchanged-test-password")
        cve = CVE(id="CVE-2025-1122", description="Historical CVE")
        scan = Scan(
            device=archived[0],
            status="completed",
            summary="Historical scan",
        )
        finding = Finding(
            scan=scan,
            device=archived[0],
            cve=cve,
            severity="HIGH",
            summary="Historical finding",
            evidence="Original evidence",
        )
        db.session.add_all([*archived, user, cve, scan, finding])
        db.session.commit()
        user_id = user.id
        finding_id = finding.id
        password_hash = user.password_hash

    runner = app.test_cli_runner()
    first = runner.invoke(args=["setup-wokwi-device"])
    second = runner.invoke(args=["setup-wokwi-device"])
    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    with app.app_context():
        assert Device.query.filter_by(name="SolarGuard-01").count() == 1
        assert [
            (device.id, device.status)
            for device in Device.query.order_by(Device.id).all()
        ][:2] == [(1, "archived"), (2, "archived")]
        assert Device.query.count() == 3
        assert Scan.query.count() == 1
        assert Finding.query.count() == 1
        assert db.session.get(CVE, "CVE-2025-1122").description == "Historical CVE"
        assert db.session.get(Finding, finding_id).evidence == "Original evidence"
        preserved_user = db.session.get(User, user_id)
        assert preserved_user.password_hash == password_hash


def test_non_admin_cannot_start_component_scan():
    app = make_app()
    with app.app_context():
        user = User(
            username="viewer",
            email="telemetry-viewer@example.com",
            is_admin=False,
        )
        user.set_password("viewer-test-password")
        db.session.add(user)
        db.session.commit()
        viewer_id = user.id

    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(viewer_id)
        session["_fresh"] = True
    response = client.post("/scans/components")
    assert response.status_code == 403


def test_component_scan_post_requires_csrf_token():
    app = make_app(csrf_enabled=True)
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True

    response = client.post("/scans/components")
    assert response.status_code == 400


def test_regular_sma_scan_is_blocked_for_simulated_asset():
    app = make_app()
    with app.app_context():
        with pytest.raises(HTTPException) as error:
            from app.services.scan_service import run_scan_for_device

            run_scan_for_device(app.telemetry_device_id)
        assert error.value.code == 409


def test_mqtt_worker_stores_messages_and_resubscribes_after_reconnect(
    monkeypatch,
):
    app = make_app()

    class FakeMQTTClient:
        def __init__(self, *_args, **_kwargs):
            self.subscriptions = []

        def username_pw_set(self, *_args, **_kwargs):
            pytest.fail("Unexpected MQTT credentials in this test.")

        def tls_set(self):
            pytest.fail("Unexpected MQTT TLS in this test.")

        def connect_async(self, host, port, keepalive):
            assert host == app.config["TELEMETRY_MQTT_BROKER_HOST"]
            assert port == app.config["TELEMETRY_MQTT_BROKER_PORT"]
            assert keepalive == 60

        def subscribe(self, topic, qos):
            self.subscriptions.append((topic, qos))

        def loop_forever(self, retry_first_connection):
            assert retry_first_connection is True
            reason_code = SimpleNamespace(is_failure=False)
            for _ in range(2):
                self.on_connect(self, None, None, reason_code, None)
            message = SimpleNamespace(
                topic=MQTT_TOPIC,
                payload=encoded_payload(),
            )
            self.on_message(self, None, message)
            self.on_message(self, None, message)

    fake_client = FakeMQTTClient()
    monkeypatch.setattr(
        "app.services.telemetry_mqtt.mqtt.Client",
        lambda *_args, **_kwargs: fake_client,
    )

    run_telemetry_subscriber(app)

    assert fake_client.subscriptions == [(MQTT_TOPIC, 0), (MQTT_TOPIC, 0)]
    with app.app_context():
        assert TelemetryReading.query.count() == 1
