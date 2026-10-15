from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import OperationalError
from werkzeug.exceptions import HTTPException

from app import create_app
from app.extensions import db
from app.models.alert import SecurityAlert
from app.models.cve import CVE
from app.models.device import Device
from app.models.device_component import DeviceComponent
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.telemetry import TelemetryReading
from app.models.user import User
from app.services.component_scan_service import run_component_scan
from app.services.dashboard_service import build_vulnerability_summary
from app.services.device_bootstrap import (
    ensure_sma_firmware_reference_device,
    ensure_solar_guard_components,
)
from app.services.telemetry_service import (
    TelemetryDeviceError,
    TelemetryValidationError,
    ingest_telemetry_message,
    validate_telemetry_payload,
)
from app.services.telemetry_mqtt import run_telemetry_subscriber
from app.services.telemetry_mqtt import process_telemetry_message
from app.services.telemetry_mqtt import _process_is_running, _single_worker_lock


MQTT_TOPIC = (
    "energy-iot-cve-monitor/477868883321291777/SolarGuard-01/telemetry"
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
            telemetry_device_id="SolarGuard-01",
            vendor=app.config["TELEMETRY_DEVICE_VENDOR"],
            model=app.config["TELEMETRY_DEVICE_MODEL"],
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
        "schema_version": 1,
        "message_type": "telemetry_with_runtime_info",
        "message_id": "boot1234-1",
        "device_id": "SolarGuard-01",
        "source": "wokwi_simulation",
        "manufacturer": "Espressif",
        "model": "ESP32 development board (Wokwi esp32dev target)",
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
        "payload_source": "wokwi_simulation",
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
        ({"schema_version": True}, "schema_version must be integer 1"),
        ({"schema_version": "1"}, "schema_version must be integer 1"),
        ({"schema_version": None}, "schema_version must be integer 1"),
        ({"message_type": "runtime_info"}, "message_type is not supported"),
        ({"source": "physical_device"}, "identify the simulation source"),
        ({"telemetry_status": "REAL"}, "labelled SIMULATED"),
        ({"timestamp": "2026-01-01T00:00:00"}, "include a timezone"),
        ({"timestamp_source": "fabricated_clock"}, "timestamp_source is not supported"),
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


def test_checked_in_wokwi_identity_matches_backend_configuration():
    app = make_app()
    sketch = (
        Path(__file__).resolve().parents[1] / "wowki" / "sketch.ino"
    ).read_text(encoding="utf-8")

    manufacturer = re.search(
        r'static const char \*MANUFACTURER = "([^"]+)";',
        sketch,
    )
    model = re.search(
        r'static const char \*ASSET_MODEL =\s*"([^"]+)";',
        sketch,
    )

    assert manufacturer is not None
    assert model is not None
    assert manufacturer.group(1) == app.config["TELEMETRY_DEVICE_VENDOR"]
    assert model.group(1) == app.config["TELEMETRY_DEVICE_MODEL"]
    assert '"{\\"schema_version\\":1,"' in sketch
    assert '"\\"arduino_core_version\\":\\"%u.%u.%u\\","' in sketch
    assert "esp_get_idf_version()" in sketch


def test_legacy_telemetry_without_message_type_remains_compatible():
    app = make_app()
    legacy_payload = payload()
    legacy_payload.pop("message_type")

    with app.app_context():
        validated = validate_telemetry_payload(
            json.dumps(legacy_payload),
            datetime.now(UTC),
        )

    assert validated["device_id"] == "SolarGuard-01"
    assert validated["telemetry_status"] == "SIMULATED"


def test_uptime_fallback_uses_server_receipt_time_without_claiming_device_utc():
    app = make_app()
    received_at = datetime.now(UTC)
    fallback = payload(
        timestamp=None,
        timestamp_source="uptime",
        uptime_ms=12345,
    )

    with app.app_context():
        validated = validate_telemetry_payload(
            json.dumps(fallback),
            received_at,
        )

    assert validated["timestamp_source"] == "server_received"
    assert validated["source_uptime_ms"] == 12345
    assert validated["timestamp"] == received_at.replace(tzinfo=None)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        (
            {"timestamp": None, "timestamp_source": "uptime"},
            "uptime_ms is required",
        ),
        (
            {
                "timestamp": None,
                "timestamp_source": "uptime",
                "uptime_ms": True,
            },
            "uptime_ms must be an unsigned",
        ),
        (
            {
                "timestamp_source": "uptime",
                "uptime_ms": 12345,
            },
            "timestamp must be null",
        ),
    ],
)
def test_uptime_fallback_rejects_missing_or_invalid_evidence(updates, message):
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
        assert app.config["TELEMETRY_MQTT_BROKER_HOST"] == "test.mosquitto.org"
        assert app.config["TELEMETRY_MQTT_TOPIC"] == MQTT_TOPIC
        assert app.config["TELEMETRY_MQTT_ACK_TOPIC"] == f"{MQTT_TOPIC}/ack"
        with pytest.raises(TelemetryValidationError, match="Unexpected MQTT topic"):
            ingest_telemetry_message("wrong/topic", encoded_payload())

        assert ingest_telemetry_message(MQTT_TOPIC, encoded_payload()) is True
        assert ingest_telemetry_message(MQTT_TOPIC, encoded_payload()) is False
        assert TelemetryReading.query.count() == 1
        assert TelemetryReading.query.one().ingest_source == "mqtt"
        assert TelemetryReading.query.one().payload_source == "wokwi_simulation"


def test_uptime_fallback_persists_provenance_and_api_message_id():
    app = make_app()
    message = payload(
        message_id="boot1234-uptime",
        timestamp=None,
        timestamp_source="uptime",
        uptime_ms=45678,
    )

    class FakeMQTTClient:
        def __init__(self):
            self.published = []

        def publish(self, topic, payload, qos, retain):
            acknowledgement = json.loads(payload)
            self.published.append((topic, acknowledgement, qos, retain))
            return SimpleNamespace(rc=0)

    mqtt_client = FakeMQTTClient()
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True

    with app.app_context():
        acknowledgement = process_telemetry_message(
            mqtt_client,
            MQTT_TOPIC,
            json.dumps(message).encode("utf-8"),
        )
        assert acknowledgement["outcome"] == "stored"
        assert acknowledgement["message_id"] == "boot1234-uptime"
        assert mqtt_client.published == [
            (f"{MQTT_TOPIC}/ack", acknowledgement, 1, False)
        ]
        reading = TelemetryReading.query.one()
        assert reading.timestamp_source == "server_received"
        assert reading.source_uptime_ms == 45678
        assert reading.timestamp == reading.received_at

    response = client.get("/api/dashboard/telemetry")

    assert response.status_code == 200
    assert response.json["latest"]["message_id"] == "boot1234-uptime"
    assert response.json["latest"]["timestamp_source"] == "server_received"
    assert response.json["latest"]["source_uptime_ms"] == 45678


def test_demo_threshold_alert_is_persisted_and_repeated_events_are_grouped():
    app = make_app()
    with app.app_context():
        first_payload = payload(
            message_id="boot1234-1",
            voltage=301.0,
            current=1.0,
            power=301.0,
        )
        assert ingest_telemetry_message(
            MQTT_TOPIC,
            json.dumps(first_payload),
        ) is True

        alert = SecurityAlert.query.one()
        assert alert.alert_type == "telemetry"
        assert alert.source == "telemetry"
        assert alert.severity == "medium"
        assert "301 V" in alert.summary
        assert "280 V" in alert.summary
        assert "DEMONSTRATION RULE" in alert.summary
        assert "not evidence of a physical equipment fault" in alert.summary

        repeated_payload = payload(
            message_id="boot1234-2",
            voltage=302.0,
            current=1.0,
            power=302.0,
        )
        assert ingest_telemetry_message(
            MQTT_TOPIC,
            json.dumps(repeated_payload),
        ) is True
        assert SecurityAlert.query.count() == 1
        assert "302 V" in SecurityAlert.query.one().summary
        assert TelemetryReading.query.count() == 2


def test_normal_demo_telemetry_does_not_create_anomaly_alerts():
    app = make_app()
    with app.app_context():
        assert ingest_telemetry_message(MQTT_TOPIC, encoded_payload()) is True
        assert SecurityAlert.query.count() == 0


def test_worker_acknowledges_committed_and_duplicate_messages(caplog):
    app = make_app()

    class FakeMQTTClient:
        def __init__(self):
            self.published = []

        def publish(self, topic, payload, qos, retain):
            self.published.append((topic, json.loads(payload), qos, retain))
            return SimpleNamespace(rc=0)

    client = FakeMQTTClient()
    caplog.set_level("DEBUG", logger="app.services.telemetry_mqtt")
    with app.app_context():
        first = process_telemetry_message(client, MQTT_TOPIC, encoded_payload())
        second = process_telemetry_message(client, MQTT_TOPIC, encoded_payload())

        assert first["outcome"] == "stored"
        assert first["message_id"] == "boot1234-1"
        assert first["device_id"] == "SolarGuard-01"
        assert "committed" in first["reason"]
        assert first["duplicate"] is False
        reading = TelemetryReading.query.one()
        assert reading.device.last_seen == reading.received_at
        assert second["outcome"] == "stored"
        assert second["duplicate"] is True
        assert "duplicate delivery ignored" in second["reason"]
        assert TelemetryReading.query.count() == 1
        assert [
            (item[0], item[2], item[3]) for item in client.published
        ] == [
            (f"{MQTT_TOPIC}/ack", 1, False),
            (f"{MQTT_TOPIC}/ack", 1, False),
        ]
        assert sum(
            "Telemetry acknowledgement queued" in record.message
            for record in caplog.records
        ) == 2
        assert not any(
            "Could not publish telemetry acknowledgement" in record.message
            for record in caplog.records
        )


def test_worker_rejects_invalid_message_with_correlated_acknowledgement(caplog):
    app = make_app()

    class FakeMQTTClient:
        def __init__(self):
            self.published = []

        def publish(self, topic, payload, qos, retain):
            self.published.append((topic, json.loads(payload), qos, retain))
            return SimpleNamespace(rc=0)

    client = FakeMQTTClient()
    caplog.set_level("WARNING", logger="app.services.telemetry_mqtt")
    with app.app_context():
        acknowledgement = process_telemetry_message(
            client,
            MQTT_TOPIC,
            encoded_payload(power=10.0),
        )

        assert acknowledgement["outcome"] == "rejected"
        assert acknowledgement["message_id"] == "boot1234-1"
        assert acknowledgement["device_id"] == "SolarGuard-01"
        assert acknowledgement["worker_id"].startswith("telemetry-worker-")
        assert "power does not agree" in acknowledgement["reason"]
        assert TelemetryReading.query.count() == 0
        assert len(client.published) == 1
        assert any(
            "power does not agree" in record.message
            and "payload_keys=" in record.message
            and f"topic={MQTT_TOPIC!r}" in record.message
            for record in caplog.records
        )


@pytest.mark.parametrize(
    "schema_version",
    ["missing", "string"],
)
def test_worker_rejects_missing_or_string_schema_version_with_reason(
    caplog,
    schema_version,
):
    app = make_app()

    class FakeMQTTClient:
        def __init__(self):
            self.published = []

        def publish(self, topic, payload, qos, retain):
            self.published.append((topic, json.loads(payload), qos, retain))
            return SimpleNamespace(rc=0)

    message = payload()
    if schema_version == "missing":
        message.pop("schema_version")
    else:
        message["schema_version"] = "1"
    raw = json.dumps(message).encode("utf-8")
    client = FakeMQTTClient()
    caplog.set_level("WARNING", logger="app.services.telemetry_mqtt")

    with app.app_context():
        acknowledgement = process_telemetry_message(client, MQTT_TOPIC, raw)

        assert acknowledgement["outcome"] == "rejected"
        assert acknowledgement["reason"] == "schema_version must be integer 1."
        assert acknowledgement["message_id"] == "boot1234-1"
        assert acknowledgement["worker_id"].startswith("telemetry-worker-")
        assert client.published[0][1] == acknowledgement
        assert TelemetryReading.query.count() == 0
        rejection_log = next(
            record.message
            for record in caplog.records
            if "Rejected MQTT telemetry" in record.message
        )
        assert "schema_version" in rejection_log
        assert "reason=schema_version must be integer 1." in rejection_log
        assert "power=920.0" not in rejection_log


def test_telemetry_worker_single_instance_lock(tmp_path):
    app = make_app()
    app.instance_path = str(tmp_path)

    with _single_worker_lock(app):
        with pytest.raises(
            RuntimeError,
            match=f"already holds.*owner PID {os.getpid()} is still running",
        ):
            with _single_worker_lock(app):
                pytest.fail("A second worker lock unexpectedly succeeded.")

    pid_file = Path(tmp_path) / "telemetry-worker.pid"
    assert pid_file.read_text(encoding="ascii").strip() == str(os.getpid())
    pid_file.write_text("2147483647\n", encoding="ascii")
    assert _process_is_running(2147483647) is False
    assert _process_is_running(os.getpid()) is True
    with _single_worker_lock(app):
        assert pid_file.read_text(encoding="ascii").strip() == str(os.getpid())


def test_hosted_sma_identity_is_rejected_without_persisting(caplog):
    app = make_app()

    class FakeMQTTClient:
        def __init__(self):
            self.published = []

        def publish(self, topic, payload, qos, retain):
            self.published.append((topic, json.loads(payload), qos, retain))
            return SimpleNamespace(rc=0)

    client = FakeMQTTClient()
    caplog.set_level("WARNING", logger="app.services.telemetry_mqtt")
    with app.app_context():
        acknowledgement = process_telemetry_message(
            client,
            MQTT_TOPIC,
            encoded_payload(
                manufacturer="SMA Solar Technology",
                model="Sunny Boy TL-21",
            ),
        )

        assert acknowledgement["outcome"] == "rejected"
        assert acknowledgement["message_id"] == "boot1234-1"
        assert acknowledgement["device_id"] == "SolarGuard-01"
        assert acknowledgement["reason"] == (
            "Simulated asset metadata did not match."
        )
        assert TelemetryReading.query.count() == 0
        assert client.published[0][1] == acknowledgement
        assert any(
            "Simulated asset metadata did not match." in record.message
            for record in caplog.records
        )


def test_worker_rejects_wrong_device_id_without_persisting():
    app = make_app()

    class FakeMQTTClient:
        def __init__(self):
            self.published = []

        def publish(self, topic, payload, qos, retain):
            self.published.append((topic, json.loads(payload), qos, retain))
            return SimpleNamespace(rc=0)

    client = FakeMQTTClient()
    with app.app_context():
        acknowledgement = process_telemetry_message(
            client,
            MQTT_TOPIC,
            encoded_payload(device_id="Other-Device"),
        )

        assert acknowledgement["outcome"] == "rejected"
        assert acknowledgement["device_id"] == "Other-Device"
        assert "Unknown telemetry device_id" in acknowledgement["reason"]
        assert TelemetryReading.query.count() == 0
        assert client.published[0][0] == f"{MQTT_TOPIC}/ack"


def test_worker_requests_retry_after_database_commit_failure(monkeypatch):
    app = make_app()

    class FakeMQTTClient:
        def __init__(self):
            self.published = []

        def publish(self, topic, payload, qos, retain):
            self.published.append((topic, json.loads(payload), qos, retain))
            return SimpleNamespace(rc=0)

    original_commit = db.session.commit

    def fail_commit():
        raise OperationalError(
            "insert telemetry",
            {},
            RuntimeError("database unavailable"),
        )

    client = FakeMQTTClient()
    with app.app_context():
        monkeypatch.setattr(db.session, "commit", fail_commit)
        acknowledgement = process_telemetry_message(
            client,
            MQTT_TOPIC,
            encoded_payload(voltage=301.0, current=1.0, power=301.0),
        )

        assert acknowledgement["outcome"] == "error"
        assert acknowledgement["message_id"] == "boot1234-1"
        assert "retry this message" in acknowledgement["reason"]
        monkeypatch.setattr(db.session, "commit", original_commit)
        assert TelemetryReading.query.count() == 0
        assert SecurityAlert.query.count() == 0


def test_worker_rejects_malformed_json_without_inventing_correlation_id():
    app = make_app()

    class FakeMQTTClient:
        def publish(self, topic, payload, qos, retain):
            self.ack = json.loads(payload)
            self.delivery = (topic, qos, retain)
            return SimpleNamespace(rc=0)

    client = FakeMQTTClient()
    with app.app_context():
        acknowledgement = process_telemetry_message(client, MQTT_TOPIC, b"{")

        assert acknowledgement["outcome"] == "rejected"
        assert acknowledgement["message_id"] is None
        assert acknowledgement["device_id"] is None
        assert client.delivery == (f"{MQTT_TOPIC}/ack", 1, False)


def test_wokwi_project_and_sketch_use_the_configured_telemetry_topic():
    repository = Path(__file__).resolve().parents[1]
    sketch = (repository / "wowki" / "sketch.ino").read_text(encoding="utf-8")
    telemetry_mqtt_source = (
        repository / "app" / "services" / "telemetry_mqtt.py"
    ).read_text(encoding="utf-8")
    project = (repository / "wowki" / "wokwi-project.txt").read_text(
        encoding="utf-8"
    )

    assert MQTT_TOPIC in sketch
    assert "telemetry_with_runtime_info" in sketch
    assert "WIFI_CONNECT_TIMEOUT_MS = 10000" in sketch
    assert "class BoundedWiFiClient" in sketch
    assert "WiFiClient::connect(host, port, MQTT_CONNECT_TIMEOUT_MS)" in sketch
    assert "mqttClient.setSocketTimeout(3)" in sketch
    assert "static const size_t MQTT_BUFFER_SIZE = 1024;" in sketch
    assert "mqttClient.setBufferSize(MQTT_BUFFER_SIZE)" in sketch
    assert "char pendingPayload[768];" in sketch
    assert "topic_len=%u | payload_len=%u | packet_required=%u | buffer_size=%u" in sketch
    assert "MQTT publish result=%s" in sketch
    assert "Same message remains pending." in sketch
    assert "MAX_ACK_RETRY_INTERVAL_MS = 30000" in sketch
    assert "Acknowledgement subscription request sent at QoS 1" in sketch
    assert "ACK received | message=%s | outcome=%s | worker=%s | reason=%s" in sketch
    assert '"worker_id": worker_id' in telemetry_mqtt_source
    assert 'extractJsonString(response, "reason", reason, sizeof(reason))' in sketch
    assert '"REJECTED | %s | %s\\n"' in sketch
    assert '\\"timestamp_source\\":\\"%s\\"' in sketch
    assert "UTC unavailable; using server receipt time and device uptime." in sketch
    assert "Waiting for UTC time synchronization; not publishing yet." not in sketch
    assert "while (WiFi.status()" not in sketch
    assert sketch.count("configTime(") == 1
    assert "477868883321291777" in project


def test_representative_wokwi_payload_fits_sketch_and_mqtt_buffers():
    message = payload(
        message_id="0123456789abcdef-4294967295",
        timestamp="2026-10-15T13:42:00Z",
        timestamp_source="device_utc",
        uptime_ms=0xFFFFFFFF,
    )
    payload_bytes = len(json.dumps(message, separators=(",", ":")).encode("utf-8"))
    packet_buffer_required = 5 + 2 + len(MQTT_TOPIC.encode("utf-8")) + payload_bytes

    assert payload_bytes < 768
    assert packet_buffer_required < 1024


def test_local_demo_command_stores_and_labels_synthetic_telemetry():
    app = make_app()
    runner = app.test_cli_runner()

    result = runner.invoke(args=["telemetry-demo"])

    assert result.exit_code == 0, result.output
    assert "LOCAL SIMULATED" in result.output
    assert "No MQTT broker or physical device was contacted" in result.output
    with app.app_context():
        reading = TelemetryReading.query.one()
        assert reading.ingest_source == "local_demo"
        assert reading.payload_source == "local_demo"
        assert reading.telemetry_status == "SIMULATED"
        assert reading.chip_model == "LOCAL-DEMO"

    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True
    response = client.get("/api/dashboard/telemetry")

    assert response.status_code == 200
    assert response.json["connectivity_status"] == "never_connected"
    assert response.json["latest"]["ingest_source"] == "local_demo"
    assert response.json["latest"]["payload_source"] == "local_demo"
    assert response.json["runtime"]["evidence_type"] == "synthetic"


def test_mqtt_local_demo_payload_remains_marked_synthetic():
    app = make_app()
    with app.app_context():
        synthetic = payload(
            message_id="mqtt-local-demo-1",
            source="local_demo",
            chip_model="LOCAL-DEMO-MQTT",
            arduino_core_version="not reported",
            esp_idf_version="not reported",
        )
        assert ingest_telemetry_message(
            MQTT_TOPIC,
            json.dumps(synthetic),
            ingest_source="mqtt",
        )

    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True
    response = client.get("/api/dashboard/telemetry")

    assert response.status_code == 200
    assert response.json["latest"]["ingest_source"] == "mqtt"
    assert response.json["latest"]["payload_source"] == "local_demo"
    assert response.json["runtime"]["evidence_type"] == "synthetic"
    assert "Synthetic local demo values" in response.json["runtime"]["evidence_note"]


def test_telemetry_ingestion_rejects_unknown_source():
    app = make_app()
    with app.app_context():
        with pytest.raises(ValueError, match="ingest_source"):
            ingest_telemetry_message(
                MQTT_TOPIC,
                encoded_payload(),
                ingest_source="unknown",
            )


def test_unknown_and_archived_devices_cannot_ingest_messages():
    app = make_app()
    with app.app_context():
        Device.query.filter_by(name="SolarGuard-01").delete()
        db.session.commit()
        with pytest.raises(TelemetryDeviceError, match="not registered"):
            ingest_telemetry_message(MQTT_TOPIC, encoded_payload())

        device = Device(
            name="SolarGuard-01",
            telemetry_device_id="SolarGuard-01",
            vendor=app.config["TELEMETRY_DEVICE_VENDOR"],
            model=app.config["TELEMETRY_DEVICE_MODEL"],
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
    assert response.json["connectivity_status"] == "never_connected"

    with app.app_context():
        reading = add_reading(app.telemetry_device_id)
        response = client.get("/api/dashboard/telemetry")
        assert response.status_code == 200
        assert response.json["state"] == "connected"
        assert response.json["connectivity_status"] == "online"
        reading.received_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(
            seconds=60
        )
        db.session.commit()

    response = client.get("/api/dashboard/telemetry")
    assert response.status_code == 200
    assert response.json["state"] == "stale"
    assert response.json["connectivity_status"] == "offline"
    assert response.json["latest"]["telemetry_status"] == "SIMULATED"
    assert response.json["latest"]["message_id"] == "boot1234-1"
    assert response.json["latest"]["timestamp_source"] == "unknown"
    assert response.json["runtime"]["esp_idf_version"] == "v5.5.2"
    assert response.json["runtime"]["evidence_type"] == "reported"
    assert response.json["runtime"]["payload_source"] == "wokwi_simulation"
    assert response.json["runtime"]["confidence"] == "low"
    assert response.json["runtime"]["independently_verified"] is False
    assert response.json["product_firmware"]["version"] == "unknown"
    assert response.json["product_firmware"]["status"] == "unknown"
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
        self.keyword_queries = []

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

    def fetch_cves(self, keyword, page_size, start_index=0):
        self.keyword_queries.append((keyword, page_size, start_index))
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
        assert finding.match_status == "potential"
        assert finding.component_name == "ESP-IDF"
        assert finding.component_version == "v5.5.2"
        assert finding.confidence == "low"
        assert finding.cve.cvss_vector.startswith("CVSS:3.1/")
        assert finding.cve.source == "nvd"
        assert nvd.queries[0][3] == 0
        assert "component-product CPE criterion" in finding.evidence
        assert "https://nvd.nist.gov/vuln/detail/CVE-2025-1234" in finding.evidence
        assert "incomplete" in scan.summary.lower()
        evidence = json.loads(scan.notes)
        idf_state = next(
            item for item in evidence["components"] if item["component"] == "ESP-IDF"
        )
        assert idf_state["evidence_status"] == "REPORTED"
        assert idf_state["assessment"] == "assessed"
        assert "unauthenticated" in idf_state["evidence_note"]
        summary = build_vulnerability_summary()
        assert summary["severity"]["high"] == {"evaluated": 0, "potential": 1}


def test_component_scan_saves_not_applicable_and_unknown_mapping_results():
    app = make_app()
    with app.app_context():
        add_reading(app.telemetry_device_id)
        nvd = FakeComponentNVD(
            [cve_entry("CVE-2025-4321", "6.0", "7.0")]
        )
        scan = run_component_scan(app.telemetry_device_id, nvd)

        assert scan.status == "completed"
        assert scan.findings[0].match_status == "potential"
        assert scan.findings[0].matched_by == "nvd-cpe-product-potential"
        assert "Arduino ESP32 core" in scan.summary
        assert len(nvd.queries) == 2
        summary = build_vulnerability_summary()
        assert summary["severity"]["high"] == {"evaluated": 0, "potential": 1}


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


def test_component_scan_persists_unassessed_components_and_displays_scan_evidence():
    app = make_app()
    with app.app_context():
        add_reading(
            app.telemetry_device_id,
            esp_idf_version="not reported",
            arduino_core_version="not reported",
        )
        scan = run_component_scan(
            app.telemetry_device_id,
            FakeComponentNVD([]),
        )
        assert scan.status == "completed"
        assert scan.findings == []
        evidence = json.loads(scan.notes)
        assert evidence["device"]["firmware_version"] is None
        idf_state = next(
            item for item in evidence["components"] if item["component"] == "ESP-IDF"
        )
        assert idf_state["assessment"] == "not_assessed"
        assert idf_state["version"] is None
        assert "not proof" not in scan.summary.lower()
        assert DeviceComponent.query.filter_by(
            device_id=app.telemetry_device_id,
            component_key="esp_idf_runtime",
        ).one().evidence_status == "NOT_ASSESSED"

    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True
    response = client.get(f"/scans/{scan.id}")
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert "No matching CVEs returned" in page
    assert "This is not proof of safety" in page
    assert "ESP-IDF" in page
    assert "Not Assessed" in page


def test_component_scan_keeps_unknown_version_unassessed_but_records_product_candidates():
    app = make_app()
    with app.app_context():
        add_reading(
            app.telemetry_device_id,
            esp_idf_version="not reported",
            arduino_core_version="not reported",
        )
        nvd = FakeComponentNVD(
            [cve_entry("CVE-2025-1234", "5.0", "6.0")]
        )

        scan = run_component_scan(app.telemetry_device_id, nvd)

        assert scan.status == "completed"
        assert len(scan.findings) == 1
        finding = scan.findings[0]
        assert finding.match_status == "potential"
        assert finding.confidence == "low"
        assert finding.component_name == "ESP-IDF"
        assert finding.matched_by == "nvd-cpe-product-potential"
        assert "Applicability cannot be confirmed" in finding.evidence
        assert nvd.keyword_queries == [("Espressif ESP-IDF", 100, 0)]
        evidence = json.loads(scan.notes)
        idf_state = next(
            item for item in evidence["components"] if item["component"] == "ESP-IDF"
        )
        assert idf_state["assessment"] == "not_assessed"
        assert "version prevents applicability confirmation" in idf_state["reason"]


def test_setup_wokwi_cli_corrects_legacy_identity_without_losing_telemetry():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.create_all()
        device = Device(
            name="SolarGuard-01",
            telemetry_device_id="SolarGuard-01",
            vendor="SMA Solar Technology",
            model="Sunny Boy TL-21",
            firmware="2.60.03.R",
            firmware_version="2.60.03.R",
        )
        db.session.add(device)
        db.session.commit()
        device_id = device.id
        add_reading(device_id)

    result = app.test_cli_runner().invoke(args=["setup-wokwi-device"])
    assert result.exit_code == 0, result.output
    with app.app_context():
        device = db.session.get(Device, device_id)
        assert Device.query.count() == 1
        assert device.telemetry_device_id == "SolarGuard-01"
        assert device.vendor == app.config["TELEMETRY_DEVICE_VENDOR"]
        assert device.model == app.config["TELEMETRY_DEVICE_MODEL"]
        assert device.firmware == "unknown"
        assert device.firmware_version is None
        assert TelemetryReading.query.filter_by(device_id=device_id).count() == 1
        assert {
            component.component_key for component in device.components
        } == {
            "esp32_board",
            "esp32_chip",
            "application",
            "arduino_esp32_core",
            "esp_idf_runtime",
            "toolchain",
            "bootloader",
            "mqtt_client_library",
            "represented_inverter",
        }


def test_runtime_component_reports_do_not_overwrite_verified_evidence():
    app = make_app()
    with app.app_context():
        add_reading(
            app.telemetry_device_id,
            esp_idf_version="v5.5.2",
            arduino_core_version="3.3.6",
        )
        component = DeviceComponent(
            device_id=app.telemetry_device_id,
            component_key="esp_idf_runtime",
            name="ESP-IDF",
            component_type="software",
            vendor="Espressif",
            product="ESP-IDF (runtime-reported version)",
            version="4.4.0",
            evidence_source="Verified build manifest",
            evidence_method="Signed build record",
            evidence_note="Version confirmed by the retained build record.",
            evidence_status="VERIFIED",
            confidence="high",
        )
        db.session.add(component)
        db.session.commit()

        ensure_solar_guard_components(
            db.session.get(Device, app.telemetry_device_id)
        )
        scan = run_component_scan(
            app.telemetry_device_id,
            FakeComponentNVD([]),
        )

        db.session.refresh(component)
        assert component.version == "4.4.0"
        assert component.evidence_source == "Verified build manifest"
        assert component.evidence_note == (
            "Version confirmed by the retained build record."
        )
        assert component.evidence_status == "VERIFIED"

        evidence = json.loads(scan.notes)
        idf_state = next(
            item for item in evidence["components"] if item["component"] == "ESP-IDF"
        )
        assert idf_state["version"] == "4.4.0"
        assert idf_state["evidence_status"] == "VERIFIED"
        assert "telemetry reports v5.5.2" in idf_state["evidence_note"]


def test_solar_guard_product_firmware_cannot_be_set_from_inventory_api():
    app = make_app()
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True

    response = client.patch(
        f"/api/devices/{app.telemetry_device_id}",
        json={"firmware_version": "2.60.03.R"},
    )

    assert response.status_code == 409
    assert "cannot be set as installed" in response.json["error"]
    with app.app_context():
        device = db.session.get(Device, app.telemetry_device_id)
        assert device.firmware == "unknown"
        assert device.firmware_version is None


def test_reference_device_firmware_cannot_be_marked_as_installed():
    app = make_app()
    with app.app_context():
        reference = ensure_sma_firmware_reference_device()
        reference_id = reference.id
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True

    response = client.patch(
        f"/api/devices/{reference_id}",
        json={"firmware_version": "2.60.03.R"},
    )

    assert response.status_code == 409
    assert "cannot be set as installed" in response.json["error"]
    with app.app_context():
        reference = db.session.get(Device, reference_id)
        assert reference.firmware_version is None
        assert reference.firmware == "unknown"


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
        device = Device.query.filter_by(name="SolarGuard-01").one()
        assert device.vendor == app.config["TELEMETRY_DEVICE_VENDOR"]
        assert device.model == app.config["TELEMETRY_DEVICE_MODEL"]
        assert device.firmware == "unknown"
        assert device.firmware_version is None
        assert device.simulation_status == "simulated"
        assert DeviceComponent.query.filter_by(device_id=device.id).count() == 9
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
    response = client.post(
        "/api/scans/components",
        json={"device_id": app.telemetry_device_id},
    )
    assert response.status_code == 403


def test_solar_guard_profile_uses_component_scan_api(monkeypatch):
    app = make_app()
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"] = str(app.telemetry_user_id)
        session["_fresh"] = True

    profile = client.get(f"/devices/{app.telemetry_device_id}")
    assert profile.status_code == 200
    assert 'data-scan-endpoint="/api/scans/components"' in profile.get_data(
        as_text=True
    )

    with app.app_context():
        generic_scan_count = Scan.query.filter_by(
            device_id=app.telemetry_device_id
        ).count()
    generic_response = client.post(
        "/api/scans",
        json={"device_id": app.telemetry_device_id},
    )
    assert generic_response.status_code == 409
    with app.app_context():
        assert Scan.query.filter_by(
            device_id=app.telemetry_device_id
        ).count() == generic_scan_count

    monkeypatch.setattr(
        "app.blueprints.api_scans.run_component_scan",
        lambda device_id: SimpleNamespace(
            id=123,
            status="completed",
            summary=f"Completed scan for device {device_id}.",
        ),
    )
    response = client.post(
        "/api/scans/components",
        json={"device_id": app.telemetry_device_id},
    )

    assert response.status_code == 201
    assert response.json == {
        "id": 123,
        "status": "completed",
        "summary": f"Completed scan for device {app.telemetry_device_id}.",
    }


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
    tmp_path,
):
    app = make_app()
    app.instance_path = str(tmp_path)

    class FakeMQTTClient:
        def __init__(self, *_args, **_kwargs):
            self.subscriptions = []
            self.published = []

        def username_pw_set(self, *_args, **_kwargs):
            pytest.fail("Unexpected MQTT credentials in this test.")

        def reconnect_delay_set(self, min_delay, max_delay):
            assert (min_delay, max_delay) == (1, 30)

        def tls_set(self):
            pytest.fail("Unexpected MQTT TLS in this test.")

        def connect_async(self, host, port, keepalive):
            assert host == app.config["TELEMETRY_MQTT_BROKER_HOST"]
            assert port == app.config["TELEMETRY_MQTT_BROKER_PORT"]
            assert keepalive == 60

        def subscribe(self, topic, qos):
            self.subscriptions.append((topic, qos))
            return 0, len(self.subscriptions)

        def publish(self, topic, payload, qos, retain):
            self.published.append((topic, json.loads(payload), qos, retain))
            return SimpleNamespace(rc=0)

        def loop_forever(self, retry_first_connection):
            assert retry_first_connection is True
            reason_code = SimpleNamespace(is_failure=False)
            for message_id in range(1, 3):
                self.on_connect(self, None, None, reason_code, None)
                self.on_subscribe(
                    self,
                    None,
                    message_id,
                    [reason_code],
                    None,
                )
            self.on_disconnect(self, None, None, reason_code, None)
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

    assert fake_client.subscriptions == [(MQTT_TOPIC, 1), (MQTT_TOPIC, 1)]
    assert [
        (topic, ack["outcome"], ack["duplicate"], qos, retain)
        for topic, ack, qos, retain in fake_client.published
    ] == [
        (f"{MQTT_TOPIC}/ack", "stored", False, 1, False),
        (f"{MQTT_TOPIC}/ack", "stored", True, 1, False),
    ]
    with app.app_context():
        assert TelemetryReading.query.count() == 1
