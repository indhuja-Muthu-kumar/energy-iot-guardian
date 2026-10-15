from __future__ import annotations

import json
import logging
import math
import re
from datetime import UTC, datetime, timedelta
from secrets import token_hex

from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.alert import SecurityAlert
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.models.telemetry import TelemetryReading

logger = logging.getLogger(__name__)
MAX_TELEMETRY_MESSAGE_BYTES = 2048
MESSAGE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,80}")


class TelemetryValidationError(ValueError):
    pass


class TelemetryDeviceError(ValueError):
    pass


def _record_demo_threshold_alerts(device: Device, payload: dict) -> None:
    thresholds = current_app.config["TELEMETRY_DEMO_THRESHOLDS"]
    for field, threshold in thresholds.items():
        measured = payload[field]
        maximum = threshold["maximum"]
        if measured <= maximum:
            continue

        key = f"telemetry:{device.id}:{field}_above_demo_limit"
        summary = (
            f"DEMONSTRATION RULE: simulated {field} measured {measured:g} "
            f"{threshold['unit']}, above the configured demo limit "
            f"{maximum:g} {threshold['unit']} at "
            f"{payload['received_at'].isoformat()} UTC. This is a simulated-data "
            "threshold alert, not evidence of a physical equipment fault."
        )
        alert = SecurityAlert.query.filter_by(dedupe_key=key).first()
        if alert is None:
            alert = SecurityAlert(
                device_id=device.id,
                cve_id=None,
                alert_type="telemetry",
                severity="medium",
                title=f"Simulated telemetry {field} threshold exceeded",
                summary=summary,
                dedupe_key=key,
                source="telemetry",
            )
            db.session.add(alert)
        else:
            alert.summary = summary
            alert.status = "open"
            alert.acknowledged_at = None


def _required_text(payload: dict, field: str, max_length: int) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise TelemetryValidationError(f"{field} must be a non-empty string.")
    value = value.strip()
    if len(value) > max_length:
        raise TelemetryValidationError(f"{field} is too long.")
    return value


def validate_telemetry_payload(raw: bytes | str, received_at: datetime) -> dict:
    if isinstance(raw, bytes):
        if len(raw) > MAX_TELEMETRY_MESSAGE_BYTES:
            raise TelemetryValidationError("Telemetry message is too large.")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise TelemetryValidationError(
                "Telemetry message must be UTF-8 JSON."
            ) from error
    elif not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_TELEMETRY_MESSAGE_BYTES:
        raise TelemetryValidationError("Telemetry message is too large.")

    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as error:
        raise TelemetryValidationError("Telemetry message is not valid JSON.") from error
    if not isinstance(payload, dict):
        raise TelemetryValidationError("Telemetry message must be a JSON object.")
    schema_version = payload.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 1
    ):
        raise TelemetryValidationError("schema_version must be integer 1.")
    if (
        "message_type" in payload
        and payload["message_type"] != "telemetry_with_runtime_info"
    ):
        raise TelemetryValidationError("message_type is not supported.")

    device_id = _required_text(payload, "device_id", 80)
    if device_id != current_app.config["TELEMETRY_DEVICE_ID"]:
        raise TelemetryValidationError("Unknown telemetry device_id.")
    manufacturer = _required_text(payload, "manufacturer", 120)
    model = _required_text(payload, "model", 120)
    if (
        manufacturer != current_app.config["TELEMETRY_DEVICE_VENDOR"]
        or model != current_app.config["TELEMETRY_DEVICE_MODEL"]
    ):
        raise TelemetryValidationError("Simulated asset metadata did not match.")
    if payload.get("telemetry_status") != "SIMULATED":
        raise TelemetryValidationError("Telemetry must be labelled SIMULATED.")
    if payload.get("source") not in {"wokwi_simulation", "local_demo"}:
        raise TelemetryValidationError(
            "source must identify the simulation source."
        )

    message_id = _required_text(payload, "message_id", 80)
    if not MESSAGE_ID_PATTERN.fullmatch(message_id):
        raise TelemetryValidationError("message_id has an invalid format.")

    numeric_values = {}
    for field, minimum, maximum in (
        ("voltage", 0.0, 500.0),
        ("current", 0.0, 100.0),
        ("power", 0.0, 50000.0),
    ):
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TelemetryValidationError(f"{field} must be numeric.")
        value = float(value)
        if not math.isfinite(value) or not minimum <= value <= maximum:
            raise TelemetryValidationError(f"{field} is outside the allowed range.")
        numeric_values[field] = value
    calculated_power = numeric_values["voltage"] * numeric_values["current"]
    if abs(calculated_power - numeric_values["power"]) > max(2.0, calculated_power * 0.03):
        raise TelemetryValidationError("power does not agree with voltage × current.")

    received_at = received_at.astimezone(UTC)
    timestamp_source = payload.get("timestamp_source")
    if timestamp_source is None:
        timestamp_source = "unknown"
    if timestamp_source not in {
        "device_utc",
        "server_generated",
        "uptime",
        "unknown",
    }:
        raise TelemetryValidationError("timestamp_source is not supported.")

    uptime_ms = payload.get("uptime_ms")
    if uptime_ms is not None and (
        isinstance(uptime_ms, bool)
        or not isinstance(uptime_ms, int)
        or not 0 <= uptime_ms <= 0xFFFFFFFF
    ):
        raise TelemetryValidationError(
            "uptime_ms must be an unsigned 32-bit integer."
        )

    if timestamp_source == "uptime":
        if payload.get("timestamp", "missing") is not None:
            raise TelemetryValidationError(
                "timestamp must be null when timestamp_source is uptime."
            )
        if uptime_ms is None:
            raise TelemetryValidationError(
                "uptime_ms is required when timestamp_source is uptime."
            )
        timestamp = received_at
        stored_timestamp_source = "server_received"
    else:
        timestamp_value = _required_text(payload, "timestamp", 40)
        try:
            timestamp = datetime.fromisoformat(
                timestamp_value.replace("Z", "+00:00")
            )
        except ValueError as error:
            raise TelemetryValidationError("timestamp must be ISO-8601.") from error
        if timestamp.tzinfo is None:
            raise TelemetryValidationError("timestamp must include a timezone.")
        timestamp = timestamp.astimezone(UTC)
        if timestamp > received_at.replace(microsecond=0) + timedelta(minutes=5):
            raise TelemetryValidationError("timestamp is too far in the future.")
        stored_timestamp_source = timestamp_source

    chip_revision = payload.get("chip_revision")
    if (
        isinstance(chip_revision, bool)
        or not isinstance(chip_revision, int)
        or not 0 <= chip_revision <= 1000
    ):
        raise TelemetryValidationError("chip_revision must be an integer from 0 to 1000.")

    return {
        "device_id": device_id,
        "message_id": message_id,
        "payload_source": payload["source"],
        "timestamp_source": stored_timestamp_source,
        "source_uptime_ms": uptime_ms,
        **numeric_values,
        "timestamp": timestamp.replace(tzinfo=None),
        "received_at": received_at.replace(tzinfo=None),
        "telemetry_status": "SIMULATED",
        "chip_model": _required_text(payload, "chip_model", 80),
        "chip_revision": chip_revision,
        "arduino_core_version": _required_text(
            payload,
            "arduino_core_version",
            80,
        ),
        "esp_idf_version": _required_text(payload, "esp_idf_version", 80),
    }


def ingest_telemetry_message(
    topic: str,
    raw: bytes | str,
    *,
    ingest_source: str = "mqtt",
) -> bool:
    if topic != current_app.config["TELEMETRY_MQTT_TOPIC"]:
        raise TelemetryValidationError("Unexpected MQTT topic.")
    if ingest_source not in {"mqtt", "local_demo"}:
        raise ValueError("ingest_source must be 'mqtt' or 'local_demo'.")
    received_at = datetime.now(UTC)
    payload = validate_telemetry_payload(raw, received_at)

    device = Device.query.filter_by(
        telemetry_device_id=payload["device_id"],
    ).first()
    if device is None:
        raise TelemetryDeviceError(
            "SolarGuard-01 stable telemetry device_id is not registered."
        )
    if (
        device.vendor != current_app.config["TELEMETRY_DEVICE_VENDOR"]
        or device.model != current_app.config["TELEMETRY_DEVICE_MODEL"]
    ):
        raise TelemetryDeviceError(
            "Telemetry device ID does not match the expected simulated metadata."
        )
    if device.status == ARCHIVED_DEVICE_STATUS:
        raise TelemetryDeviceError("Archived devices cannot receive live telemetry.")

    if TelemetryReading.query.filter_by(
        source_message_id=payload["message_id"]
    ).first():
        return False

    reading = TelemetryReading(
        device_id=device.id,
        source_message_id=payload["message_id"],
        voltage=payload["voltage"],
        current=payload["current"],
        power=payload["power"],
        timestamp=payload["timestamp"],
        received_at=payload["received_at"],
        ingest_source=ingest_source,
        payload_source=payload["payload_source"],
        timestamp_source=payload["timestamp_source"],
        source_uptime_ms=payload["source_uptime_ms"],
        telemetry_status=payload["telemetry_status"],
        chip_model=payload["chip_model"],
        chip_revision=payload["chip_revision"],
        arduino_core_version=payload["arduino_core_version"],
        esp_idf_version=payload["esp_idf_version"],
    )
    db.session.add(reading)
    device.last_seen = received_at.replace(tzinfo=None)
    _record_demo_threshold_alerts(device, payload)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        if TelemetryReading.query.filter_by(
            source_message_id=payload["message_id"]
        ).first():
            return False
        raise
    return True


def create_local_demo_reading() -> bool:
    """Store one explicitly local simulated reading without using MQTT."""
    timestamp = datetime.now(UTC).replace(microsecond=0)
    payload = {
        "schema_version": 1,
        "message_id": f"local-{token_hex(12)}",
        "device_id": current_app.config["TELEMETRY_DEVICE_ID"],
        "source": "local_demo",
        "manufacturer": current_app.config["TELEMETRY_DEVICE_VENDOR"],
        "model": current_app.config["TELEMETRY_DEVICE_MODEL"],
        "voltage": 230.0,
        "current": 4.0,
        "power": 920.0,
        "timestamp": timestamp.isoformat(),
        "timestamp_source": "server_generated",
        "telemetry_status": "SIMULATED",
        "chip_model": "LOCAL-DEMO",
        "chip_revision": 0,
        "arduino_core_version": "not reported",
        "esp_idf_version": "not reported",
    }
    return ingest_telemetry_message(
        current_app.config["TELEMETRY_MQTT_TOPIC"],
        json.dumps(payload),
        ingest_source="local_demo",
    )
