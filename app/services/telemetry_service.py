from __future__ import annotations

import json
import logging
import math
import re
from datetime import UTC, datetime, timedelta

from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.models.telemetry import TelemetryReading

logger = logging.getLogger(__name__)
MAX_TELEMETRY_MESSAGE_BYTES = 2048
MESSAGE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,80}")


class TelemetryValidationError(ValueError):
    pass


class TelemetryDeviceError(ValueError):
    pass


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

    timestamp_value = _required_text(payload, "timestamp", 40)
    try:
        timestamp = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
    except ValueError as error:
        raise TelemetryValidationError("timestamp must be ISO-8601.") from error
    if timestamp.tzinfo is None:
        raise TelemetryValidationError("timestamp must include a timezone.")
    timestamp = timestamp.astimezone(UTC)
    received_at = received_at.astimezone(UTC)
    if timestamp > received_at.replace(microsecond=0) + timedelta(minutes=5):
        raise TelemetryValidationError("timestamp is too far in the future.")

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


def ingest_telemetry_message(topic: str, raw: bytes | str) -> bool:
    if topic != current_app.config["TELEMETRY_MQTT_TOPIC"]:
        raise TelemetryValidationError("Unexpected MQTT topic.")
    received_at = datetime.now(UTC)
    payload = validate_telemetry_payload(raw, received_at)

    device = Device.query.filter_by(
        name=payload["device_id"],
        vendor=current_app.config["TELEMETRY_DEVICE_VENDOR"],
        model=current_app.config["TELEMETRY_DEVICE_MODEL"],
    ).first()
    if device is None:
        raise TelemetryDeviceError(
            "SolarGuard-01 is not registered with the expected simulated metadata."
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
        telemetry_status=payload["telemetry_status"],
        chip_model=payload["chip_model"],
        chip_revision=payload["chip_revision"],
        arduino_core_version=payload["arduino_core_version"],
        esp_idf_version=payload["esp_idf_version"],
    )
    db.session.add(reading)
    device.last_seen = payload["received_at"]
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
