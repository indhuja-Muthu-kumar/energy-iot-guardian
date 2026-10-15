from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Blueprint, current_app, jsonify
from flask_login import login_required

from app.extensions import db
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.models.finding import Finding
from app.models.kev import CISA_KEV_SOURCE, KEVEntry
from app.models.scan import Scan
from app.models.telemetry import TelemetryReading
from app.services.dashboard_service import build_vulnerability_summary

api_dashboard_bp = Blueprint("api_dashboard", __name__)


@api_dashboard_bp.get("")
@login_required
def dashboard_stats():
    return jsonify({
        "devices": db.session.query(Device).count(),
        "scans": db.session.query(Scan).count(),
        "findings": db.session.query(Finding).count(),
        "kev_entries": KEVEntry.query.filter_by(source=CISA_KEV_SOURCE).count(),
        "vulnerability_summary": build_vulnerability_summary(),
    })


@api_dashboard_bp.get("/telemetry")
@login_required
def dashboard_telemetry():
    device = Device.query.filter_by(
        telemetry_device_id=current_app.config["TELEMETRY_DEVICE_ID"],
    ).first()
    if device is None:
        return jsonify(
            {
                "state": "waiting",
                "connectivity_status": "unregistered",
                "message": "Waiting for telemetry from the registered Wokwi device.",
                "history": [],
                "firmware_inventory_complete": False,
            }
        )

    readings = (
        TelemetryReading.query.filter_by(device_id=device.id)
        .order_by(TelemetryReading.received_at.desc(), TelemetryReading.id.desc())
        .limit(current_app.config["TELEMETRY_HISTORY_LIMIT"])
        .all()
    )
    if not readings:
        archived = device.status == ARCHIVED_DEVICE_STATUS
        return jsonify(
            {
                "state": "archived" if archived else "waiting",
                "connectivity_status": (
                    "archived" if archived else "never_connected"
                ),
                "device": {
                    "id": device.id,
                    "name": device.name,
                    "vendor": device.vendor,
                    "model": device.model,
                    "status": device.status,
                },
                "message": (
                    "This device is archived and has no telemetry history."
                    if archived
                    else "Waiting for telemetry from Wokwi."
                ),
                "history": [],
                "firmware_inventory_complete": False,
            }
        )

    latest = readings[0]
    now = datetime.now(UTC).replace(tzinfo=None)
    if device.status == ARCHIVED_DEVICE_STATUS:
        state = "archived"
    elif now - latest.received_at > timedelta(
        seconds=current_app.config["TELEMETRY_STALE_AFTER_SECONDS"]
    ):
        state = "demo_stale" if latest.ingest_source == "local_demo" else "stale"
    elif latest.ingest_source == "local_demo":
        state = "demo"
    else:
        state = "connected"
    connectivity_status = (
        "archived"
        if state == "archived"
        else "never_connected"
        if latest.ingest_source == "local_demo"
        else "offline"
        if state == "stale"
        else "online"
    )

    def iso_utc(value: datetime) -> str:
        return value.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")

    return jsonify(
        {
            "state": state,
            "connectivity_status": connectivity_status,
            "device": {
                "id": device.id,
                "name": device.name,
                "vendor": device.vendor,
                "model": device.model,
                "status": device.status,
            },
            "latest": {
                "message_id": latest.source_message_id,
                "voltage": latest.voltage,
                "current": latest.current,
                "power": latest.power,
                "timestamp": iso_utc(latest.timestamp),
                "timestamp_source": latest.timestamp_source,
                "source_uptime_ms": latest.source_uptime_ms,
                "received_at": iso_utc(latest.received_at),
                "ingest_source": latest.ingest_source,
                "payload_source": latest.payload_source,
                "telemetry_status": latest.telemetry_status,
            },
            "history": [
                {
                    "timestamp": iso_utc(reading.timestamp),
                    "voltage": reading.voltage,
                    "current": reading.current,
                    "power": reading.power,
                }
                for reading in readings
            ],
            "runtime": {
                "chip_model": latest.chip_model,
                "chip_revision": latest.chip_revision,
                "arduino_core_version": latest.arduino_core_version,
                "esp_idf_version": latest.esp_idf_version,
                "source": latest.ingest_source,
                "payload_source": latest.payload_source,
                "reported_at": iso_utc(latest.received_at),
                "evidence_type": (
                    "synthetic"
                    if latest.payload_source == "local_demo"
                    else (
                        "reported"
                        if latest.payload_source == "wokwi_simulation"
                        else "unknown"
                    )
                ),
                "confidence": "low",
                "independently_verified": False,
                "evidence_note": (
                    "Synthetic local demo values; not hardware evidence."
                    if latest.payload_source == "local_demo"
                    else (
                        "Reported in the simulated MQTT payload; the public "
                        "broker does not authenticate the publisher."
                        if latest.payload_source == "wokwi_simulation"
                        else (
                            "The source of this legacy telemetry payload was "
                            "not retained; runtime values are not independently "
                            "verified."
                        )
                    )
                ),
            },
            "product_firmware": {
                "version": (
                    device.firmware_version or device.firmware or "unknown"
                ),
                "status": (
                    "unknown"
                    if not (
                        device.firmware_version
                        or device.firmware
                    )
                    or (
                        (device.firmware_version or device.firmware).strip().lower()
                        == "unknown"
                    )
                    else "recorded_unverified"
                ),
            },
            "firmware_inventory_complete": False,
        }
    )
