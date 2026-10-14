from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Blueprint, current_app, jsonify
from flask_login import login_required

from app.extensions import db
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.models.finding import Finding
from app.models.kev import KEVEntry
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
        "kev_entries": db.session.query(KEVEntry).count(),
        "vulnerability_summary": build_vulnerability_summary(),
    })


@api_dashboard_bp.get("/telemetry")
@login_required
def dashboard_telemetry():
    device = Device.query.filter_by(
        name=current_app.config["TELEMETRY_DEVICE_ID"],
        vendor=current_app.config["TELEMETRY_DEVICE_VENDOR"],
        model=current_app.config["TELEMETRY_DEVICE_MODEL"],
    ).first()
    if device is None:
        return jsonify(
            {
                "state": "waiting",
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

    def iso_utc(value: datetime) -> str:
        return value.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")

    return jsonify(
        {
            "state": state,
            "device": {
                "id": device.id,
                "name": device.name,
                "vendor": device.vendor,
                "model": device.model,
                "status": device.status,
            },
            "latest": {
                "voltage": latest.voltage,
                "current": latest.current,
                "power": latest.power,
                "timestamp": iso_utc(latest.timestamp),
                "received_at": iso_utc(latest.received_at),
                "ingest_source": latest.ingest_source,
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
            },
            "firmware_inventory_complete": False,
        }
    )
