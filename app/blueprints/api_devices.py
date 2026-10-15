from __future__ import annotations

import json
from datetime import UTC, datetime

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required

from app.extensions import db
from app.models.audit import AuditLog
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.schemas.device import DeviceSchema

api_devices_bp = Blueprint("api_devices", __name__)

device_schema = DeviceSchema()


def _has_firmware_evidence(payload: dict) -> bool:
    return any(
        field in payload
        for field in (
            "firmware_evidence_source",
            "firmware_evidence_method",
            "firmware_evidence_note",
        )
    )


def _normalize_firmware_fields(data: dict, payload: dict) -> None:
    if "firmware_version" in payload:
        version = (data.get("firmware_version") or "").strip()
    elif "firmware" in payload:
        version = (data.get("firmware") or "").strip()
    else:
        return

    if not version or version.lower() == "unknown":
        data["firmware"] = "unknown"
        data["firmware_version"] = None
    else:
        data["firmware"] = version
        data["firmware_version"] = version


def _record_firmware_evidence(
    device: Device,
    payload: dict,
    data: dict,
) -> None:
    version = device.firmware_version
    if not version and device.firmware.lower() != "unknown":
        version = device.firmware

    if not version or not version.strip() or version.strip().lower() == "unknown":
        device.firmware = "unknown"
        device.firmware_version = None
        device.firmware_evidence_source = None
        device.firmware_evidence_method = None
        device.firmware_evidence_note = None
        device.firmware_evidence_collected_at = None
        device.firmware_verification_status = "UNKNOWN"
        device.firmware_confidence = "none"
        action = "firmware_evidence_cleared"
        evidence = {"status": "UNKNOWN"}
    else:
        source = (data.get("firmware_evidence_source") or "").strip()
        method = (data.get("firmware_evidence_method") or "").strip()
        note = (data.get("firmware_evidence_note") or "").strip()
        device.firmware_evidence_source = source or "Operator entry"
        device.firmware_evidence_method = method or "Manual inventory entry"
        device.firmware_evidence_note = note or None
        device.firmware_evidence_collected_at = datetime.now(UTC).replace(tzinfo=None)
        device.firmware_verification_status = "REPORTED"
        device.firmware_confidence = "low"
        action = "firmware_evidence_reported"
        evidence = {
            "version": version,
            "source": device.firmware_evidence_source,
            "method": device.firmware_evidence_method,
            "status": "REPORTED",
        }

    db.session.add(
        AuditLog(
            user_id=current_user.id,
            action=action,
            entity_type="device",
            entity_id=str(device.id) if device.id is not None else None,
            details=json.dumps(evidence, sort_keys=True),
        )
    )


@api_devices_bp.get("")
@login_required
def list_devices():
    items = (
        Device.query.filter(
            Device.status.is_distinct_from(ARCHIVED_DEVICE_STATUS)
        )
        .order_by(Device.name.asc())
        .all()
    )
    return jsonify({"items": device_schema.dump(items, many=True)})


@api_devices_bp.post("")
@login_required
def create_device():
    payload = request.get_json(silent=True) or {}
    if "status" in payload and not current_user.is_admin:
        return jsonify({"error": "Only administrators can set device status."}), 403
    errors = device_schema.validate(payload)
    if errors:
        return jsonify({"errors": errors}), 400
    if _has_firmware_evidence(payload) and not (
        "firmware_version" in payload or "firmware" in payload
    ):
        return jsonify(
            {"error": "Firmware evidence details require a firmware version."}
        ), 400
    data = device_schema.load(payload)
    evidence_fields = {
        key: data.pop(key)
        for key in (
            "firmware_evidence_source",
            "firmware_evidence_method",
            "firmware_evidence_note",
        )
        if key in data
    }
    _normalize_firmware_fields(data, payload)
    device = Device(**data)
    db.session.add(device)
    db.session.flush()
    if "firmware_version" in payload or (
        "firmware" in payload and data["firmware"].lower() != "unknown"
    ):
        _record_firmware_evidence(device, payload, evidence_fields)
    db.session.commit()
    return jsonify(device_schema.dump(device)), 201


@api_devices_bp.route("/<int:device_id>", methods=["PUT", "PATCH"])
@login_required
def update_device(device_id: int):
    device = db.get_or_404(Device, device_id)
    if device.status == ARCHIVED_DEVICE_STATUS:
        return jsonify({"error": "Archived devices cannot be edited."}), 409
    payload = request.get_json(silent=True) or {}
    if (
        (
            device.telemetry_device_id
            == current_app.config["TELEMETRY_DEVICE_ID"]
            or device.simulation_status == "reference"
        )
        and any(
            field in payload
            for field in ("firmware", "firmware_version")
        )
    ):
        return jsonify(
            {
                "error": (
                    "Firmware on simulated and reference-only inventory records "
                    "cannot be set as installed. Record component or documented "
                    "reference evidence separately."
                )
            }
        ), 409
    if "status" in payload and not current_user.is_admin:
        return jsonify({"error": "Only administrators can set device status."}), 403
    errors = device_schema.validate(payload, partial=True)
    if errors:
        return jsonify({"errors": errors}), 400
    if _has_firmware_evidence(payload) and not (
        "firmware_version" in payload or "firmware" in payload
    ):
        return jsonify(
            {"error": "Firmware evidence details require a firmware version update."}
        ), 400
    data = device_schema.load(payload, partial=True)
    evidence_fields = {
        key: data.pop(key)
        for key in (
            "firmware_evidence_source",
            "firmware_evidence_method",
            "firmware_evidence_note",
        )
        if key in data
    }
    firmware_updated = "firmware_version" in data or "firmware" in data
    _normalize_firmware_fields(data, payload)
    for field, value in data.items():
        setattr(device, field, value)
    if firmware_updated:
        _record_firmware_evidence(device, payload, evidence_fields)
    db.session.commit()
    return jsonify(device_schema.dump(device))


@api_devices_bp.get("/<int:device_id>")
@login_required
def get_device(device_id: int):
    device = db.get_or_404(Device, device_id)
    return jsonify(device_schema.dump(device))
