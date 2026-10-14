from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from app.extensions import db
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.schemas.device import DeviceSchema

api_devices_bp = Blueprint("api_devices", __name__)

device_schema = DeviceSchema()


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
    data = device_schema.load(payload)
    if "firmware_version" in payload:
        data["firmware"] = data["firmware_version"] or "unknown"
    elif data["firmware"].lower() != "unknown":
        data["firmware_version"] = data["firmware"]
    device = Device(**data)
    db.session.add(device)
    db.session.commit()
    return jsonify(device_schema.dump(device)), 201


@api_devices_bp.route("/<int:device_id>", methods=["PUT", "PATCH"])
@login_required
def update_device(device_id: int):
    device = db.get_or_404(Device, device_id)
    if device.status == ARCHIVED_DEVICE_STATUS:
        return jsonify({"error": "Archived devices cannot be edited."}), 409
    payload = request.get_json(silent=True) or {}
    if "status" in payload and not current_user.is_admin:
        return jsonify({"error": "Only administrators can set device status."}), 403
    errors = device_schema.validate(payload, partial=True)
    if errors:
        return jsonify({"errors": errors}), 400
    data = device_schema.load(payload, partial=True)
    if "firmware_version" in data:
        data["firmware"] = data["firmware_version"] or "unknown"
    elif "firmware" in data:
        data["firmware_version"] = (
            None if data["firmware"].lower() == "unknown" else data["firmware"]
        )
    for field, value in data.items():
        setattr(device, field, value)
    db.session.commit()
    return jsonify(device_schema.dump(device))


@api_devices_bp.get("/<int:device_id>")
@login_required
def get_device(device_id: int):
    device = db.get_or_404(Device, device_id)
    return jsonify(device_schema.dump(device))
