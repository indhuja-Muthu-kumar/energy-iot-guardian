from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import login_required

from app.models.scan import Scan
from app.services.scan_service import run_scan_for_device

api_scans_bp = Blueprint("api_scans", __name__)


@api_scans_bp.get("")
@login_required
def list_scans():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return jsonify({
        "items": [
            {
                "id": s.id,
                "device_id": s.device_id,
                "scan_type": s.scan_type,
                "status": s.status,
                "summary": s.summary,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in scans
        ]
    })


@api_scans_bp.post("")
@login_required
def create_scan():
    payload = request.get_json(silent=True) or {}
    device_id = payload.get("device_id")
    if not isinstance(device_id, int) or isinstance(device_id, bool):
        return jsonify({"error": "device_id is required."}), 400
    scan = run_scan_for_device(device_id)
    status_code = 201 if scan.status == "completed" else 502
    return jsonify({"id": scan.id, "status": scan.status, "summary": scan.summary}), status_code
