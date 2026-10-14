from __future__ import annotations

from flask import Blueprint, jsonify
from flask_login import login_required

from app.models.kev import KEVEntry

api_kev_bp = Blueprint("api_kev", __name__)


@api_kev_bp.get("")
@login_required
def list_kev():
    entries = KEVEntry.query.order_by(KEVEntry.created_at.desc()).limit(50).all()
    return jsonify({"items": [{
        "id": entry.id,
        "cve_id": entry.cve_id,
        "vendor_project": entry.vendor_project,
        "product": entry.product,
        "short_description": entry.short_description,
    } for entry in entries]})
