from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import login_required

from app.extensions import db
from app.models.cve import CVE

api_cves_bp = Blueprint("api_cves", __name__)


@api_cves_bp.get("")
@login_required
def list_cves():
    query = request.args.get("q", "").strip()
    results = CVE.query

    if query:
        search = f"%{query}%"
        results = results.filter(
            CVE.id.ilike(search) |
            CVE.description.ilike(search)
        )

    items = results.limit(25).all()

    return jsonify({
        "items": [{
            "id": item.id,
            "description": item.description,
            "severity": item.severity,
            "cvss_score": item.cvss_score,
        } for item in items]
    })


@api_cves_bp.get("/<cve_id>")
@login_required
def get_cve(cve_id: str):
    item = db.get_or_404(CVE, cve_id)

    return jsonify({
        "id": item.id,
        "description": item.description,
        "severity": item.severity,
        "cvss_score": item.cvss_score,
        "cwe": item.cwe,
    })