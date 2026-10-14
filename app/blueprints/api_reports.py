from __future__ import annotations
from flask import Blueprint, Response, jsonify, request
from flask_login import login_required

from app.extensions import db
from app.models.scan import Scan
from app.services.report_service import export_csv

api_reports_bp = Blueprint("api_reports", __name__)


@api_reports_bp.get("/csv")
@login_required
def export_report_csv():
    scan_id = None
    if "scan_id" in request.args:
        raw_scan_id = request.args.get("scan_id", "")
        if not raw_scan_id:
            return jsonify({"error": "scan_id must be a positive integer."}), 400
        try:
            scan_id = int(raw_scan_id)
        except ValueError:
            return jsonify({"error": "scan_id must be a positive integer."}), 400
        if scan_id < 1:
            return jsonify({"error": "scan_id must be a positive integer."}), 400
        if db.session.get(Scan, scan_id) is None:
            return jsonify({"error": "Scan not found."}), 404
    csv_data = export_csv(scan_id=scan_id)
    filename = (
        f"energy_iot_scan_{scan_id}_findings.csv"
        if scan_id is not None
        else "energy_iot_report.csv"
    )
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@api_reports_bp.get("/summary")
@login_required
def report_summary():
    return jsonify({"status": "ok", "message": "Report generator ready."})
