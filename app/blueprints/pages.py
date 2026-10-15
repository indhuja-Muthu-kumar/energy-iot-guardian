from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from threading import Lock

import requests
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.models.alert import SecurityAlert
from app.models.audit import AuditLog
from app.models.cve import CVE
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.models.finding import Finding
from app.models.kev import CISA_KEV_SOURCE, KEVEntry
from app.models.patch import PatchCandidate
from app.models.scan import Scan
from app.models.sync_log import SyncLog
from app.models.telemetry import TelemetryReading
from app.models.user import User
from app.services.dashboard_service import (
    build_dashboard_panels,
    build_recent_activity,
    build_vulnerability_summary,
)
from app.services.component_scan_service import run_component_scan
from app.services.risk_service import prioritize_finding

pages_bp = Blueprint("pages", __name__)
logger = logging.getLogger(__name__)
_nvd_sync_lock = Lock()


@pages_bp.route("/")
def landing():
    return render_template("landing.html")


@pages_bp.route("/dashboard")
@login_required
def dashboard():
    device_count = db.session.query(Device).count()
    scan_count = db.session.query(Scan).count()
    finding_count = db.session.query(Finding).count()
    kev_count = KEVEntry.query.filter_by(source=CISA_KEV_SOURCE).count()
    vulnerability_summary = build_vulnerability_summary(include_device_summaries=True)
    dashboard_panels = build_dashboard_panels()
    dashboard_panels["recent_alerts"] = (
        SecurityAlert.query.order_by(SecurityAlert.created_at.desc()).limit(5).all()
    )
    dashboard_panels["latest_nvd_sync"] = (
        SyncLog.query.filter_by(source="nvd", status="success")
        .order_by(SyncLog.completed_at.desc(), SyncLog.id.desc())
        .first()
    )
    dashboard_panels["latest_nvd_attempt"] = (
        SyncLog.query.filter_by(source="nvd")
        .order_by(SyncLog.started_at.desc(), SyncLog.id.desc())
        .first()
    )
    dashboard_panels["latest_kev_sync"] = (
        SyncLog.query.filter_by(source="kev", status="success")
        .order_by(SyncLog.completed_at.desc(), SyncLog.id.desc())
        .first()
    )
    dashboard_panels["latest_kev_attempt"] = (
        SyncLog.query.filter_by(source="kev")
        .order_by(SyncLog.started_at.desc(), SyncLog.id.desc())
        .first()
    )
    latest_kev_completed_at = (
        dashboard_panels["latest_kev_sync"].completed_at
        if dashboard_panels["latest_kev_sync"]
        else None
    )
    kev_sync_age_seconds = (
        (
            datetime.now(UTC).replace(tzinfo=None) - latest_kev_completed_at
        ).total_seconds()
        if latest_kev_completed_at
        else None
    )
    dashboard_panels["kev_catalog_fresh"] = bool(
        kev_sync_age_seconds is not None
        and 0 <= kev_sync_age_seconds
        <= current_app.config["INTELLIGENCE_STALE_AFTER_SECONDS"]
    )
    dashboard_panels["open_alert_count"] = SecurityAlert.query.filter_by(status="open").count()
    dashboard_panels["open_alerts"] = (
        SecurityAlert.query.filter_by(status="open")
        .order_by(SecurityAlert.created_at.desc(), SecurityAlert.id.desc())
        .limit(5)
        .all()
    )
    dashboard_panels["pending_patch_candidates"] = (
        PatchCandidate.query.filter_by(status="discovered")
        .order_by(PatchCandidate.created_at.desc(), PatchCandidate.id.desc())
        .limit(5)
        .all()
    )
    dashboard_panels["pending_patch_count"] = PatchCandidate.query.filter_by(
        status="discovered"
    ).count()
    dashboard_panels["recent_remediation"] = (
        PatchCandidate.query.order_by(
            PatchCandidate.updated_at.desc(),
            PatchCandidate.id.desc(),
        )
        .limit(5)
        .all()
    )
    dashboard_panels["recent_activity"] = build_recent_activity()
    dashboard_panels["risk_devices"] = sorted(
        (
            item
            for item in vulnerability_summary["device_summaries"].values()
            if (
                item["severity"]["critical"]["evaluated"]
                + item["severity"]["critical"]["potential"]
                + item["severity"]["high"]["evaluated"]
                + item["severity"]["high"]["potential"]
            )
        ),
        key=lambda item: (
            item["severity"]["critical"]["evaluated"]
            + item["severity"]["critical"]["potential"]
            + item["severity"]["high"]["evaluated"]
            + item["severity"]["high"]["potential"],
            item["severity"]["critical"]["potential"],
        ),
        reverse=True,
    )[:5]
    return render_template(
        "dashboard.html",
        wallet={
            "devices": device_count,
            "scans": scan_count,
            "findings": finding_count,
            "kev": kev_count,
        },
        finding_count=finding_count,
        cve_count=db.session.query(CVE).count(),
        confirmed_device_cves=sum(
            bucket["evaluated"]
            for item in vulnerability_summary["device_summaries"].values()
            for bucket in (
                *item["severity"].values(),
                item["unknown_severity"],
            )
        ),
        vulnerability_summary=vulnerability_summary,
        dashboard_panels=dashboard_panels,
    )


@pages_bp.route("/devices")
@login_required
def devices():
    items = (
        Device.query.filter(Device.status.is_distinct_from(ARCHIVED_DEVICE_STATUS))
        .order_by(Device.name.asc())
        .all()
    )
    latest_telemetry = {}
    latest_findings = {}
    telemetry_freshness = {}
    device_ids = [device.id for device in items]
    if device_ids:
        for reading in (
            TelemetryReading.query.filter(TelemetryReading.device_id.in_(device_ids))
            .order_by(
                TelemetryReading.received_at.desc(),
                TelemetryReading.id.desc(),
            )
            .all()
        ):
            latest_telemetry.setdefault(reading.device_id, reading)
        now = datetime.now(UTC).replace(tzinfo=None)
        stale_after = current_app.config["TELEMETRY_STALE_AFTER_SECONDS"]
        simulated_device_id = current_app.config["TELEMETRY_DEVICE_ID"]
        for device in items:
            reading = latest_telemetry.get(device.id)
            if reading is None:
                telemetry_freshness[device.id] = "never"
            elif reading.ingest_source == "local_demo":
                telemetry_freshness[device.id] = "demo"
            elif (now - reading.received_at).total_seconds() > stale_after:
                telemetry_freshness[device.id] = (
                    "simulated_stale"
                    if device.telemetry_device_id == simulated_device_id
                    else "stale"
                )
            else:
                telemetry_freshness[device.id] = (
                    "simulated_fresh"
                    if device.telemetry_device_id == simulated_device_id
                    else "fresh"
                )
        for finding in (
            Finding.query.join(Scan, Finding.scan_id == Scan.id)
            .filter(Finding.device_id.in_(device_ids))
            .order_by(Scan.created_at.desc(), Finding.id.desc())
            .all()
        ):
            latest_findings.setdefault(finding.device_id, finding)
    return render_template(
        "devices.html",
        devices=items,
        latest_telemetry=latest_telemetry,
        telemetry_freshness=telemetry_freshness,
        simulated_telemetry_device_id=current_app.config["TELEMETRY_DEVICE_ID"],
        latest_findings=latest_findings,
    )


@pages_bp.route("/alerts")
@login_required
def alerts():
    query = SecurityAlert.query
    status_filter = request.args.get("status", "").strip().lower()
    severity_filter = request.args.get("severity", "").strip().lower()
    type_filter = request.args.get("type", "").strip().lower()
    device_filter = request.args.get("device", "").strip()
    search = request.args.get("q", "").strip()[:120]
    if status_filter in {"open", "acknowledged", "in_progress", "resolved"}:
        query = query.filter(SecurityAlert.status == status_filter)
    else:
        status_filter = ""
    if severity_filter in {"critical", "high", "medium", "low", "unknown"}:
        query = query.filter(db.func.lower(SecurityAlert.severity) == severity_filter)
    else:
        severity_filter = ""
    if type_filter and len(type_filter) <= 80:
        query = query.filter(db.func.lower(SecurityAlert.alert_type) == type_filter)
    else:
        type_filter = ""
    if device_filter.isdigit():
        query = query.filter(SecurityAlert.device_id == int(device_filter))
    else:
        device_filter = ""
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            db.or_(
                SecurityAlert.title.ilike(pattern),
                SecurityAlert.summary.ilike(pattern),
                SecurityAlert.cve_id.ilike(pattern),
            )
        )

    alert_items = (
        query.order_by(SecurityAlert.created_at.desc(), SecurityAlert.id.desc()).limit(100).all()
    )
    alert_keys = {(item.device_id, item.cve_id) for item in alert_items if item.cve_id}
    cve_ids = {cve_id for _device_id, cve_id in alert_keys}
    latest_findings = {}
    patches = {}
    if cve_ids:
        rows = (
            Finding.query.join(Scan, Finding.scan_id == Scan.id)
            .filter(Finding.cve_id.in_(cve_ids))
            .order_by(Scan.created_at.desc(), Finding.id.desc())
            .all()
        )
        for finding in rows:
            key = (finding.device_id, finding.cve_id)
            if key in alert_keys:
                latest_findings.setdefault(key, finding)
        for candidate in PatchCandidate.query.filter(PatchCandidate.cve_id.in_(cve_ids)).all():
            key = (candidate.device_id, candidate.cve_id)
            if key in alert_keys:
                patches.setdefault(key, candidate)

    return render_template(
        "alerts.html",
        alerts=alert_items,
        latest_findings=latest_findings,
        patches=patches,
        status_filter=status_filter,
        severity_filter=severity_filter,
        type_filter=type_filter,
        device_filter=device_filter,
        search=search,
        devices=Device.query.order_by(Device.name.asc()).all(),
    )


@pages_bp.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id: int):
    alert = db.get_or_404(SecurityAlert, alert_id)
    timeline = (
        AuditLog.query.filter_by(
            entity_type="security_alert",
            entity_id=str(alert.id),
        )
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(100)
        .all()
    )
    timeline_entries = []
    for event in timeline:
        try:
            details = json.loads(event.details) if event.details else {}
        except (json.JSONDecodeError, TypeError):
            details = {"legacy_details": event.details}
        timeline_entries.append(
            {
                "action": event.action,
                "created_at": event.created_at,
                "user": event.user,
                "details": details,
            }
        )
    latest_finding = None
    if alert.cve_id:
        latest_finding = (
            Finding.query.filter_by(
                device_id=alert.device_id,
                cve_id=alert.cve_id,
            )
            .order_by(Finding.created_at.desc(), Finding.id.desc())
            .first()
        )
    return render_template(
        "alert_detail.html",
        alert=alert,
        timeline=timeline_entries,
        latest_finding=latest_finding,
    )


@pages_bp.post("/alerts/<int:alert_id>/transition")
@login_required
def transition_alert(alert_id: int):
    if not current_user.is_admin:
        abort(403)
    alert = db.get_or_404(SecurityAlert, alert_id)
    new_status = request.form.get("status", "").strip().lower()
    note = request.form.get("note", "").strip()[:2000]
    allowed_transitions = {
        "open": {"acknowledged"},
        "acknowledged": {"open", "in_progress"},
        "in_progress": {"open", "resolved"},
        "resolved": {"open"},
    }
    if new_status not in allowed_transitions.get(alert.status, set()):
        abort(400, description="That alert status transition is not allowed.")

    previous_status = alert.status
    alert.status = new_status
    alert.acknowledged_at = (
        datetime.now(UTC).replace(tzinfo=None)
        if new_status == "acknowledged"
        else None
    )
    action = "reopened" if previous_status == "resolved" else "status_changed"
    details = {
        "from": previous_status,
        "to": new_status,
        "note": note or None,
    }
    db.session.add(
        AuditLog(
            user_id=current_user.id,
            action=action,
            entity_type="security_alert",
            entity_id=str(alert.id),
            details=json.dumps(details, sort_keys=True),
        )
    )
    db.session.commit()
    flash(f"Alert status changed to {new_status.replace('_', ' ')}.", "success")
    return redirect(url_for("pages.alert_detail", alert_id=alert.id))


@pages_bp.post("/alerts/<int:alert_id>/notes")
@login_required
def add_alert_note(alert_id: int):
    if not current_user.is_admin:
        abort(403)
    alert = db.get_or_404(SecurityAlert, alert_id)
    note = request.form.get("note", "").strip()
    if not note or len(note) > 2000:
        abort(400, description="Enter an incident note of 1 to 2000 characters.")
    db.session.add(
        AuditLog(
            user_id=current_user.id,
            action="note_added",
            entity_type="security_alert",
            entity_id=str(alert.id),
            details=json.dumps({"note": note}, sort_keys=True),
        )
    )
    db.session.commit()
    flash("Incident note added to the timeline.", "success")
    return redirect(url_for("pages.alert_detail", alert_id=alert.id))


@pages_bp.post("/alerts/<int:alert_id>/acknowledge")
@login_required
def toggle_alert_acknowledgement(alert_id: int):
    if not current_user.is_admin:
        abort(403)
    alert = db.get_or_404(SecurityAlert, alert_id)
    if alert.status == "open":
        alert.status = "acknowledged"
        alert.acknowledged_at = datetime.now(UTC).replace(tzinfo=None)
        db.session.add(
            AuditLog(
                user_id=current_user.id,
                action="status_changed",
                entity_type="security_alert",
                entity_id=str(alert.id),
                details=json.dumps({"from": "open", "to": "acknowledged"}),
            )
        )
        db.session.commit()
        flash("Alert acknowledged.", "success")
    elif alert.status == "acknowledged":
        alert.status = "open"
        alert.acknowledged_at = None
        db.session.add(
            AuditLog(
                user_id=current_user.id,
                action="status_changed",
                entity_type="security_alert",
                entity_id=str(alert.id),
                details=json.dumps({"from": "acknowledged", "to": "open"}),
            )
        )
        db.session.commit()
        flash("Alert marked unread.", "success")
    else:
        flash("Use the alert detail page to choose a valid status transition.", "warning")
    return redirect(url_for("pages.alert_detail", alert_id=alert.id))


@pages_bp.route("/remediation")
@login_required
def remediation():
    candidates = (
        PatchCandidate.query.join(Device)
        .order_by(PatchCandidate.updated_at.desc(), PatchCandidate.id.desc())
        .limit(100)
        .all()
    )
    return render_template("remediation.html", candidates=candidates)


@pages_bp.post("/remediation/<int:candidate_id>/approve-recommendation")
@login_required
def approve_vendor_recommendation(candidate_id: int):
    if not current_user.is_admin:
        abort(403)
    candidate = db.get_or_404(PatchCandidate, candidate_id)
    if candidate.is_simulated or not candidate.patch_url:
        abort(409, description="Only source-backed recommendations can be approved.")
    if candidate.status != "discovered":
        flash("Only recommendations awaiting review can be approved.", "warning")
        return redirect(url_for("pages.remediation"))

    candidate.status = "approved"
    candidate.approved_by = current_user.username
    candidate.approved_at = datetime.now(UTC).replace(tzinfo=None)
    candidate.verification_note = (
        "Recommendation approved for follow-up only. No firmware or software "
        "was installed, and the source did not establish a verified fixed version."
    )
    db.session.add(
        AuditLog(
            user_id=current_user.id,
            action="recommendation_approved",
            entity_type="patch_candidate",
            entity_id=str(candidate.id),
            details=json.dumps({
                "status": "approved",
                "patch_url": candidate.patch_url,
                "device_updated": False,
            }, sort_keys=True),
        )
    )
    db.session.commit()
    flash(
        "Vendor recommendation approved for follow-up. No update was applied.",
        "success",
    )
    return redirect(url_for("pages.remediation"))


@pages_bp.post("/remediation/<int:candidate_id>/approve")
@login_required
def approve_simulated_patch(candidate_id: int):
    if not current_user.is_admin:
        abort(403)
    candidate = db.get_or_404(PatchCandidate, candidate_id)
    if not candidate.is_simulated:
        abort(409, description="This workflow only supports simulated candidates.")
    if candidate.status != "discovered":
        flash("Only newly discovered simulated candidates can be approved.", "warning")
        return redirect(url_for("pages.remediation"))

    from app.services.patch_service import approve_patch

    approve_patch(candidate.id, approver=current_user.username)
    flash("Simulated approval recorded. No device was updated.", "success")
    return redirect(url_for("pages.remediation"))


@pages_bp.post("/remediation/<int:candidate_id>/verify")
@login_required
def verify_simulated_patch(candidate_id: int):
    if not current_user.is_admin:
        abort(403)
    candidate = db.get_or_404(PatchCandidate, candidate_id)
    if not candidate.is_simulated:
        abort(409, description="This workflow only supports simulated candidates.")
    if candidate.status != "approved":
        flash("Approve the simulated workflow before recording verification.", "warning")
        return redirect(url_for("pages.remediation"))

    from app.services.patch_service import verify_patch

    verify_patch(candidate.id, verifier=current_user.username)
    flash(
        "Simulated verification recorded. This is not evidence of a real patch.",
        "warning",
    )
    return redirect(url_for("pages.remediation"))


@pages_bp.post("/remediation/<int:candidate_id>/reject")
@login_required
def reject_simulated_patch(candidate_id: int):
    if not current_user.is_admin:
        abort(403)
    candidate = db.get_or_404(PatchCandidate, candidate_id)
    if not candidate.is_simulated:
        abort(409, description="This workflow only supports simulated candidates.")
    if candidate.status != "discovered":
        flash("Only newly discovered simulated candidates can be rejected.", "warning")
        return redirect(url_for("pages.remediation"))

    candidate.status = "rejected"
    db.session.add(
        AuditLog(
            user_id=current_user.id,
            action="review_rejected",
            entity_type="patch_candidate",
            entity_id=str(candidate.id),
            details=json.dumps({
                "from": "discovered",
                "to": "rejected",
                "note": (
                    "Simulated candidate rejected during review; no patch "
                    "was applied."
                ),
            }, sort_keys=True),
        )
    )
    db.session.commit()
    flash("Simulated candidate rejected. No device was changed.", "success")
    return redirect(url_for("pages.remediation"))


@pages_bp.post("/devices/<int:device_id>/archive")
@login_required
def archive_device(device_id: int):
    if not current_user.is_admin:
        abort(403)

    device = db.get_or_404(Device, device_id)
    if device.status == ARCHIVED_DEVICE_STATUS:
        flash("Device is already archived.", "warning")
        return redirect(url_for("pages.devices"))

    device.status = ARCHIVED_DEVICE_STATUS
    db.session.commit()
    flash("Device archived. Its scans, findings, and reports were preserved.", "success")
    return redirect(url_for("pages.devices"))


@pages_bp.post("/devices/<int:device_id>/delete")
@login_required
def delete_device(device_id: int):
    if not current_user.is_admin:
        abort(403)

    device = db.get_or_404(Device, device_id)
    if (
        Scan.query.filter_by(device_id=device_id).first()
        or Finding.query.filter_by(device_id=device_id).first()
        or TelemetryReading.query.filter_by(device_id=device_id).first()
    ):
        flash(
            "This device cannot be deleted because it has scan or finding "
            "history, or stored telemetry history.",
            "error",
        )
        return redirect(url_for("pages.devices"))

    db.session.delete(device)
    db.session.commit()
    flash("Device deleted successfully.", "success")
    return redirect(url_for("pages.devices"))


@pages_bp.route("/devices/<int:device_id>")
@login_required
def device_detail(device_id: int):
    device = db.get_or_404(Device, device_id)
    scans = Scan.query.filter_by(device_id=device_id).order_by(Scan.created_at.desc()).all()
    findings = (
        Finding.query.filter_by(device_id=device_id)
        .order_by(Finding.created_at.desc())
        .limit(100)
        .all()
    )
    cve_ids = {finding.cve_id for finding in findings}
    kev_ids = (
        {
            entry.cve_id
            for entry in KEVEntry.query.filter(
                KEVEntry.cve_id.in_(cve_ids),
                KEVEntry.source == CISA_KEV_SOURCE,
            ).all()
        }
        if cve_ids
        else set()
    )
    finding_priorities = {
        finding.id: prioritize_finding(
            finding.severity,
            finding.score
            if finding.score is not None
            else finding.cve.cvss_score if finding.cve is not None else None,
            finding.match_status,
            finding.cve_id in kev_ids,
        )
        for finding in findings
    }
    telemetry = (
        TelemetryReading.query.filter_by(device_id=device_id)
        .order_by(TelemetryReading.received_at.desc(), TelemetryReading.id.desc())
        .limit(12)
        .all()
    )
    alerts_for_device = (
        SecurityAlert.query.filter_by(device_id=device_id)
        .order_by(SecurityAlert.created_at.desc())
        .limit(10)
        .all()
    )
    remediation_items = (
        PatchCandidate.query.filter_by(device_id=device_id)
        .order_by(PatchCandidate.updated_at.desc(), PatchCandidate.id.desc())
        .limit(10)
        .all()
    )
    return render_template(
        "device_detail.html",
        device=device,
        component_scan_device=(
            device.telemetry_device_id
            == current_app.config["TELEMETRY_DEVICE_ID"]
            and device.vendor == current_app.config["TELEMETRY_DEVICE_VENDOR"]
            and device.model == current_app.config["TELEMETRY_DEVICE_MODEL"]
        ),
        scans=scans,
        findings=findings,
        finding_priorities=finding_priorities,
        kev_ids=kev_ids,
        telemetry=telemetry,
        alerts=alerts_for_device,
        remediation_items=remediation_items,
    )


@pages_bp.route("/scans")
@login_required
def scans():
    items = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("scans.html", scans=items)


@pages_bp.route("/scans/new")
@login_required
def scan_new():
    devices = (
        Device.query.filter(
            Device.status.is_distinct_from(ARCHIVED_DEVICE_STATUS),
            Device.telemetry_device_id.is_(None),
        )
        .order_by(Device.name.asc())
        .all()
    )
    component_device = Device.query.filter_by(
        telemetry_device_id=current_app.config["TELEMETRY_DEVICE_ID"],
        vendor=current_app.config["TELEMETRY_DEVICE_VENDOR"],
        model=current_app.config["TELEMETRY_DEVICE_MODEL"],
        status="active",
    ).first()
    return render_template(
        "scan_new.html",
        devices=devices,
        component_device=component_device,
    )


@pages_bp.post("/scans/components")
@login_required
def scan_components():
    if not current_user.is_admin:
        abort(403)
    device = Device.query.filter_by(
        telemetry_device_id=current_app.config["TELEMETRY_DEVICE_ID"],
        vendor=current_app.config["TELEMETRY_DEVICE_VENDOR"],
        model=current_app.config["TELEMETRY_DEVICE_MODEL"],
        status="active",
    ).first()
    if device is None:
        abort(409, description="Register SolarGuard-01 before scanning components.")
    scan = run_component_scan(device.id)
    if scan.status == "completed":
        flash("ESP32 component scan completed.", "success")
    else:
        flash("ESP32 component scan failed; review the scan summary.", "error")
    return redirect(url_for("pages.scan_detail", scan_id=scan.id))


@pages_bp.route("/scans/<int:scan_id>")
@login_required
def scan_detail(scan_id: int):
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        abort(404)
    try:
        scan_evidence = json.loads(scan.notes or "{}")
    except (json.JSONDecodeError, TypeError):
        scan_evidence = {}
    if not isinstance(scan_evidence, dict):
        scan_evidence = {}

    cve_ids = {finding.cve_id for finding in scan.findings}
    kev_sync_log = (
        SyncLog.query.filter_by(source="kev", status="success")
        .order_by(SyncLog.completed_at.desc(), SyncLog.id.desc())
        .first()
    )
    kev_last_sync = kev_sync_log.completed_at if kev_sync_log else None
    kev_sync_age = (
        (datetime.now(UTC).replace(tzinfo=None) - kev_last_sync).total_seconds()
        if kev_last_sync
        else None
    )
    kev_sync_fresh = bool(
        kev_sync_age is not None
        and 0 <= kev_sync_age
        <= current_app.config["INTELLIGENCE_STALE_AFTER_SECONDS"]
    )
    kev_ids = (
        {
            entry.cve_id
            for entry in KEVEntry.query.filter(
                KEVEntry.cve_id.in_(cve_ids),
                KEVEntry.source == CISA_KEV_SOURCE,
            ).all()
        }
        if cve_ids
        else set()
    )
    remediation_by_cve: dict[str, list[PatchCandidate]] = {}
    if cve_ids:
        candidates = PatchCandidate.query.filter(
            PatchCandidate.device_id == scan.device_id,
            PatchCandidate.cve_id.in_(cve_ids),
            PatchCandidate.is_simulated.is_(False),
        ).all()
        for candidate in candidates:
            if candidate.cve_id:
                remediation_by_cve.setdefault(candidate.cve_id, []).append(candidate)

    cvss_metadata = {}
    for finding in scan.findings:
        raw = finding.cve.raw if finding.cve and isinstance(finding.cve.raw, dict) else {}
        metrics = raw.get("metrics") if isinstance(raw, dict) else {}
        if not isinstance(metrics, dict):
            metrics = {}
        for metric_name in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
            metric_list = metrics.get(metric_name)
            if not isinstance(metric_list, list):
                continue
            metric = next(
                (entry for entry in metric_list if isinstance(entry, dict)),
                None,
            )
            if metric is None:
                continue
            cvss_data = metric.get("cvssData")
            cvss_data = cvss_data if isinstance(cvss_data, dict) else {}
            cvss_metadata[finding.id] = {
                "version": cvss_data.get("version") or "version unavailable",
                "source": metric.get("source") or "NVD source not specified",
            }
            break

    return render_template(
        "scan_detail.html",
        scan=scan,
        scan_evidence=scan_evidence,
        kev_ids=kev_ids,
        kev_last_sync=kev_last_sync,
        kev_sync_fresh=kev_sync_fresh,
        remediation_by_cve=remediation_by_cve,
        cvss_metadata=cvss_metadata,
    )


@pages_bp.route("/cves")
@login_required
def cves():
    query_text = request.args.get("q", "").strip()[:120]
    severity_filter = request.args.get("severity", "").strip().upper()
    device_filter = request.args.get("device", "").strip()
    assessment_filter = request.args.get("assessment", "").strip()
    patch_filter = request.args.get("patch", "").strip()
    published_after = request.args.get("published_after", "").strip()
    published_before = request.args.get("published_before", "").strip()

    query = CVE.query
    if query_text:
        search = f"%{query_text}%"
        query = query.filter(CVE.id.ilike(search) | CVE.description.ilike(search))
    if severity_filter in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        query = query.filter(db.func.upper(CVE.severity) == severity_filter)
    else:
        severity_filter = ""
    if device_filter.isdigit():
        query = query.filter(CVE.findings.any(Finding.device_id == int(device_filter)))
    else:
        device_filter = ""
    if assessment_filter == "confirmed":
        query = query.filter(CVE.findings.any(Finding.match_status == "affected"))
    elif assessment_filter == "potential":
        query = query.filter(
            CVE.findings.any(Finding.match_status.in_(("potential", "indeterminate")))
        )
    elif assessment_filter == "unknown":
        query = query.filter(~CVE.findings.any())
    else:
        assessment_filter = ""
    patch_cve_ids = db.session.query(PatchCandidate.cve_id).filter(
        PatchCandidate.cve_id.is_not(None)
    )
    if patch_filter == "candidate":
        query = query.filter(CVE.id.in_(patch_cve_ids))
    elif patch_filter == "none":
        query = query.filter(~CVE.id.in_(patch_cve_ids))
    else:
        patch_filter = ""
    try:
        if published_after:
            after = datetime.strptime(published_after, "%Y-%m-%d")
            query = query.filter(CVE.published_date >= after)
        if published_before:
            before = datetime.strptime(published_before, "%Y-%m-%d")
            query = query.filter(CVE.published_date < before + timedelta(days=1))
    except ValueError:
        flash("Publication dates must use YYYY-MM-DD.", "error")
        published_after = ""
        published_before = ""

    cve_items = (
        query.order_by(CVE.published_date.desc().nullslast(), CVE.id.desc()).limit(100).all()
    )
    cve_ids = [item.id for item in cve_items]
    findings_by_cve = {cve_id: [] for cve_id in cve_ids}
    if cve_ids:
        findings = (
            Finding.query.join(Scan, Finding.scan_id == Scan.id)
            .filter(Finding.cve_id.in_(cve_ids))
            .order_by(Scan.created_at.desc(), Finding.id.desc())
            .all()
        )
        seen_device_cves = set()
        for finding in findings:
            key = (finding.device_id, finding.cve_id)
            if key in seen_device_cves:
                continue
            seen_device_cves.add(key)
            findings_by_cve[finding.cve_id].append(finding)

    latest_sync = (
        SyncLog.query.filter_by(source="nvd", status="success")
        .order_by(SyncLog.completed_at.desc(), SyncLog.id.desc())
        .first()
    )
    latest_sync_attempt = (
        SyncLog.query.filter_by(source="nvd")
        .order_by(SyncLog.started_at.desc(), SyncLog.id.desc())
        .first()
    )
    patch_cve_ids = {
        cve_id
        for (cve_id,) in db.session.query(PatchCandidate.cve_id)
        .filter(PatchCandidate.cve_id.in_(cve_ids or [""]))
        .distinct()
        .all()
    }
    return render_template(
        "cves.html",
        cves=cve_items,
        findings_by_cve=findings_by_cve,
        devices=Device.query.order_by(Device.name.asc()).all(),
        filters={
            "q": query_text,
            "severity": severity_filter,
            "device": device_filter,
            "assessment": assessment_filter,
            "patch": patch_filter,
            "published_after": published_after,
            "published_before": published_before,
        },
        latest_sync=latest_sync,
        latest_sync_attempt=latest_sync_attempt,
        patch_cve_ids=patch_cve_ids,
        total_cves=db.session.query(CVE).count(),
        is_admin=current_user.is_admin,
    )


@pages_bp.post("/cves/sync")
@login_required
def sync_cves():
    if not current_user.is_admin:
        abort(403)
    keyword = request.form.get("keyword", "Espressif ESP32").strip()
    if not keyword or len(keyword) > 120:
        flash("Enter a search phrase of 1 to 120 characters.", "error")
        return redirect(url_for("pages.cves"))
    if not _nvd_sync_lock.acquire(blocking=False):
        flash("An NVD sync is already running in this process.", "warning")
        return redirect(url_for("pages.cves"))

    sync_log_id = None
    try:
        sync_log = SyncLog(
            source="nvd",
            status="running",
            details=f"Keyword: {keyword}",
            records_processed=0,
        )
        db.session.add(sync_log)
        db.session.commit()
        sync_log_id = sync_log.id

        from app.services.nvd_sync_service import sync_nvd_catalog

        count = sync_nvd_catalog(keyword)
        sync_log.status = "success"
        sync_log.records_processed = count
        sync_log.completed_at = datetime.now(UTC).replace(tzinfo=None)
        sync_log.details = f"Keyword: {keyword}; CVE records saved: {count}"
        db.session.commit()
        flash(f"NVD sync completed: {count} CVE records processed.", "success")
    except (requests.RequestException, ValueError, SQLAlchemyError) as error:
        db.session.rollback()
        logger.exception("NVD sync failed for keyword %r", keyword)
        failed_log = db.session.get(SyncLog, sync_log_id) if sync_log_id is not None else None
        if failed_log is not None:
            failed_log.status = "failed"
            failed_log.completed_at = datetime.now(UTC).replace(tzinfo=None)
            failed_log.details = f"Keyword: {keyword}; {type(error).__name__}: {error}"
            db.session.commit()
        flash(
            "NVD sync failed. Check network access and application logs; "
            "existing CVE data was preserved.",
            "error",
        )
    finally:
        _nvd_sync_lock.release()
    return redirect(url_for("pages.cves"))


@pages_bp.route("/cves/<cve_id>")
@login_required
def cve_detail(cve_id: str):
    return render_template("cve_detail.html", cve_id=cve_id)


@pages_bp.route("/reports")
@login_required
def reports():
    items = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("reports.html", scans=items)


@pages_bp.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


@pages_bp.route("/admin/users")
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    users = User.query.order_by(User.username.asc()).all()
    return render_template("admin_users.html", users=users)
