from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    url_for,
)
from flask_login import current_user, login_required

from app.extensions import db
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.models.finding import Finding
from app.models.kev import KEVEntry
from app.models.scan import Scan
from app.models.telemetry import TelemetryReading
from app.models.user import User
from app.services.dashboard_service import (
    build_dashboard_panels,
    build_vulnerability_summary,
)
from app.services.component_scan_service import run_component_scan

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/")
def landing():
    return render_template("landing.html")


@pages_bp.route("/dashboard")
@login_required
def dashboard():
    device_count = db.session.query(Device).count()
    scan_count = db.session.query(Scan).count()
    finding_count = db.session.query(Finding).count()
    kev_count = db.session.query(KEVEntry).count()
    vulnerability_summary = build_vulnerability_summary(
        include_device_summaries=True
    )
    dashboard_panels = build_dashboard_panels()
    dashboard_panels["risk_devices"] = sorted(
        (
            item for item in vulnerability_summary["device_summaries"].values()
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
        vulnerability_summary=vulnerability_summary,
        dashboard_panels=dashboard_panels,
    )


@pages_bp.route("/devices")
@login_required
def devices():
    items = (
        Device.query.filter(
            Device.status.is_distinct_from(ARCHIVED_DEVICE_STATUS)
        )
        .order_by(Device.name.asc())
        .all()
    )
    return render_template("devices.html", devices=items)


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
    scans = (
        Scan.query.filter_by(device_id=device_id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    findings = (
        Finding.query.filter_by(device_id=device_id)
        .order_by(Finding.created_at.desc())
        .all()
    )
    return render_template("device_detail.html", device=device, scans=scans, findings=findings)


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
            Device.name != current_app.config["TELEMETRY_DEVICE_ID"],
        )
        .order_by(Device.name.asc())
        .all()
    )
    component_device = Device.query.filter_by(
        name=current_app.config["TELEMETRY_DEVICE_ID"],
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
        name=current_app.config["TELEMETRY_DEVICE_ID"],
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
    return render_template("scan_detail.html", scan=scan)


@pages_bp.route("/cves")
@login_required
def cves():
    return render_template("cves.html")


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
