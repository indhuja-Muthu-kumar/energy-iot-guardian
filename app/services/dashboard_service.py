from __future__ import annotations

from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models.alert import SecurityAlert
from app.models.cve import CVE
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.models.finding import Finding
from app.models.patch import PatchCandidate
from app.models.scan import Scan
from app.models.sync_log import SyncLog
from app.models.telemetry import TelemetryReading
from app.services.matcher import assess_cpe_match

SEVERITIES = ("critical", "high", "medium", "low")
POTENTIAL_MATCH_METHODS = (
    "nvd-vendor-model-keyword",
    "nvd-cpe-product-potential",
    "nvd-cpe-logic-indeterminate",
)


def build_vulnerability_summary(include_device_summaries: bool = False) -> dict:
    devices = Device.query.order_by(Device.id.asc()).all()
    scans = Scan.query.order_by(Scan.created_at.desc(), Scan.id.desc()).all()

    latest_scan_by_device = {}
    for scan in scans:
        latest_scan_by_device.setdefault(scan.device_id, scan)

    latest_scans = list(latest_scan_by_device.values())
    completed_scan_ids = [
        scan.id for scan in latest_scans if scan.status == "completed"
    ]
    summary = {
        "severity": {
            severity: {"evaluated": 0, "potential": 0}
            for severity in SEVERITIES
        },
        "unknown_severity": {"evaluated": 0, "potential": 0},
        "device_count": len(devices),
        "devices_with_completed_latest_scan": len(completed_scan_ids),
        "devices_with_failed_latest_scan": sum(
            scan.status == "failed" for scan in latest_scans
        ),
        "devices_with_incomplete_latest_scan": sum(
            scan.status not in {"completed", "failed"} for scan in latest_scans
        ),
        "devices_without_scans": sum(
            device.id not in latest_scan_by_device for device in devices
        ),
    }
    if include_device_summaries:
        summary["device_summaries"] = {
            device.id: {
                "id": device.id,
                "name": device.name,
                "vendor": device.vendor,
                "model": device.model,
                "severity": {
                    severity: {"evaluated": 0, "potential": 0}
                    for severity in SEVERITIES
                },
                "unknown_severity": {"evaluated": 0, "potential": 0},
            }
            for device in devices
        }
    if not completed_scan_ids:
        return summary

    rows = (
        db.session.query(
            Scan.device_id,
            Scan.scan_type,
            Finding.component_name,
            Finding.matched_by,
            Finding.cve_id,
            Finding.match_status,
            CVE.severity,
            CVE.raw,
            Device,
        )
        .join(Finding, Finding.scan_id == Scan.id)
        .outerjoin(CVE, CVE.id == Finding.cve_id)
        .join(Device, Device.id == Scan.device_id)
        .filter(
            Scan.id.in_(completed_scan_ids),
            Finding.device_id == Scan.device_id,
        )
        .all()
    )

    findings_by_device_cve = {}
    for (
        device_id,
        scan_type,
        finding_component_name,
        matched_by,
        cve_id,
        finding_match_status,
        cve_severity,
        cve_data,
        device,
    ) in rows:
        if scan_type == "components":
            if finding_match_status == "not_applicable":
                continue
            evaluated = finding_match_status == "affected"
        elif (
            finding_component_name
            and finding_component_name != device.model
            and isinstance(matched_by, str)
            and matched_by.startswith("nvd-cpe")
        ):
            if finding_match_status in {"not_affected", "not_applicable"}:
                continue
            evaluated = finding_match_status == "affected"
        else:
            assessment = (
                assess_cpe_match(device, cve_data)
                if isinstance(cve_data, dict)
                else None
            )
            if assessment is not None and assessment[0] == "not_affected":
                continue
            evaluated = assessment is not None and assessment[0] == "affected"
        key = (device_id, cve_id)
        severity = (
            cve_severity.strip().casefold()
            if isinstance(cve_severity, str) and cve_severity.strip()
            else None
        )
        record = findings_by_device_cve.setdefault(
            key,
            {
                "device_id": device_id,
                "evaluated": evaluated,
                "severity": severity,
            },
        )
        if not evaluated:
            record["evaluated"] = False

    for record in findings_by_device_cve.values():
        match_type = "evaluated" if record["evaluated"] else "potential"
        bucket = summary["severity"].get(record["severity"])
        if bucket is None:
            bucket = summary["unknown_severity"]
        bucket[match_type] += 1
        if include_device_summaries:
            device_summary = summary["device_summaries"][record["device_id"]]
            device_bucket = device_summary["severity"].get(record["severity"])
            if device_bucket is None:
                device_bucket = device_summary["unknown_severity"]
            device_bucket[match_type] += 1

    return summary


def build_dashboard_panels(recent_limit: int = 6) -> dict:
    recent_scans = (
        Scan.query.options(joinedload(Scan.device))
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(recent_limit)
        .all()
    )
    scan_ids = [scan.id for scan in recent_scans]
    potential_counts = {}
    if scan_ids:
        potential_counts = dict(
            db.session.query(
                Finding.scan_id,
                func.count(func.distinct(Finding.cve_id)),
            )
            .join(Scan, Scan.id == Finding.scan_id)
            .filter(
                Finding.scan_id.in_(scan_ids),
                Finding.device_id == Scan.device_id,
                Finding.matched_by.in_(POTENTIAL_MATCH_METHODS),
            )
            .group_by(Finding.scan_id)
            .all()
        )

    scans_with_counts = [
        {
            "scan": scan,
            "potential_findings": potential_counts.get(scan.id, 0),
        }
        for scan in recent_scans
    ]
    trend_points = [
        {
            "label": (
                scan.created_at.strftime("%b %d")
                if scan.created_at
                else f"#{scan.id}"
            ),
            "potential": potential_counts.get(scan.id, 0),
        }
        for scan in reversed(recent_scans)
        if scan.status == "completed"
    ]
    devices = (
        Device.query.filter(
            Device.status.is_distinct_from(ARCHIVED_DEVICE_STATUS)
        )
        .order_by(Device.name.asc())
        .limit(5)
        .all()
    )

    return {
        "recent_scans": scans_with_counts,
        "trend_points": trend_points,
        "devices": devices,
    }


def build_recent_activity(limit: int = 6) -> list[dict]:
    events = []

    def add_event(
        *,
        kind: str,
        record_id: int,
        title: str,
        detail: str,
        status: str,
        timestamp: datetime | None,
        device_id: int | None = None,
    ) -> None:
        events.append({
            "kind": kind,
            "record_id": record_id,
            "title": title,
            "detail": detail,
            "status": status,
            "timestamp": timestamp,
            "device_id": device_id,
        })

    for scan in (
        Scan.query.options(joinedload(Scan.device))
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(limit)
    ):
        device_name = scan.device.name if scan.device else "Unknown device"
        add_event(
            kind="scan",
            record_id=scan.id,
            title=f"{scan.scan_type.replace('_', ' ').title()} scan",
            detail=f"{device_name} · scan #{scan.id}",
            status=scan.status,
            timestamp=scan.completed_at or scan.created_at or scan.started_at,
            device_id=scan.device_id,
        )

    for sync in (
        SyncLog.query.filter(SyncLog.source.in_(("nvd", "kev")))
        .order_by(SyncLog.started_at.desc(), SyncLog.id.desc())
        .limit(limit)
    ):
        source_name = "CISA KEV" if sync.source == "kev" else "NVD CVE"
        detail = (
            f"{sync.records_processed or 0} records processed"
            if sync.status == "success"
            else "No successful update recorded"
        )
        add_event(
            kind="sync",
            record_id=sync.id,
            title=f"{source_name} sync",
            detail=detail,
            status=sync.status,
            timestamp=sync.completed_at or sync.started_at,
        )

    for reading in (
        TelemetryReading.query.options(joinedload(TelemetryReading.device))
        .order_by(TelemetryReading.received_at.desc(), TelemetryReading.id.desc())
        .limit(limit)
    ):
        device_name = reading.device.name if reading.device else "Unknown device"
        simulated = reading.telemetry_status.upper() == "SIMULATED"
        add_event(
            kind="telemetry",
            record_id=reading.id,
            title="Simulated telemetry received" if simulated else "Telemetry received",
            detail=(
                f"{device_name} · {reading.ingest_source.replace('_', ' ').title()}"
            ),
            status=reading.telemetry_status,
            timestamp=reading.received_at,
            device_id=reading.device_id,
        )

    for alert in (
        SecurityAlert.query.options(joinedload(SecurityAlert.device))
        .order_by(SecurityAlert.created_at.desc(), SecurityAlert.id.desc())
        .limit(limit)
    ):
        device_name = alert.device.name if alert.device else "Unknown device"
        detail = f"{alert.severity.title()} · {device_name}"
        if alert.cve_id:
            detail = f"{detail} · {alert.cve_id}"
        add_event(
            kind="alert",
            record_id=alert.id,
            title=alert.title,
            detail=detail,
            status=alert.status,
            timestamp=alert.created_at,
            device_id=alert.device_id,
        )

    for candidate in (
        PatchCandidate.query.options(joinedload(PatchCandidate.device))
        .order_by(
            PatchCandidate.updated_at.desc(),
            PatchCandidate.id.desc(),
        )
        .limit(limit)
    ):
        device_name = candidate.device.name if candidate.device else "Unknown device"
        simulation_label = "SIMULATED" if candidate.is_simulated else "Recorded candidate"
        cve_label = f" · {candidate.cve_id}" if candidate.cve_id else ""
        add_event(
            kind="remediation",
            record_id=candidate.id,
            title=f"{simulation_label} remediation",
            detail=f"{device_name} · {candidate.component_name}{cve_label}",
            status=candidate.status,
            timestamp=candidate.updated_at or candidate.created_at,
            device_id=candidate.device_id,
        )

    events.sort(
        key=lambda event: event["timestamp"] or datetime.min,
        reverse=True,
    )
    return events[:limit]
