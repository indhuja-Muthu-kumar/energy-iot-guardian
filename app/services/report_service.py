
from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from app.extensions import db
from app.models.alert import SecurityAlert
from app.models.audit import AuditLog
from app.models.device import Device
from app.models.device_component import DeviceComponent
from app.models.finding import Finding
from app.models.kev import CISA_KEV_SOURCE, KEVEntry
from app.models.patch import PatchCandidate
from app.models.sync_log import SyncLog
from app.models.telemetry import TelemetryReading
from app.services.risk_service import prioritize_finding


def build_report_rows(
    device_id: int | None = None,
    scan_id: int | None = None,
):
    rows = []
    query = Finding.query.join(Device)

    if device_id is not None:
        query = query.filter(Finding.device_id == device_id)

    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)

    for finding in query.order_by(Finding.created_at.desc()).all():
        rows.append({
            "device": finding.device.name,
            "vendor": finding.device.vendor,
            "model": finding.device.model,
            "cve_id": finding.cve_id,
            "severity": finding.severity,
            "score": finding.score,
            "cvss_vector": finding.cve.cvss_vector if finding.cve else None,
            "source": finding.cve.source if finding.cve else "unknown",
            "component": finding.component_name,
            "component_version": finding.component_version,
            "confidence": finding.confidence,
            "match_status": {
                "nvd-cpe-not-applicable": (
                    "Not applicable by evaluated NVD CPE/version data"
                ),
                "nvd-vendor-model-keyword": "Potential keyword match",
                "nvd-cpe-product-potential": "Potential NVD CPE product match",
                "nvd-cpe-logic-indeterminate": (
                    "Indeterminate NVD CPE configuration match"
                ),
                "nvd-cpe-version-range": (
                    "NVD CPE/version match (device not independently verified)"
                ),
            }.get(finding.matched_by, finding.matched_by or "Unknown"),
            "evidence": finding.evidence,
            "summary": finding.summary,
        })

    return rows


def export_csv(
    device_id: int | None = None,
    scan_id: int | None = None,
) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "device", "vendor", "model", "cve_id",
            "severity", "score", "match_status", "evidence", "summary",
            "cvss_vector", "source", "component", "component_version", "confidence",
        ],
    )
    writer.writeheader()

    for row in build_report_rows(device_id, scan_id):
        writer.writerow({
            key: _spreadsheet_safe(value) for key, value in row.items()
        })

    return buffer.getvalue()


def export_full_csv() -> str:
    generated_at = datetime.now(UTC).isoformat()
    fieldnames = [
        "record_type",
        "generated_at",
        "device_id",
        "device",
        "vendor",
        "model",
        "simulation_status",
        "component_name",
        "firmware_version",
        "firmware_status",
        "firmware_confidence",
        "firmware_evidence_source",
        "firmware_evidence_method",
        "firmware_evidence_note",
        "timestamp",
        "message_id",
        "voltage",
        "current",
        "power",
        "telemetry_source",
        "alert_id",
        "alert_category",
        "severity",
        "cvss_score",
        "cvss_vector",
        "contextual_priority",
        "status",
        "cve_id",
        "kev_status",
        "match_status",
        "confidence",
        "source",
        "evidence",
        "recommended_action",
        "target",
        "actor",
        "details",
        "limitations",
    ]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()

    def write_row(**values) -> None:
        row = {
            "generated_at": generated_at,
            **values,
        }
        writer.writerow(
            {key: _spreadsheet_safe(value) for key, value in row.items()}
        )

    for device in Device.query.order_by(Device.id.asc()).all():
        write_row(
            record_type="device",
            device_id=device.id,
            device=device.name,
            vendor=device.vendor,
            model=device.model,
            simulation_status=device.simulation_status,
            firmware_version=device.firmware_version or (
                device.firmware if device.firmware.lower() != "unknown" else None
            ),
            firmware_status=device.firmware_verification_status,
            firmware_confidence=device.firmware_confidence,
            firmware_evidence_source=device.firmware_evidence_source,
            firmware_evidence_method=device.firmware_evidence_method,
            firmware_evidence_note=device.firmware_evidence_note,
            timestamp=device.firmware_evidence_collected_at,
            status=device.status,
            limitations=(
                "Firmware is reported unless separately evidenced as verified; "
                "ESP32 runtime does not verify product firmware."
            ),
        )

    for component in DeviceComponent.query.order_by(
        DeviceComponent.device_id.asc(),
        DeviceComponent.component_key.asc(),
    ).all():
        device = component.device
        write_row(
            record_type="component_evidence",
            device_id=component.device_id,
            device=device.name if device else None,
            vendor=device.vendor if device else component.vendor,
            model=device.model if device else component.product,
            simulation_status=device.simulation_status if device else "unknown",
            component_name=component.name,
            firmware_version=component.version,
            firmware_status=component.evidence_status,
            firmware_confidence=component.confidence,
            firmware_evidence_source=component.evidence_source,
            firmware_evidence_method=component.evidence_method,
            firmware_evidence_note=component.evidence_note,
            timestamp=component.collected_at,
            source=component.evidence_source,
            status=component.evidence_status,
            evidence=component.evidence_note,
            limitations=(
                "A manufacturer reference does not prove installed identity or "
                "version. Only VERIFIED component version evidence is used for "
                "CPE version assessment."
            ),
        )

    for reading in TelemetryReading.query.order_by(
        TelemetryReading.received_at.desc(),
        TelemetryReading.id.desc(),
    ).all():
        write_row(
            record_type="telemetry",
            device_id=reading.device_id,
            device=reading.device.name if reading.device else None,
            vendor=reading.device.vendor if reading.device else None,
            model=reading.device.model if reading.device else None,
            timestamp=reading.received_at,
            message_id=reading.source_message_id,
            voltage=reading.voltage,
            current=reading.current,
            power=reading.power,
            telemetry_source=reading.ingest_source,
            status=reading.telemetry_status,
            limitations=(
                "Telemetry is labeled simulated and does not prove physical "
                "equipment measurements."
                if reading.telemetry_status == "SIMULATED"
                else None
            ),
        )

    for finding in Finding.query.order_by(Finding.created_at.desc()).all():
        device = finding.device
        cve = finding.cve
        kev_listed = (
            db.session.query(KEVEntry.id)
            .filter_by(cve_id=finding.cve_id, source=CISA_KEV_SOURCE)
            .first()
            is not None
        )
        priority = prioritize_finding(
            finding.severity,
            finding.score if finding.score is not None else (
                cve.cvss_score if cve else None
            ),
            finding.match_status,
            kev_listed,
        )
        write_row(
            record_type="finding",
            device_id=finding.device_id,
            device=device.name if device else None,
            vendor=device.vendor if device else None,
            model=device.model if device else None,
            timestamp=finding.created_at,
            cve_id=finding.cve_id,
            severity=finding.severity,
            cvss_score=finding.score if finding.score is not None else (
                cve.cvss_score if cve else None
            ),
            cvss_vector=cve.cvss_vector if cve else None,
            contextual_priority=priority["priority"],
            kev_status=(
                "Listed in stored catalog"
                if kev_listed
                else "Not listed in stored catalog; freshness may be unknown"
            ),
            match_status=finding.match_status,
            confidence=finding.confidence,
            source=cve.source if cve else "unknown",
            evidence=finding.evidence or finding.summary,
            status=finding.status,
            limitations=priority["reason"],
        )

    for alert in SecurityAlert.query.order_by(
        SecurityAlert.created_at.desc(),
        SecurityAlert.id.desc(),
    ).all():
        write_row(
            record_type="alert",
            device_id=alert.device_id,
            device=alert.device.name if alert.device else None,
            alert_id=alert.id,
            alert_category=alert.alert_type,
            severity=alert.severity,
            cve_id=alert.cve_id,
            status=alert.status,
            source=alert.source,
            evidence=alert.summary,
            timestamp=alert.updated_at or alert.created_at,
            limitations=(
                "Alert workflow status is not proof of remediation or device security."
            ),
        )

    for candidate in PatchCandidate.query.order_by(
        PatchCandidate.updated_at.desc(),
        PatchCandidate.id.desc(),
    ).all():
        write_row(
            record_type="remediation",
            device_id=candidate.device_id,
            device=candidate.device.name if candidate.device else None,
            cve_id=candidate.cve_id,
            status=candidate.status,
            source=candidate.patch_source,
            evidence=candidate.evidence,
            recommended_action=candidate.evidence,
            target=candidate.recommended_version,
            timestamp=candidate.updated_at,
            details=candidate.patch_url,
            limitations=(
                "Simulated workflow record; it does not update or verify a real device."
                if candidate.is_simulated
                else None
            ),
        )

    for sync in SyncLog.query.order_by(
        SyncLog.started_at.desc(),
        SyncLog.id.desc(),
    ).all():
        write_row(
            record_type="intelligence_sync",
            source=sync.source,
            status=sync.status,
            timestamp=sync.completed_at or sync.started_at,
            details=sync.details,
            evidence=f"Records processed: {sync.records_processed or 0}",
        )

    for event in AuditLog.query.order_by(
        AuditLog.created_at.desc(),
        AuditLog.id.desc(),
    ).all():
        write_row(
            record_type="audit_event",
            timestamp=event.created_at,
            source=event.action,
            target=f"{event.entity_type}:{event.entity_id or ''}",
            actor=event.user.username if event.user else "System",
            details=event.details,
        )

    write_row(
        record_type="report_limitations",
        limitations=(
            "Verification history is not implemented. KEV absence reflects only "
            "the locally stored catalog; its freshness may be unknown. "
            "Telemetry for SolarGuard-01 is simulated."
        ),
    )
    return buffer.getvalue()


def _spreadsheet_safe(value):
    if isinstance(value, datetime):
        value = value.isoformat()
    if isinstance(value, str) and (
        value.startswith(("\t", "\r"))
        or value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@"))
    ):
        return f"'{value}"
    return value
