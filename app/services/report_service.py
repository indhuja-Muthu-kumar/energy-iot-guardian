
from __future__ import annotations

import csv
import io

from app.models.device import Device
from app.models.finding import Finding


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


def _spreadsheet_safe(value):
    if isinstance(value, str) and (
        value.startswith(("\t", "\r"))
        or value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@"))
    ):
        return f"'{value}"
    return value
