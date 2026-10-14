from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from types import SimpleNamespace

import requests
from flask import abort, current_app

from app.extensions import db
from app.models.cve import CVE
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.telemetry import TelemetryReading
from app.services.matcher import assess_cpe_match
from app.services.nvd_client import NVDClient
from app.services.scan_service import (
    _cwe,
    _cvss_details,
    _cvss_vector,
    _nvd_datetime,
)

logger = logging.getLogger(__name__)
PAGE_SIZE = 100
VERSION_PATTERN = re.compile(
    r"[vV]?\d+(?:\.\d+)*"
)
CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
COMPONENTS = (
    {
        "name": "ESP-IDF",
        "runtime_key": "esp_idf_version",
        "search_product": "ESP-IDF",
        "product_tokens": {"espidf"},
        "title_tokens": {"espidf"},
    },
    {
        "name": "Arduino ESP32 core",
        "runtime_key": "arduino_core_version",
        "search_product": "Arduino ESP32",
        "product_tokens": {"arduinoesp32", "esp32arduino"},
        "title_tokens": {"arduino", "esp32"},
    },
)
NVD_VENDOR = "espressif"


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _resolve_cpe(client: NVDClient, component: dict) -> str | None:
    page_size = 100
    response = client.fetch_cpe(
        "Espressif",
        component["search_product"],
        results_per_page=page_size,
        start_index=0,
    )
    products = response.get("products") if isinstance(response, dict) else None
    total_results = response.get("totalResults") if isinstance(response, dict) else None
    if (
        not isinstance(products, list)
        or not isinstance(total_results, int)
        or isinstance(total_results, bool)
        or total_results < 0
        or len(products) != min(page_size, total_results)
    ):
        raise ValueError("NVD CPE response did not contain a complete product page.")

    all_products = list(products)
    while len(all_products) < total_results:
        start_index = len(all_products)
        page = client.fetch_cpe(
            "Espressif",
            component["search_product"],
            results_per_page=page_size,
            start_index=start_index,
        )
        page_products = page.get("products") if isinstance(page, dict) else None
        page_total = page.get("totalResults") if isinstance(page, dict) else None
        if (
            not isinstance(page_products, list)
            or page_total != total_results
            or len(page_products) != min(page_size, total_results - start_index)
        ):
            raise ValueError("NVD CPE response did not contain a complete product page.")
        all_products.extend(page_products)

    for entry in all_products:
        cpe = entry.get("cpe") if isinstance(entry, dict) else None
        cpe_name = cpe.get("cpeName") if isinstance(cpe, dict) else None
        if not isinstance(cpe_name, str):
            continue
        fields = cpe_name.split(":")
        if (
            len(fields) != 13
            or fields[:3] != ["cpe", "2.3", "a"]
            or _normalize(fields[3]) != NVD_VENDOR
            or _normalize(fields[4]) not in component["product_tokens"]
            or fields[5] == "-"
        ):
            continue
        titles = cpe.get("titles") or []
        title_text = " ".join(
            title.get("title", "").lower()
            for title in titles
            if isinstance(title, dict) and isinstance(title.get("title"), str)
        )
        normalized_title = _normalize(title_text)
        if not all(token in normalized_title for token in component["title_tokens"]):
            continue
        return cpe_name
    return None


def _fetch_cves_by_cpe(client: NVDClient, cpe_name: str) -> list[dict]:
    payload = client.fetch_cves_by_cpe(
        cpe_name,
        page_size=PAGE_SIZE,
        start_index=0,
    )
    if not isinstance(payload, dict):
        raise ValueError("NVD response was not a JSON object.")
    vulnerabilities = payload.get("vulnerabilities")
    total_results = payload.get("totalResults")
    if (
        not isinstance(vulnerabilities, list)
        or not isinstance(total_results, int)
        or isinstance(total_results, bool)
        or total_results < 0
        or len(vulnerabilities) != min(PAGE_SIZE, total_results)
    ):
        raise ValueError("NVD response did not contain a complete CVE page.")

    all_vulnerabilities = list(vulnerabilities)
    while len(all_vulnerabilities) < total_results:
        start_index = len(all_vulnerabilities)
        page = client.fetch_cves_by_cpe(
            cpe_name,
            page_size=PAGE_SIZE,
            start_index=start_index,
        )
        page_items = page.get("vulnerabilities") if isinstance(page, dict) else None
        page_total = page.get("totalResults") if isinstance(page, dict) else None
        expected_size = min(PAGE_SIZE, total_results - start_index)
        if (
            not isinstance(page_items, list)
            or page_total != total_results
            or len(page_items) != expected_size
        ):
            raise ValueError("NVD response did not contain a complete CVE page.")
        all_vulnerabilities.extend(page_items)
    return all_vulnerabilities


def _versioned_cpe(cpe_name: str, version: str) -> str:
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError(f"Unsupported runtime version string: {version!r}")
    fields = cpe_name.split(":")
    fields[5] = version.lstrip("vV")
    return ":".join(fields)


def run_component_scan(
    device_id: int,
    client: NVDClient | None = None,
) -> Scan:
    device = db.session.get(Device, device_id)
    if device is None:
        abort(404)
    if (
        device.name != current_app.config["TELEMETRY_DEVICE_ID"]
        or device.vendor != current_app.config["TELEMETRY_DEVICE_VENDOR"]
        or device.model != current_app.config["TELEMETRY_DEVICE_MODEL"]
    ):
        abort(400, description="Component scans are only supported for SolarGuard-01.")
    if device.status == ARCHIVED_DEVICE_STATUS:
        abort(409, description="Archived devices cannot be scanned.")
    latest = (
        TelemetryReading.query.filter_by(device_id=device.id)
        .order_by(TelemetryReading.received_at.desc(), TelemetryReading.id.desc())
        .first()
    )
    if latest is None:
        abort(409, description="No ESP32 runtime inventory has been received yet.")

    scan = Scan(
        device_id=device.id,
        scan_type="components",
        status="running",
        started_at=datetime.now(UTC).replace(tzinfo=None),
        summary="Checking reported ESP32 software components against NVD CPE data.",
    )
    db.session.add(scan)
    db.session.commit()
    scan_id = scan.id

    try:
        nvd = client or NVDClient()
        findings = []
        pending_cves = {}
        assessed_components = 0
        incomplete_components = []

        runtime = {
            "esp_idf_version": latest.esp_idf_version,
            "arduino_core_version": latest.arduino_core_version,
        }
        for component in COMPONENTS:
            version = runtime[component["runtime_key"]]
            if not VERSION_PATTERN.fullmatch(version):
                incomplete_components.append(
                    f"{component['name']}: unsupported reported version format"
                )
                continue
            base_cpe = _resolve_cpe(nvd, component)
            if base_cpe is None:
                incomplete_components.append(
                    f"{component['name']}: no exact NVD CPE product mapping found"
                )
                continue
            assessed_components += 1
            exact_cpe = _versioned_cpe(base_cpe, version)
            component_target = SimpleNamespace(
                vendor=NVD_VENDOR,
                model=base_cpe.split(":")[4],
                firmware=version,
                firmware_version=version,
            )
            vulnerabilities = _fetch_cves_by_cpe(nvd, exact_cpe)
            for item in vulnerabilities:
                cve_data = item.get("cve") if isinstance(item, dict) else None
                cve_id = cve_data.get("id") if isinstance(cve_data, dict) else None
                if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
                    continue
                cve_id = cve_id.upper()
                assessment = assess_cpe_match(component_target, cve_data)
                if assessment is None:
                    match_status = "potential"
                    evidence = (
                        "NVD returned this CVE for the exact reported CPE/version "
                        "query, but it did not provide an evaluable applicability "
                        "configuration. Treat this as a potential match only."
                    )
                else:
                    match_status, evidence = assessment
                descriptions = cve_data.get("descriptions") or []
                description = next(
                    (
                        entry["value"]
                        for entry in descriptions
                        if isinstance(entry, dict)
                        and entry.get("lang") == "en"
                        and isinstance(entry.get("value"), str)
                    ),
                    "",
                )
                score, severity, attack_vector = _cvss_details(cve_data)
                cve = pending_cves.get(cve_id) or db.session.get(CVE, cve_id)
                if cve is None:
                    cve = CVE(id=cve_id)
                cve.description = description
                cve.published_date = _nvd_datetime(cve_data.get("published"))
                cve.last_modified_date = _nvd_datetime(cve_data.get("lastModified"))
                cve.severity = severity
                cve.cvss_score = score
                cve.cvss_vector = _cvss_vector(cve_data)
                cve.attack_vector = attack_vector
                cve.cwe = _cwe(cve_data)
                cve.source = "nvd"
                cve.raw = cve_data
                pending_cves[cve_id] = cve
                stored_status = {
                    "affected": "affected",
                    "potential": "potential",
                    "indeterminate": "indeterminate",
                    "not_affected": "not_applicable",
                }.get(match_status, "indeterminate")
                matched_by = {
                    "affected": "nvd-cpe-version-range",
                    "potential": "nvd-cpe-product-potential",
                    "indeterminate": "nvd-cpe-logic-indeterminate",
                    "not_affected": "nvd-cpe-not-applicable",
                }.get(match_status, "nvd-cpe-logic-indeterminate")
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        device_id=device.id,
                        cve_id=cve_id,
                        severity=severity or "unknown",
                        score=score,
                        summary=description,
                        evidence=_component_evidence(
                            evidence,
                            component["name"],
                            version,
                        ),
                        matched_by=matched_by,
                        component_name=component["name"],
                        component_version=version,
                        match_status=stored_status,
                        confidence=(
                            "high" if stored_status in {"affected", "not_applicable"}
                            else "low"
                        ),
                    )
                )

        for cve in pending_cves.values():
            db.session.add(cve)
        db.session.add_all(findings)
        scan.status = "completed"
        affected = sum(item.match_status == "affected" for item in findings)
        potential = sum(
            item.match_status in {"potential", "indeterminate"} for item in findings
        )
        not_applicable = sum(
            item.match_status == "not_applicable" for item in findings
        )
        incomplete_summary = (
            " Component inventory incomplete: "
            + "; ".join(incomplete_components)
            + "."
            if incomplete_components
            else ""
        )
        scan.summary = (
            f"Assessed {assessed_components} reported ESP32 component(s): "
            f"{affected} NVD affected-version match(es), {potential} potential or "
            f"indeterminate result(s), and {not_applicable} not-applicable result(s)."
            f"{incomplete_summary} Results rely on reported simulated runtime "
            "versions and NVD CPE applicability data; exploitability is not confirmed."
        )
        scan.completed_at = datetime.now(UTC).replace(tzinfo=None)
        db.session.commit()
    except (requests.RequestException, ValueError):
        logger.exception("NVD component scan failed for SolarGuard device %s", device.id)
        db.session.rollback()
        scan = db.session.get(Scan, scan_id)
        scan.status = "failed"
        scan.summary = (
            "NVD component data could not be validated or retrieved. "
            "No partial findings were saved."
        )
        scan.completed_at = datetime.now(UTC).replace(tzinfo=None)
        db.session.commit()
    except Exception:
        logger.exception("Unexpected component scan failure for device %s", device.id)
        db.session.rollback()
        scan = db.session.get(Scan, scan_id)
        scan.status = "failed"
        scan.summary = "An internal error interrupted the component scan."
        scan.completed_at = datetime.now(UTC).replace(tzinfo=None)
        db.session.commit()
    return db.session.get(Scan, scan_id)


def _component_evidence(evidence: str, name: str, version: str) -> str:
    component_evidence = (
        evidence.replace("device-product", "component-product")
        .replace("device product", "component product")
        .replace("Device identity", "Runtime component identity")
        .replace("device identity", "runtime component identity")
        .replace("Firmware", "Reported component version")
        .replace("firmware", "reported component version")
    )
    return (
        f"Reported {name} version {version}. "
        f"NVD CPE component/version assessment: {component_evidence}"
    )
