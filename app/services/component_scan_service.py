from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from types import SimpleNamespace

import requests
from flask import abort, current_app

from app.extensions import db
from app.models.cve import CVE
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.models.device_component import DeviceComponent
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.telemetry import TelemetryReading
from app.services.matcher import assess_cpe_match
from app.services.nvd_client import NVDClient
from app.services.scan_service import (
    _cwe,
    _cvss_details,
    _cvss_vector,
    _fetch_all_cves,
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
        "component_key": "esp_idf_runtime",
        "runtime_key": "esp_idf_version",
        "search_product": "ESP-IDF",
        "product_tokens": {"espidf"},
        "title_tokens": {"espidf"},
        "vendor": "Espressif",
        "product": "ESP-IDF (runtime-reported version)",
    },
    {
        "name": "Arduino ESP32 core",
        "component_key": "arduino_esp32_core",
        "runtime_key": "arduino_core_version",
        "search_product": "Arduino ESP32",
        "product_tokens": {"arduinoesp32", "esp32arduino"},
        "title_tokens": {"arduino", "esp32"},
        "vendor": "Espressif",
        "product": "Arduino-ESP32 core (runtime-reported version)",
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
        device.telemetry_device_id != current_app.config["TELEMETRY_DEVICE_ID"]
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
        component_states = []
        processed_finding_keys: set[tuple[str, str]] = set()
        runtime_keys = {
            component["component_key"] for component in COMPONENTS
        }

        runtime = {
            "esp_idf_version": latest.esp_idf_version,
            "arduino_core_version": latest.arduino_core_version,
        }
        for saved_component in device.components:
            if saved_component.component_key in runtime_keys:
                continue
            if saved_component.component_type == "software":
                reason = (
                    "Software dependency not assessed: an installed version "
                    "and exact NVD CPE are not established. "
                    f"{saved_component.evidence_note}"
                )
            else:
                reason = (
                    "This hardware identity or reference item is not an "
                    "installed software version assessed by the component scan."
                )
            component_states.append(
                {
                    "component": saved_component.name,
                    "version": saved_component.version,
                    "evidence_status": saved_component.evidence_status,
                    "assessment": "not_assessed",
                    "reason": reason,
                    "evidence_source": saved_component.evidence_source,
                    "evidence_note": saved_component.evidence_note,
                }
            )

        for component in COMPONENTS:
            raw_version = runtime[component["runtime_key"]]
            version = raw_version.strip() if isinstance(raw_version, str) else ""
            source = (
                f"MQTT topic {current_app.config['TELEMETRY_MQTT_TOPIC']} "
                f"(message {latest.source_message_id})"
            )
            has_usable_version = bool(
                version and VERSION_PATTERN.fullmatch(version)
            )
            inventory_component = next(
                (
                    item
                    for item in device.components
                    if item.component_key == component["component_key"]
                ),
                None,
            )
            reported_version = version
            inventory_is_verified = bool(
                inventory_component
                and inventory_component.evidence_status.upper() == "VERIFIED"
            )
            if inventory_is_verified and inventory_component:
                version = (
                    inventory_component.version.strip()
                    if isinstance(inventory_component.version, str)
                    else ""
                )
                has_usable_version = bool(
                    version and VERSION_PATTERN.fullmatch(version)
                )
            evidence_status = (
                "VERIFIED"
                if inventory_is_verified
                else "REPORTED" if has_usable_version else "NOT_ASSESSED"
            )
            evidence_source = (
                inventory_component.evidence_source
                if inventory_is_verified
                and inventory_component
                and inventory_component.evidence_source
                else source
            )
            if inventory_is_verified and inventory_component:
                evidence_note = (
                    inventory_component.evidence_note
                    or "The saved component version has VERIFIED evidence."
                )
                if reported_version != version:
                    evidence_note = (
                        f"{evidence_note} Latest simulated telemetry reports "
                        f"{reported_version or 'no version'}; the verified "
                        "inventory value was retained without modification."
                    )
            else:
                evidence_note = (
                    "The version is self-reported over simulated MQTT and is "
                    "not authenticated as physical-device evidence."
                )
            state = {
                "component": component["name"],
                "version": (
                    version
                    if has_usable_version
                    else (
                        inventory_component.version
                        if inventory_is_verified and inventory_component
                        else None
                    )
                ),
                "evidence_status": evidence_status,
                "assessment": "not_assessed",
                "reason": "",
                "evidence_source": evidence_source,
                "evidence_note": evidence_note,
            }
            if not has_usable_version:
                incomplete_components.append(
                    f"{component['name']}: version missing or unsupported"
                )
                if inventory_is_verified:
                    state["reason"] = (
                        "The verified inventory version is missing or has an "
                        "unsupported format; it was retained and not assessed. "
                        f"Latest simulated report: {reported_version or 'missing'}."
                    )
                else:
                    state["reason"] = (
                        "No usable numeric runtime version was reported; the "
                        "component cannot be assessed (reported value: "
                        f"{reported_version or 'missing'})."
                    )
                    if inventory_component is not None:
                        inventory_component.evidence_status = "NOT_ASSESSED"
                        inventory_component.confidence = "none"
                        inventory_component.evidence_method = (
                            "Simulated ESP32 runtime self-report via MQTT"
                        )
                        inventory_component.evidence_source = source
                        inventory_component.evidence_note = (
                            f"{state['reason']} Previously reported version "
                            f"{inventory_component.version or 'unknown'} is "
                            "retained as historical evidence, not treated as "
                            "the current installed version."
                        )
                        inventory_component.collected_at = latest.received_at
                    else:
                        db.session.add(
                            DeviceComponent(
                                device_id=device.id,
                                component_key=component["component_key"],
                                name=component["name"],
                                component_type="software",
                                vendor=component["vendor"],
                                product=component["product"],
                                evidence_source=source,
                                evidence_method=(
                                    "Simulated ESP32 runtime self-report via MQTT"
                                ),
                                evidence_note=state["reason"],
                                evidence_status="NOT_ASSESSED",
                                confidence="none",
                                collected_at=latest.received_at,
                            )
                        )
                    base_cpe = _resolve_cpe(nvd, component)
                    if base_cpe is not None:
                        state["reason"] += (
                            " NVD was queried for CPE-matched product candidates; "
                            "the missing/unsupported version prevents applicability "
                            "confirmation."
                        )
                        candidate_target = SimpleNamespace(
                            vendor=NVD_VENDOR,
                            model=base_cpe.split(":")[4],
                            firmware=reported_version or None,
                            firmware_version=reported_version or None,
                            firmware_verification_status=evidence_status,
                        )
                        candidates = _fetch_all_cves(
                            nvd,
                            f"{component['vendor']} {component['search_product']}",
                        )
                        for item in candidates:
                            cve_data = item.get("cve") if isinstance(item, dict) else None
                            cve_id = (
                                cve_data.get("id")
                                if isinstance(cve_data, dict)
                                else None
                            )
                            if (
                                not isinstance(cve_id, str)
                                or not CVE_ID_PATTERN.fullmatch(cve_id)
                            ):
                                continue
                            cve_id = cve_id.upper()
                            finding_key = (cve_id, component["name"])
                            if finding_key in processed_finding_keys:
                                continue
                            assessment = assess_cpe_match(candidate_target, cve_data)
                            if assessment is None:
                                continue
                            match_status, evidence = assessment
                            if match_status not in {"potential", "indeterminate"}:
                                continue
                            processed_finding_keys.add(finding_key)
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
                            cve = pending_cves.get(cve_id) or db.session.get(
                                CVE,
                                cve_id,
                            )
                            if cve is None:
                                cve = CVE(id=cve_id)
                            cve.description = description
                            cve.published_date = _nvd_datetime(
                                cve_data.get("published")
                            )
                            cve.last_modified_date = _nvd_datetime(
                                cve_data.get("lastModified")
                            )
                            cve.severity = severity
                            cve.cvss_score = score
                            cve.cvss_vector = _cvss_vector(cve_data)
                            cve.attack_vector = attack_vector
                            cve.cwe = _cwe(cve_data)
                            cve.source = "nvd"
                            cve.raw = cve_data
                            pending_cves[cve_id] = cve
                            findings.append(
                                Finding(
                                    scan_id=scan_id,
                                    device_id=device.id,
                                    cve_id=cve_id,
                                    severity=severity or "unknown",
                                    score=score,
                                    summary=description,
                                    evidence=(
                                        f"Reported {component['name']} value "
                                        f"{reported_version or 'unknown'}; "
                                        "NVD product-level candidate only. "
                                        f"{evidence} Applicability cannot be "
                                        "confirmed without a usable, verified "
                                        "installed version. Source: "
                                        "https://nvd.nist.gov/vuln/detail/"
                                        f"{cve_id}."
                                    ),
                                    matched_by=(
                                        "nvd-cpe-product-potential"
                                        if match_status == "potential"
                                        else "nvd-cpe-logic-indeterminate"
                                    ),
                                    component_name=component["name"],
                                    component_version=reported_version or None,
                                    match_status=match_status,
                                    confidence="low",
                                )
                            )
                component_states.append(state)
                continue

            if not inventory_is_verified:
                evidence_note = (
                    f"Version {version} reported by SolarGuard-01 at "
                    f"{latest.received_at:%Y-%m-%d %H:%M:%S} UTC. Telemetry is "
                    "simulated and unauthenticated; it does not prove a physical "
                    "device configuration."
                )
                if inventory_component is None:
                    inventory_component = DeviceComponent(
                        device_id=device.id,
                        component_key=component["component_key"],
                        name=component["name"],
                        component_type="software",
                        vendor=component["vendor"],
                        product=component["product"],
                        evidence_method=(
                            "Simulated ESP32 runtime self-report via MQTT"
                        ),
                        evidence_note=evidence_note,
                        evidence_status="REPORTED",
                        confidence="low",
                    )
                    db.session.add(inventory_component)
                inventory_component.version = version
                inventory_component.evidence_source = source
                inventory_component.evidence_method = (
                    "Simulated ESP32 runtime self-report via MQTT"
                )
                inventory_component.evidence_note = evidence_note
                inventory_component.evidence_status = "REPORTED"
                inventory_component.confidence = "low"
                inventory_component.collected_at = latest.received_at
            state["evidence_source"] = evidence_source
            state["evidence_note"] = evidence_note

            base_cpe = _resolve_cpe(nvd, component)
            if base_cpe is None:
                incomplete_components.append(
                    f"{component['name']}: no exact NVD CPE product mapping found"
                )
                state["reason"] = (
                    "No exact NVD CPE product mapping was identified for this "
                    "reported component."
                )
                component_states.append(state)
                continue
            assessed_components += 1
            state["assessment"] = "assessed"
            state["reason"] = (
                "Verified inventory version and exact NVD product CPE were queried."
                if inventory_is_verified
                else (
                    "Reported runtime version and exact NVD product CPE were "
                    "queried. Applicability remains potential unless the runtime "
                    "evidence is independently verified."
                )
            )
            component_states.append(state)
            exact_cpe = _versioned_cpe(base_cpe, version)
            component_target = SimpleNamespace(
                vendor=NVD_VENDOR,
                model=base_cpe.split(":")[4],
                firmware=version,
                firmware_version=version,
                firmware_verification_status=evidence_status,
            )
            vulnerabilities = _fetch_cves_by_cpe(nvd, exact_cpe)
            for item in vulnerabilities:
                cve_data = item.get("cve") if isinstance(item, dict) else None
                cve_id = cve_data.get("id") if isinstance(cve_data, dict) else None
                if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
                    continue
                cve_id = cve_id.upper()
                finding_key = (cve_id, component["name"])
                if finding_key in processed_finding_keys:
                    continue
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
                        )
                        + f" Source: https://nvd.nist.gov/vuln/detail/{cve_id}.",
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
                processed_finding_keys.add(finding_key)

        db.session.commit()
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
        unassessed_count = sum(
            item["assessment"] == "not_assessed" for item in component_states
        )
        scan.summary = (
            f"Assessed {assessed_components} reported ESP32 component(s): "
            f"{affected} NVD affected-version match(es), {potential} potential or "
            f"indeterminate result(s), {not_applicable} not-applicable result(s), "
            f"and {unassessed_count} component(s) not assessed."
            f"{incomplete_summary} Results rely on reported simulated runtime "
            "versions and NVD CPE applicability data; exploitability is not confirmed."
        )
        scan.notes = json.dumps(
            {
                "device": {
                    "name": device.name,
                    "vendor": device.vendor,
                    "model": device.model,
                    "firmware_version": device.firmware_version,
                    "firmware_evidence_status": (
                        device.firmware_verification_status
                    ),
                    "simulation_status": device.simulation_status,
                    "telemetry_received_at": (
                        latest.received_at.isoformat() if latest.received_at else None
                    ),
                    "telemetry_message_id": latest.source_message_id,
                },
                "components": component_states,
                "source_urls": ["https://nvd.nist.gov/vuln/search"],
            },
            sort_keys=True,
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
        if component_states:
            scan.notes = json.dumps(
                {"components": component_states},
                sort_keys=True,
            )
        scan.completed_at = datetime.now(UTC).replace(tzinfo=None)
        db.session.commit()
    except Exception:
        logger.exception("Unexpected component scan failure for device %s", device.id)
        db.session.rollback()
        scan = db.session.get(Scan, scan_id)
        scan.status = "failed"
        scan.summary = "An internal error interrupted the component scan."
        if component_states:
            scan.notes = json.dumps(
                {"components": component_states},
                sort_keys=True,
            )
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
