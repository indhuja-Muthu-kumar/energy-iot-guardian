from __future__ import annotations

import json
import logging
import math
import re
from datetime import UTC, datetime
from types import SimpleNamespace

import requests
from flask import abort, current_app

from app.extensions import db
from app.models.cve import CVE
from app.models.device import ARCHIVED_DEVICE_STATUS, Device
from app.models.finding import Finding
from app.models.device_component import DeviceComponent
from app.models.patch import PatchCandidate
from app.models.scan import Scan
from app.services.alert_service import create_alerts_from_findings
from app.services.matcher import assess_cpe_match, compute_match_score
from app.services.nvd_client import NVDClient

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
NVD_PAGE_SIZE = 100


def _nvd_datetime(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(
            tzinfo=None
        )
    except ValueError:
        logger.warning("Ignoring malformed NVD timestamp: %r", value)
        return None


def _cvss_details(cve_data: dict) -> tuple[float | None, str | None, str | None]:
    metrics = cve_data.get("metrics") or {}
    if not isinstance(metrics, dict):
        return None, None, None
    selected: tuple[float | None, str | None, str | None] = (None, None, None)
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_name) or []
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                data = entry.get("cvssData") or {}
                if not isinstance(data, dict):
                    continue
                score = data.get("baseScore")
                if isinstance(score, bool):
                    score = None
                try:
                    score = float(score) if score is not None else None
                except (TypeError, ValueError):
                    score = None
                if score is not None and (
                    not math.isfinite(score) or not 0 <= score <= 10
                ):
                    score = None
                severity = data.get("baseSeverity") or entry.get("baseSeverity")
                attack_vector = data.get("attackVector")
                severity = severity if isinstance(severity, str) else None
                attack_vector = (
                    attack_vector if isinstance(attack_vector, str) else None
                )
                selected = (
                    selected[0] if selected[0] is not None else score,
                    selected[1] if selected[1] is not None else severity,
                    selected[2] if selected[2] is not None else attack_vector,
                )
                if selected[0] is not None:
                    return selected
    return selected


def _cvss_vector(cve_data: dict) -> str | None:
    metrics = cve_data.get("metrics") or {}
    if not isinstance(metrics, dict):
        return None
    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        for entry in metrics.get(metric_name) or []:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData") or {}
            vector = data.get("vectorString") if isinstance(data, dict) else None
            if isinstance(vector, str) and vector:
                return vector
    return None


def _cwe(cve_data: dict) -> str | None:
    weaknesses = cve_data.get("weaknesses") or []
    if not isinstance(weaknesses, list):
        return None
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for description in weakness.get("description") or []:
            if not isinstance(description, dict):
                continue
            value = description.get("value")
            if isinstance(value, str) and value and value != "NVD-CWE-noinfo":
                return value
    return None


def _mark_scan_failed(scan_id: int, summary: str) -> Scan:
    db.session.rollback()
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        raise RuntimeError(
            "The scan record disappeared during failure handling."
        ) from None

    db.session.query(Finding).filter_by(scan_id=scan_id).delete(
        synchronize_session=False
    )
    scan.status = "failed"
    scan.summary = summary
    scan.completed_at = datetime.now(UTC).replace(tzinfo=None)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("Could not save failure status for scan %s", scan_id)
        raise
    return scan


def _fetch_all_cves(nvd: NVDClient, keyword: str) -> list:
    payload = nvd.fetch_cves(keyword, page_size=NVD_PAGE_SIZE)
    if not isinstance(payload, dict):
        raise ValueError("NVD response was not a JSON object.")
    vulnerabilities = payload.get("vulnerabilities")
    total_results = payload.get("totalResults")
    if not isinstance(vulnerabilities, list):
        raise ValueError("NVD response did not contain a vulnerabilities list.")
    if (
        not isinstance(total_results, int)
        or isinstance(total_results, bool)
        or total_results < 0
    ):
        raise ValueError("NVD response did not contain a valid totalResults count.")
    if len(vulnerabilities) > total_results:
        raise ValueError("NVD response contained more records than totalResults.")
    expected_page_size = min(NVD_PAGE_SIZE, total_results)
    if len(vulnerabilities) != expected_page_size:
        raise ValueError("NVD response did not contain the complete first page.")

    all_vulnerabilities = list(vulnerabilities)
    while len(all_vulnerabilities) < total_results:
        start_index = len(all_vulnerabilities)
        page = nvd.fetch_cves(
            keyword,
            page_size=NVD_PAGE_SIZE,
            start_index=start_index,
        )
        if not isinstance(page, dict):
            raise ValueError("NVD response was not a JSON object.")
        page_vulnerabilities = page.get("vulnerabilities")
        page_total = page.get("totalResults")
        if (
            not isinstance(page_vulnerabilities, list)
            or not isinstance(page_total, int)
            or isinstance(page_total, bool)
            or page_total != total_results
        ):
            raise ValueError("NVD result count changed or the next page was malformed.")
        expected_page_size = min(
            NVD_PAGE_SIZE,
            total_results - start_index,
        )
        if len(page_vulnerabilities) != expected_page_size:
            raise ValueError("NVD response did not contain a complete result page.")
        all_vulnerabilities.extend(page_vulnerabilities)

    return all_vulnerabilities


def _fetch_all_cves_by_cpe(nvd: NVDClient, cpe_name: str) -> list:
    payload = nvd.fetch_cves_by_cpe(
        cpe_name,
        page_size=NVD_PAGE_SIZE,
        start_index=0,
    )
    if not isinstance(payload, dict):
        raise ValueError("NVD CPE response was not a JSON object.")
    vulnerabilities = payload.get("vulnerabilities")
    total_results = payload.get("totalResults")
    if (
        not isinstance(vulnerabilities, list)
        or not isinstance(total_results, int)
        or isinstance(total_results, bool)
        or total_results < 0
        or len(vulnerabilities) != min(NVD_PAGE_SIZE, total_results)
    ):
        raise ValueError("NVD CPE response did not contain a complete first page.")

    results = list(vulnerabilities)
    while len(results) < total_results:
        start_index = len(results)
        page = nvd.fetch_cves_by_cpe(
            cpe_name,
            page_size=NVD_PAGE_SIZE,
            start_index=start_index,
        )
        page_items = page.get("vulnerabilities") if isinstance(page, dict) else None
        page_total = page.get("totalResults") if isinstance(page, dict) else None
        expected = min(NVD_PAGE_SIZE, total_results - start_index)
        if (
            not isinstance(page_items, list)
            or page_total != total_results
            or len(page_items) != expected
        ):
            raise ValueError("NVD CPE response did not contain a complete result page.")
        results.extend(page_items)
    return results


def _component_cpe_for_version(component: DeviceComponent) -> str | None:
    if (
        not component.cpe_name
        or not component.version
        or component.evidence_status.upper() != "VERIFIED"
    ):
        return None
    fields = component.cpe_name.split(":")
    if len(fields) != 13 or fields[:3] != ["cpe", "2.3", "a"]:
        raise ValueError(
            f"Component {component.name!r} has an invalid NVD CPE identifier."
        )
    if not re.fullmatch(r"[vV]?\d+(?:\.\d+)*", component.version):
        raise ValueError(
            f"Component {component.name!r} has an unsupported version format."
        )
    fields[5] = component.version.lstrip("vV")
    return ":".join(fields)


def _nvd_vendor_advisory(cve_data: dict) -> str | None:
    references = cve_data.get("references")
    if not isinstance(references, list):
        return None
    for reference in references:
        if not isinstance(reference, dict):
            continue
        url = reference.get("url")
        tags = reference.get("tags")
        if (
            isinstance(url, str)
            and url.startswith("https://")
            and len(url) <= 400
            and isinstance(tags, list)
            and any(
                isinstance(tag, str) and tag.strip().lower() == "vendor advisory"
                for tag in tags
            )
        ):
            return url
    return None


def _record_vendor_recommendation(
    device: Device,
    finding: Finding,
    cve_data: dict,
) -> bool:
    if finding.match_status in {"not_affected", "not_applicable"}:
        return False
    advisory_url = _nvd_vendor_advisory(cve_data)
    if advisory_url is None:
        return False

    component_name = finding.component_name or device.model
    candidate = PatchCandidate.query.filter_by(
        device_id=device.id,
        cve_id=finding.cve_id,
        component_name=component_name,
        recommended_version="",
    ).first()
    evidence = (
        "NVD references this HTTPS page as a vendor advisory. The advisory "
        "content and any fixed version have not been independently extracted; "
        "review the vendor source for applicability, supported update steps, "
        "compatibility, and backup requirements. No update was applied."
    )
    if candidate is None:
        db.session.add(
            PatchCandidate(
                device_id=device.id,
                cve_id=finding.cve_id,
                component_name=component_name,
                component_version=finding.component_version,
                recommended_version="",
                patch_source="NVD-tagged-vendor-advisory",
                patch_url=advisory_url,
                evidence=evidence,
                status="discovered",
                source_confidence="medium",
                is_simulated=False,
            )
        )
    elif candidate.status == "discovered":
        candidate.component_version = finding.component_version
        candidate.patch_url = advisory_url
        candidate.evidence = evidence
        candidate.patch_source = "NVD-tagged-vendor-advisory"
        candidate.is_simulated = False
        candidate.source_confidence = "medium"
    return True


def run_scan_for_device(
    device_id: int,
    client: NVDClient | None = None,
) -> Scan:
    device = db.session.get(Device, device_id)
    if device is None:
        abort(404)
    if device.status == ARCHIVED_DEVICE_STATUS:
        abort(409, description="Archived devices cannot be scanned.")
    if device.telemetry_device_id == current_app.config["TELEMETRY_DEVICE_ID"]:
        abort(
            409,
            description=(
                "SolarGuard-01 reports ESP32 software versions, not verified "
                "SMA inverter firmware. Use the ESP32 component scan workflow."
            ),
        )
    scan = Scan(
        device_id=device.id,
        status="running",
        started_at=datetime.now(UTC).replace(tzinfo=None),
        summary="Loading saved device evidence and querying NVD.",
    )
    db.session.add(scan)
    db.session.commit()
    scan_id = scan.id

    try:
        nvd = client or NVDClient()
        queries: list[tuple[str, object, str | None, str | None]] = [
            (
                f"{device.vendor} {device.model}".strip(),
                device,
                None,
                None,
            )
        ]
        component_states = []
        for component in device.components:
            if component.component_type != "software":
                component_states.append({
                    "component": component.name,
                    "version": component.version,
                    "evidence_status": component.evidence_status,
                    "assessment": "not_assessed",
                    "reason": "Hardware identity is tracked separately from software versions.",
                    "evidence_source": component.evidence_source,
                    "evidence_note": component.evidence_note,
                })
                continue
            exact_cpe = _component_cpe_for_version(component)
            if exact_cpe is None:
                component_states.append({
                    "component": component.name,
                    "version": component.version,
                    "evidence_status": component.evidence_status,
                    "assessment": "not_assessed",
                    "reason": (
                        "A verified installed version and exact NVD CPE are "
                        "both required for component version assessment."
                    ),
                    "evidence_source": component.evidence_source,
                    "evidence_note": component.evidence_note,
                })
                continue
            target = SimpleNamespace(
                vendor=component.vendor,
                model=component.product,
                firmware=component.version,
                firmware_version=component.version,
                firmware_verification_status=component.evidence_status,
            )
            queries.append((exact_cpe, target, component.name, component.version))
            component_states.append({
                "component": component.name,
                "version": component.version,
                "evidence_status": component.evidence_status,
                "assessment": "assessed",
                "reason": "Verified version and exact NVD CPE are available.",
                "evidence_source": component.evidence_source,
                "evidence_note": component.evidence_note,
            })

        affected_count = 0
        potential_count = 0
        not_affected_count = 0
        duplicate_count = 0
        processed_findings: set[tuple[str, str | None]] = set()
        saved_findings = []
        queried_entries = 0
        recommendation_count = 0
        for query, target, component_name, component_version in queries:
            is_cpe_query = query.startswith("cpe:2.3:")
            vulnerabilities = (
                _fetch_all_cves_by_cpe(nvd, query)
                if is_cpe_query
                else _fetch_all_cves(nvd, query)
            )
            queried_entries += len(vulnerabilities)
            for item in vulnerabilities:
                if not isinstance(item, dict):
                    raise ValueError("NVD response contained a malformed vulnerability.")
                cve_data = item.get("cve")
                if not isinstance(cve_data, dict):
                    raise ValueError("NVD response contained a malformed CVE record.")
                cve_id = cve_data.get("id")
                if not isinstance(cve_id, str):
                    raise ValueError("NVD response contained a CVE without a valid ID.")
                if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id, flags=re.IGNORECASE):
                    continue
                cve_id = cve_id.upper()
                finding_key = (cve_id, component_name)
                if finding_key in processed_findings:
                    duplicate_count += 1
                    continue
                processed_findings.add(finding_key)

                descriptions = cve_data.get("descriptions") or []
                if not isinstance(descriptions, list):
                    descriptions = []
                description = next(
                    (
                        entry.get("value", "")
                        for entry in descriptions
                        if isinstance(entry, dict) and entry.get("lang") == "en"
                    ),
                    "",
                )
                if not isinstance(description, str):
                    description = ""
                score, severity, attack_vector = _cvss_details(cve_data)
                weakness = _cwe(cve_data)
                cve = db.session.get(CVE, cve_id) or CVE(id=cve_id)
                cve.description = description
                cve.published_date = _nvd_datetime(cve_data.get("published"))
                cve.last_modified_date = _nvd_datetime(cve_data.get("lastModified"))
                cve.severity = severity
                cve.cvss_score = score
                cve.cvss_vector = _cvss_vector(cve_data)
                cve.attack_vector = attack_vector
                cve.cwe = weakness
                cve.source = "nvd"
                cve.raw = cve_data
                db.session.add(cve)

                assessment = assess_cpe_match(target, cve_data)
                if assessment is not None:
                    match_status, evidence = assessment
                    if match_status == "affected":
                        matched_by = "nvd-cpe-version-range"
                    elif match_status == "not_affected":
                        matched_by = "nvd-cpe-not-affected"
                    elif match_status == "indeterminate":
                        matched_by = "nvd-cpe-logic-indeterminate"
                    else:
                        matched_by = "nvd-cpe-product-potential"
                else:
                    if component_name is not None:
                        match_status = "potential"
                        matched_by = "nvd-cpe-product-potential"
                        evidence = (
                            "NVD returned this CVE for the exact verified "
                            f"component CPE/version {query}, but provided no "
                            "evaluable applicability configuration. This is a "
                            "potential match only."
                        )
                    else:
                        match_score = compute_match_score(device, description)
                        if match_score <= 0:
                            continue
                        match_status = "potential"
                        matched_by = "nvd-vendor-model-keyword"
                        description_lower = description.lower()
                        matched_terms = [
                            f"{label} '{value}'"
                            for label, value in (
                                ("vendor", device.vendor),
                                ("model", device.model),
                            )
                            if value and len(value.strip()) >= 4
                            and value.strip().lower() in description_lower
                        ]
                        evidence = (
                            "NVD description keyword match for "
                            f"{', '.join(matched_terms)}; this is a potential match only. "
                            f"Firmware {device.firmware_version or device.firmware or 'unknown'} "
                            "was not verified against an applicable NVD CPE/version "
                            "configuration."
                        )

                component_source = None
                if component_name:
                    component_source = next(
                        (
                            component.evidence_source
                            for component in device.components
                            if component.name == component_name
                        ),
                        None,
                    )
                finding = Finding(
                    scan_id=scan.id,
                    device_id=device.id,
                    cve_id=cve_id,
                    severity=severity or "unknown",
                    score=score,
                    summary=description,
                    evidence=(
                        f"Reported component {component_name} version "
                        f"{component_version or 'unknown'}; {evidence} "
                        "Evidence source: "
                        f"{component_source or 'not recorded'}. "
                        f"Source: https://nvd.nist.gov/vuln/detail/{cve_id}."
                        if component_name
                        else (
                            f"{evidence} "
                            f"Source: https://nvd.nist.gov/vuln/detail/{cve_id}."
                        )
                    ),
                    matched_by=matched_by,
                    component_name=component_name or device.model,
                    component_version=(
                        component_version or device.firmware_version
                    ),
                    match_status=match_status,
                    confidence=(
                        "high" if match_status == "affected"
                        else "medium" if match_status == "not_affected"
                        else "low"
                    ),
                )
                db.session.add(finding)
                saved_findings.append(finding)
                recommendation_count += _record_vendor_recommendation(
                    device,
                    finding,
                    cve_data,
                )
                if match_status == "affected":
                    affected_count += 1
                elif match_status == "not_affected":
                    not_affected_count += 1
                else:
                    potential_count += 1

        alert_findings = [
            finding
            for finding in saved_findings
            if finding.match_status not in {"not_affected", "not_applicable"}
        ]
        create_alerts_from_findings(
            device.id,
            alert_findings,
            commit=False,
        )

        scan.status = "completed"
        scan.summary = (
            f"NVD returned {queried_entries} CVE entries; "
            f"{affected_count} matched the evaluated NVD CPE/version logic and "
            f"{potential_count} remain potential matches; "
            f"{not_affected_count} were excluded by evaluated NVD CPE/version "
            "criteria. NVD metadata does not "
            "confirm device configuration or exploitability. "
            f"{duplicate_count} duplicate CVE entries were ignored, including "
            "repeat component matches. "
            f"{recommendation_count} source-backed vendor advisory recommendation(s) "
            "require review."
        )
        scan.notes = json.dumps(
            {
                "device": {
                    "name": device.name,
                    "vendor": device.vendor,
                    "model": device.model,
                    "firmware_version": device.firmware_version,
                    "firmware_evidence_source": device.firmware_evidence_source,
                    "firmware_evidence_method": device.firmware_evidence_method,
                    "firmware_evidence_status": device.firmware_verification_status,
                    "simulation_status": device.simulation_status,
                    "asset_tag": device.asset_tag,
                    "site": device.site,
                },
                "components": component_states,
                "recommendation_note": (
                    "NVD-tagged vendor advisory references are review leads; "
                    "the advisory content and fixed version are not asserted."
                ),
                "source_urls": [
                    "https://nvd.nist.gov/vuln/search",
                ],
            },
            sort_keys=True,
        )
        scan.completed_at = datetime.now(UTC).replace(tzinfo=None)
        db.session.commit()
    except Exception as error:
        logger.exception("NVD scan failed for device %s", device.id)
        failure_summary = (
            "The vulnerability data source returned an error or invalid response. "
            "No partial findings were saved; please retry."
            if isinstance(error, (requests.RequestException, ValueError))
            else "An internal error interrupted the scan. No partial findings "
            "were saved; review the application log and retry."
        )
        scan = _mark_scan_failed(scan_id, failure_summary)
    except BaseException:
        logger.exception("Scan interrupted for device %s", device.id)
        _mark_scan_failed(
            scan_id,
            "The scan was interrupted. No partial findings were saved.",
        )
        raise
    return scan
