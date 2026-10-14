from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db
from app.models.cve import CVE
from app.services.nvd_client import NVDClient

PAGE_SIZE = 100


def _coerce_datetime(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def sync_nvd_catalog(keyword: str, client: NVDClient | None = None) -> int:
    nvd = client or NVDClient()
    payload = nvd.fetch_cves(keyword, page_size=PAGE_SIZE, start_index=0)
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
        page = nvd.fetch_cves(
            keyword,
            page_size=PAGE_SIZE,
            start_index=start_index,
        )
        page_vulnerabilities = page.get("vulnerabilities") if isinstance(page, dict) else None
        page_total = page.get("totalResults") if isinstance(page, dict) else None
        expected_page_size = min(PAGE_SIZE, total_results - start_index)
        if (
            not isinstance(page_vulnerabilities, list)
            or page_total != total_results
            or len(page_vulnerabilities) != expected_page_size
        ):
            raise ValueError("NVD response did not contain a complete CVE result page.")
        all_vulnerabilities.extend(page_vulnerabilities)

    saved = 0
    for item in all_vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_data = item.get("cve")
        if not isinstance(cve_data, dict):
            continue
        cve_id = cve_data.get("id")
        if not isinstance(cve_id, str) or not cve_id:
            continue

        record = db.session.get(CVE, cve_id)
        if record is None:
            record = CVE(id=cve_id)
            db.session.add(record)

        description = cve_data.get("descriptions") or []
        english = next(
            (
                entry.get("value")
                for entry in description
                if isinstance(entry, dict) and entry.get("lang") == "en"
            ),
            None,
        )
        metrics = cve_data.get("metrics") or {}
        cvss_entry = None
        if isinstance(metrics, dict):
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                values = metrics.get(key) or []
                if isinstance(values, list) and values:
                    first = values[0]
                    if isinstance(first, dict):
                        cvss_entry = first.get("cvssData") or {}
                        break

        score = cvss_entry.get("baseScore") if isinstance(cvss_entry, dict) else None
        if isinstance(score, bool):
            score = None
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None

        weaknesses = cve_data.get("weaknesses") or []
        cwe = None
        if isinstance(weaknesses, list):
            for weakness in weaknesses:
                if not isinstance(weakness, dict):
                    continue
                for description_entry in weakness.get("description") or []:
                    if isinstance(description_entry, dict):
                        value = description_entry.get("value")
                        if isinstance(value, str) and value:
                            cwe = value
                            break
                if cwe:
                    break

        record.description = english
        record.published_date = _coerce_datetime(cve_data.get("published"))
        record.last_modified_date = _coerce_datetime(cve_data.get("lastModified"))
        record.severity = (
            cvss_entry.get("baseSeverity") if isinstance(cvss_entry, dict) else None
        ) or "unknown"
        record.cvss_score = score
        record.cvss_vector = (
            cvss_entry.get("vectorString") if isinstance(cvss_entry, dict) else None
        )
        record.attack_vector = (
            cvss_entry.get("attackVector") if isinstance(cvss_entry, dict) else None
        )
        record.cwe = cwe
        record.source = "nvd"
        record.raw = cve_data
        saved += 1

    db.session.commit()
    return saved
