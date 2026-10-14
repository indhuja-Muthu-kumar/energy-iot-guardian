from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db
from app.models.cve import CVE
from app.services.nvd_client import NVDClient


def _coerce_datetime(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def sync_nvd_catalog(keyword: str, client: NVDClient | None = None) -> int:
    nvd = client or NVDClient()
    payload = nvd.fetch_cves(keyword, page_size=100, start_index=0)
    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulnerabilities, list):
        raise ValueError("NVD response was not a valid vulnerabilities list.")

    saved = 0
    for item in vulnerabilities:
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
        record.severity = (cvss_entry.get("baseSeverity") if isinstance(cvss_entry, dict) else None) or "unknown"
        record.cvss_score = score
        record.cvss_vector = cvss_entry.get("vectorString") if isinstance(cvss_entry, dict) else None
        record.attack_vector = cvss_entry.get("attackVector") if isinstance(cvss_entry, dict) else None
        record.cwe = cwe
        record.source = "nvd"
        record.raw = cve_data
        saved += 1

    db.session.commit()
    return saved
