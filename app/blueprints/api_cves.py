from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import login_required

from app.extensions import db
from app.models.cve import CVE
from app.models.finding import Finding
from app.models.patch import PatchCandidate

api_cves_bp = Blueprint("api_cves", __name__)


@api_cves_bp.get("")
@login_required
def list_cves():
    query = request.args.get("q", "").strip()
    results = CVE.query

    if query:
        search = f"%{query}%"
        results = results.filter(CVE.id.ilike(search) | CVE.description.ilike(search))

    items = results.limit(25).all()

    return jsonify(
        {
            "items": [
                {
                    "id": item.id,
                    "description": item.description,
                    "severity": item.severity,
                    "cvss_score": item.cvss_score,
                }
                for item in items
            ]
        }
    )


@api_cves_bp.get("/<cve_id>")
@login_required
def get_cve(cve_id: str):
    item = db.get_or_404(CVE, cve_id)
    findings = (
        Finding.query.filter_by(cve_id=item.id)
        .order_by(Finding.created_at.desc(), Finding.id.desc())
        .limit(100)
        .all()
    )
    references = []
    configurations = []
    raw = item.raw if isinstance(item.raw, dict) else {}
    for reference in raw.get("references") or []:
        if not isinstance(reference, dict):
            continue
        url = reference.get("url")
        tags = reference.get("tags") or []
        if (
            isinstance(url, str)
            and url.startswith("https://")
            and isinstance(tags, list)
            and "Vendor Advisory" in tags
        ):
            references.append({"url": url, "tags": tags})
    for configuration in raw.get("configurations") or []:
        if not isinstance(configuration, dict):
            continue
        for node in configuration.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict):
                    continue
                configurations.append(
                    {
                        "criteria": match.get("criteria"),
                        "vulnerable": match.get("vulnerable"),
                        "versionStartIncluding": match.get("versionStartIncluding"),
                        "versionStartExcluding": match.get("versionStartExcluding"),
                        "versionEndIncluding": match.get("versionEndIncluding"),
                        "versionEndExcluding": match.get("versionEndExcluding"),
                    }
                )
    patch_candidates = PatchCandidate.query.filter_by(cve_id=item.id).all()

    return jsonify(
        {
            "id": item.id,
            "description": item.description,
            "severity": item.severity,
            "cvss_score": item.cvss_score,
            "cvss_vector": item.cvss_vector,
            "cwe": item.cwe,
            "published_date": item.published_date.isoformat() if item.published_date else None,
            "last_modified_date": (
                item.last_modified_date.isoformat() if item.last_modified_date else None
            ),
            "assessments": [
                {
                    "device_id": finding.device_id,
                    "device_name": finding.device.name if finding.device else "Unknown device",
                    "vendor": finding.device.vendor if finding.device else None,
                    "model": finding.device.model if finding.device else None,
                    "component_name": finding.component_name,
                    "component_version": finding.component_version,
                    "match_status": finding.match_status,
                    "confidence": finding.confidence,
                    "matched_by": finding.matched_by,
                    "evidence": finding.evidence,
                    "summary": finding.summary,
                }
                for finding in findings
            ],
            "affected_products": configurations,
            "vendor_advisories": references,
            "patch_candidates": [
                {
                    "component_name": candidate.component_name,
                    "recommended_version": candidate.recommended_version,
                    "patch_source": candidate.patch_source,
                    "patch_url": (candidate.patch_url if not candidate.is_simulated else None),
                    "is_simulated": candidate.is_simulated,
                    "status": candidate.status,
                    "evidence": candidate.evidence,
                }
                for candidate in patch_candidates
            ],
        }
    )
