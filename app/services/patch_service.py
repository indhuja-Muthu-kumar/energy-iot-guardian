from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db
from app.models.device import Device
from app.models.patch import PatchCandidate

_TRUSTED_PATCH_CATALOG = {
    "SolarGuard-01": {
        "component_name": "ESP-IDF",
        "recommended_version": "v5.6.0",
        "patch_source": "simulated-vendor-advisory",
        "patch_url": "https://example.invalid/vendor/esp32/security-fix",
        "evidence": "Simulation only: a labeled vendor advisory record for the ESP32 runtime would be found here. No real firmware update is being executed.",
    }
}


def discover_patch_candidates(device_id: int, cve_id: str | None = None) -> list[PatchCandidate]:
    device = db.session.get(Device, device_id)
    if device is None:
        raise ValueError(f"Device {device_id} does not exist.")

    catalog = _TRUSTED_PATCH_CATALOG.get(device.name, {})
    candidate_data = {
        "device_id": device.id,
        "cve_id": cve_id,
        "component_name": catalog.get("component_name", "ESP-IDF"),
        "component_version": device.firmware_version or "unknown",
        "recommended_version": catalog.get("recommended_version", "v5.6.0"),
        "patch_source": catalog.get("patch_source", "simulated-vendor-advisory"),
        "patch_url": catalog.get("patch_url"),
        "evidence": catalog.get(
            "evidence",
            "Simulated trusted patch discovery: a vendor advisory would be validated here before release.",
        ),
        "is_simulated": True,
        "source_confidence": "high",
        "status": "discovered",
    }

    existing = PatchCandidate.query.filter_by(
        device_id=device.id,
        cve_id=candidate_data["cve_id"],
        component_name=candidate_data["component_name"],
        recommended_version=candidate_data["recommended_version"],
    ).first()
    if existing is not None:
        return [existing]

    candidate = PatchCandidate(**candidate_data)
    db.session.add(candidate)
    db.session.commit()
    return [candidate]


def _snapshot_patch(candidate: PatchCandidate) -> PatchCandidate:
    snapshot = PatchCandidate(
        device_id=candidate.device_id,
        cve_id=candidate.cve_id,
        component_name=candidate.component_name,
        component_version=candidate.component_version,
        recommended_version=candidate.recommended_version,
        patch_source=candidate.patch_source,
        patch_url=candidate.patch_url,
        evidence=candidate.evidence,
        status=candidate.status,
        source_confidence=candidate.source_confidence,
        is_simulated=candidate.is_simulated,
        approved_by=candidate.approved_by,
        approved_at=candidate.approved_at,
        verified_by=candidate.verified_by,
        verified_at=candidate.verified_at,
        verification_note=candidate.verification_note,
    )
    snapshot.id = candidate.id
    return snapshot


def approve_patch(candidate_id: int, approver: str = "simulated-operator") -> PatchCandidate:
    candidate = db.session.get(PatchCandidate, candidate_id)
    if candidate is None:
        raise ValueError(f"Patch candidate {candidate_id} does not exist.")
    candidate.approve(approver, note="Simulated approval only; the workflow is intentionally labeled as a demo and no real device update was performed.")
    db.session.commit()
    return _snapshot_patch(candidate)


def verify_patch(candidate_id: int, verifier: str = "simulated-verifier") -> PatchCandidate:
    candidate = db.session.get(PatchCandidate, candidate_id)
    if candidate is None:
        raise ValueError(f"Patch candidate {candidate_id} does not exist.")
    if candidate.status != "approved":
        candidate.status = "approved"
        candidate.approved_by = "simulated-operator"
        candidate.approved_at = datetime.now(UTC).replace(tzinfo=None)
    candidate.verify(
        verifier,
        note="Simulated verification passed. This is a labeled demo workflow, not a real-world firmware validation.",
    )
    db.session.commit()
    return _snapshot_patch(candidate)
