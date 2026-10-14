from __future__ import annotations


from app.extensions import db
from app.models.device import Device
from app.models.patch import PatchCandidate


def discover_patch_candidates(device_id: int, cve_id: str | None = None) -> list[PatchCandidate]:
    device = db.session.get(Device, device_id)
    if device is None:
        raise ValueError(f"Device {device_id} does not exist.")

    candidate_data = {
        "device_id": device.id,
        "cve_id": cve_id,
        "component_name": "Unverified component",
        "component_version": None,
        "recommended_version": None,
        "patch_source": "no-verified-vendor-source",
        "patch_url": None,
        "evidence": (
            "No vendor advisory, affected component version, or fixed version "
            "has been verified for this device. This is a simulated workflow "
            "record only; no patch is being recommended or installed."
        ),
        "is_simulated": True,
        "source_confidence": "low",
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
    if not candidate.is_simulated or candidate.status != "discovered":
        raise ValueError("Only discovered simulated candidates can be approved.")
    candidate.approve(
        approver,
        note=(
            "Simulated approval only; this workflow is a demo and no real "
            "device update was performed."
        ),
    )
    db.session.commit()
    return _snapshot_patch(candidate)


def verify_patch(candidate_id: int, verifier: str = "simulated-verifier") -> PatchCandidate:
    candidate = db.session.get(PatchCandidate, candidate_id)
    if candidate is None:
        raise ValueError(f"Patch candidate {candidate_id} does not exist.")
    if not candidate.is_simulated or candidate.status != "approved":
        raise ValueError("Only approved simulated candidates can be verified.")
    candidate.verify(
        verifier,
        note=(
            "Simulated verification passed. This is a labeled demo workflow, "
            "not a real-world firmware validation."
        ),
    )
    db.session.commit()
    return _snapshot_patch(candidate)
