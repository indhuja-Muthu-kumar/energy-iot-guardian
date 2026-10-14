from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db


class PatchCandidate(db.Model):
    __tablename__ = "patch_candidates"
    __table_args__ = (
        db.UniqueConstraint(
            "device_id",
            "cve_id",
            "component_name",
            "recommended_version",
            name="uq_patch_candidate",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(
        db.Integer,
        db.ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cve_id = db.Column(db.String(32), nullable=True, index=True)
    component_name = db.Column(db.String(120), nullable=False)
    component_version = db.Column(db.String(80), nullable=True)
    recommended_version = db.Column(db.String(80), nullable=True)
    patch_source = db.Column(db.String(120), nullable=False, default="vendor-advisory")
    patch_url = db.Column(db.String(400), nullable=True)
    evidence = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="discovered")
    source_confidence = db.Column(db.String(20), nullable=False, default="high")
    is_simulated = db.Column(db.Boolean, nullable=False, default=True)
    approved_by = db.Column(db.String(120), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    verified_by = db.Column(db.String(120), nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    verification_note = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        onupdate=db.func.now(),
    )

    device = db.relationship("Device", back_populates="patch_candidates")

    def approve(self, approver: str, *, note: str | None = None):
        self.status = "approved"
        self.approved_by = approver
        self.approved_at = datetime.now(UTC).replace(tzinfo=None)
        self.verification_note = note or (
            "Simulated patch approval only; no real firmware update was performed."
        )

    def verify(self, verifier: str, *, note: str | None = None):
        self.status = "verified"
        self.verified_by = verifier
        self.verified_at = datetime.now(UTC).replace(tzinfo=None)
        self.verification_note = note or (
            "Simulated verification passed. This record is a labeled demo workflow, not a real-world patch validation."
        )
