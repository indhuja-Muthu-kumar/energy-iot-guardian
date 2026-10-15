from __future__ import annotations

from app.extensions import db


class DeviceComponent(db.Model):
    __tablename__ = "device_components"
    __table_args__ = (
        db.UniqueConstraint(
            "device_id",
            "component_key",
            name="uq_device_component_key",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(
        db.Integer,
        db.ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    component_key = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    component_type = db.Column(db.String(30), nullable=False)
    vendor = db.Column(db.String(120), nullable=True)
    product = db.Column(db.String(160), nullable=False)
    version = db.Column(db.String(120), nullable=True)
    cpe_name = db.Column(db.String(255), nullable=True)
    evidence_source = db.Column(db.String(400), nullable=True)
    evidence_method = db.Column(db.String(120), nullable=False)
    evidence_note = db.Column(db.Text, nullable=False)
    evidence_status = db.Column(
        db.String(30), nullable=False, default="NOT_ASSESSED"
    )
    confidence = db.Column(db.String(20), nullable=False, default="none")
    collected_at = db.Column(db.DateTime, nullable=True)

    device = db.relationship("Device", back_populates="components")
