from __future__ import annotations

from app.extensions import db


class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(
        db.Integer,
        db.ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cve_id = db.Column(db.String(32), nullable=True, index=True)
    alert_type = db.Column(db.String(80), nullable=False, default="cve")
    severity = db.Column(db.String(20), nullable=False, default="medium")
    title = db.Column(db.String(200), nullable=False)
    summary = db.Column(db.Text, nullable=False)
    dedupe_key = db.Column(db.String(200), nullable=False, unique=True, index=True)
    status = db.Column(db.String(30), nullable=False, default="open")
    source = db.Column(db.String(80), nullable=False, default="scan")
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        onupdate=db.func.now(),
    )
    acknowledged_at = db.Column(db.DateTime, nullable=True)

    device = db.relationship("Device", back_populates="alerts")
