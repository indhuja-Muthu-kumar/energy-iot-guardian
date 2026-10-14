from __future__ import annotations

from app.extensions import db


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False)
    cve_id = db.Column(db.String(32), db.ForeignKey("cves.id"), nullable=False)
    severity = db.Column(db.String(30), nullable=False)
    score = db.Column(db.Float, nullable=True)
    summary = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    matched_by = db.Column(db.String(80), nullable=True)
    component_name = db.Column(db.String(100), nullable=True)
    component_version = db.Column(db.String(80), nullable=True)
    match_status = db.Column(
        db.String(30),
        nullable=False,
        default="potential",
    )
    confidence = db.Column(db.String(20), nullable=False, default="low")
    status = db.Column(db.String(30), default="open")
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    scan = db.relationship("Scan", back_populates="findings")
    device = db.relationship("Device", back_populates="findings")
    cve = db.relationship("CVE", back_populates="findings")
