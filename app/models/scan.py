from __future__ import annotations

from app.extensions import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"), nullable=False)
    status = db.Column(db.String(30), default="queued")
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    summary = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    scan_type = db.Column(db.String(30), nullable=False, default="device")
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    device = db.relationship("Device", back_populates="scans")
    findings = db.relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
