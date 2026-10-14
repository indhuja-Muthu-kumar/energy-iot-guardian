from __future__ import annotations

from app.extensions import db

ARCHIVED_DEVICE_STATUS = "archived"


class Device(db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    vendor = db.Column(db.String(120), nullable=False)
    model = db.Column(db.String(120), nullable=False)
    firmware = db.Column(db.String(120), nullable=False, default="unknown")
    firmware_version = db.Column(db.String(120), nullable=True)
    serial = db.Column(db.String(80), nullable=True)
    asset_tag = db.Column(db.String(80), nullable=True)
    site = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(50), default="active")
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())
    last_seen = db.Column(db.DateTime, nullable=True)

    scans = db.relationship("Scan", back_populates="device", cascade="all, delete-orphan")
    findings = db.relationship("Finding", back_populates="device", cascade="all, delete-orphan")
    alerts = db.relationship("SecurityAlert", back_populates="device", cascade="all, delete-orphan")
    patch_candidates = db.relationship("PatchCandidate", back_populates="device", cascade="all, delete-orphan")
