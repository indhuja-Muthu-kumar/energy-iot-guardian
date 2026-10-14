from __future__ import annotations

from app.extensions import db


class CVE(db.Model):
    __tablename__ = "cves"

    id = db.Column(db.String(32), primary_key=True)
    description = db.Column(db.Text, nullable=True)
    published_date = db.Column(db.DateTime, nullable=True)
    last_modified_date = db.Column(db.DateTime, nullable=True)
    severity = db.Column(db.String(30), nullable=True)
    cvss_score = db.Column(db.Float, nullable=True)
    cvss_vector = db.Column(db.String(120), nullable=True)
    attack_vector = db.Column(db.String(50), nullable=True)
    cwe = db.Column(db.String(80), nullable=True)
    source = db.Column(db.String(40), default="nvd")
    raw = db.Column(db.JSON, nullable=True)

    findings = db.relationship("Finding", back_populates="cve", cascade="all, delete-orphan")
