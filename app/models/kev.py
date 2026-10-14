from __future__ import annotations

from app.extensions import db


class KEVEntry(db.Model):
    __tablename__ = "kev_entries"

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    vendor_project = db.Column(db.String(120), nullable=False)
    product = db.Column(db.String(120), nullable=False)
    short_description = db.Column(db.Text, nullable=True)
    required_action = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    source = db.Column(db.String(20), default="CISA KEV")
    created_at = db.Column(db.DateTime, server_default=db.func.now())
