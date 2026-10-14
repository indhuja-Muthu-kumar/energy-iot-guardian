from __future__ import annotations

from app.extensions import db


class SyncLog(db.Model):
    __tablename__ = "sync_logs"

    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(40), nullable=False)
    details = db.Column(db.Text, nullable=True)
    records_processed = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, server_default=db.func.now())
    completed_at = db.Column(db.DateTime, nullable=True)
