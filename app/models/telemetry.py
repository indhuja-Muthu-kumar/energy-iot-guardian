from __future__ import annotations

from app.extensions import db


class TelemetryReading(db.Model):
    __tablename__ = "telemetry_readings"
    __table_args__ = (
        db.UniqueConstraint(
            "source_message_id",
            name="uq_telemetry_source_message_id",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(
        db.Integer,
        db.ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    source_message_id = db.Column(db.String(80), nullable=False)
    voltage = db.Column(db.Float, nullable=False)
    current = db.Column(db.Float, nullable=False)
    power = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    received_at = db.Column(
        db.DateTime,
        nullable=False,
        index=True,
    )
    ingest_source = db.Column(
        db.String(20),
        nullable=False,
        default="mqtt",
        server_default="mqtt",
    )
    telemetry_status = db.Column(db.String(20), nullable=False)
    chip_model = db.Column(db.String(80), nullable=False)
    chip_revision = db.Column(db.Integer, nullable=False)
    arduino_core_version = db.Column(db.String(80), nullable=False)
    esp_idf_version = db.Column(db.String(80), nullable=False)

    device = db.relationship("Device")
