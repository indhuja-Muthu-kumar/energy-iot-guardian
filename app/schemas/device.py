from __future__ import annotations

from marshmallow import Schema, fields, validate


class DeviceSchema(Schema):
    id = fields.Int(dump_only=True)
    telemetry_device_id = fields.Str(dump_only=True)
    name = fields.Str(required=True, validate=validate.Length(min=1, max=150))
    vendor = fields.Str(required=True, validate=validate.Length(min=1, max=120))
    model = fields.Str(required=True, validate=validate.Length(min=1, max=120))
    firmware = fields.Str(
        load_default="unknown",
        validate=validate.Length(min=1, max=120),
    )
    firmware_version = fields.Str(
        load_default=None,
        allow_none=True,
        validate=validate.Length(max=120),
    )
    firmware_evidence_source = fields.Str(
        load_default=None,
        allow_none=True,
        validate=validate.Length(max=160),
    )
    firmware_evidence_method = fields.Str(
        load_default=None,
        allow_none=True,
        validate=validate.Length(max=120),
    )
    firmware_evidence_note = fields.Str(
        load_default=None,
        allow_none=True,
        validate=validate.Length(max=2000),
    )
    firmware_evidence_collected_at = fields.DateTime(dump_only=True)
    firmware_verification_status = fields.Str(dump_only=True)
    firmware_confidence = fields.Str(dump_only=True)
    serial = fields.Str(
        load_default=None,
        allow_none=True,
        validate=validate.Length(max=80),
    )
    asset_tag = fields.Str(
        load_default=None,
        allow_none=True,
        validate=validate.Length(max=80),
    )
    site = fields.Str(
        load_default=None,
        allow_none=True,
        validate=validate.Length(max=120),
    )
    simulation_status = fields.Str(dump_only=True)
    status = fields.Str(load_default="active")
    notes = fields.Str(
        load_default=None,
        allow_none=True,
        validate=validate.Length(max=5000),
    )
