from __future__ import annotations

from marshmallow import Schema, fields, validate


class DeviceSchema(Schema):
    id = fields.Int(dump_only=True)
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
    status = fields.Str(load_default="active")
    notes = fields.Str(
        load_default=None,
        allow_none=True,
        validate=validate.Length(max=5000),
    )
