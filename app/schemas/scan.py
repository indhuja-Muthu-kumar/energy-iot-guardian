from __future__ import annotations

from marshmallow import Schema, fields


class ScanSchema(Schema):
    id = fields.Int(dump_only=True)
    device_id = fields.Int(required=True)
    status = fields.Str(load_default="queued")
    summary = fields.Str(load_default=None, allow_none=True)
    notes = fields.Str(load_default=None, allow_none=True)
