from __future__ import annotations

from marshmallow import Schema, fields


class DeviceQuerySchema(Schema):
    q = fields.Str(load_default="")
    page = fields.Int(load_default=1)


class CVEQuerySchema(Schema):
    q = fields.Str(load_default="")
    severity = fields.Str(load_default="")
