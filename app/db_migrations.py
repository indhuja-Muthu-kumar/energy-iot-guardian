from __future__ import annotations

from sqlalchemy import inspect, text

from app.extensions import db


def ensure_firmware_version_column() -> None:
    inspector = inspect(db.engine)
    if not inspector.has_table("devices"):
        return

    columns = {column["name"] for column in inspector.get_columns("devices")}
    if "firmware_version" not in columns:
        with db.engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE devices ADD COLUMN firmware_version VARCHAR(120)")
            )
    with db.engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE devices "
                "SET firmware_version = firmware "
                "WHERE firmware_version IS NULL "
                "AND firmware IS NOT NULL "
                "AND LOWER(TRIM(firmware)) NOT IN ('', 'unknown')"
            )
        )


def ensure_firmware_evidence_columns() -> None:
    inspector = inspect(db.engine)
    if not inspector.has_table("devices"):
        return

    columns = {column["name"] for column in inspector.get_columns("devices")}
    new_columns = {
        "firmware_evidence_source": "VARCHAR(160)",
        "firmware_evidence_method": "VARCHAR(120)",
        "firmware_evidence_note": "TEXT",
        "firmware_evidence_collected_at": "DATETIME",
        "firmware_verification_status": "VARCHAR(30) NOT NULL DEFAULT 'UNKNOWN'",
        "firmware_confidence": "VARCHAR(20) NOT NULL DEFAULT 'none'",
    }
    missing_columns = {
        name: definition
        for name, definition in new_columns.items()
        if name not in columns
    }
    if missing_columns:
        with db.engine.begin() as connection:
            for name, definition in missing_columns.items():
                connection.execute(
                    text(
                        "ALTER TABLE devices "
                        f"ADD COLUMN {name} {definition}"
                    )
                )

    with db.engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE devices "
                "SET firmware_verification_status = 'REPORTED', "
                "firmware_confidence = 'low', "
                "firmware_evidence_source = 'Legacy inventory', "
                "firmware_evidence_method = 'Collection method unknown', "
                "firmware_evidence_note = "
                "'Existing value predates evidence tracking; collection time is unknown.' "
                "WHERE firmware_verification_status = 'UNKNOWN' "
                "AND COALESCE(NULLIF(TRIM(firmware_version), ''), "
                "NULLIF(TRIM(firmware), '')) IS NOT NULL "
                "AND LOWER(COALESCE(NULLIF(TRIM(firmware_version), ''), "
                "NULLIF(TRIM(firmware), ''))) != 'unknown'"
            )
        )


def ensure_telemetry_columns() -> None:
    inspector = inspect(db.engine)
    if not inspector.has_table("scans"):
        return

    migrations = {
        "telemetry_readings": {
            "ingest_source": "VARCHAR(20) NOT NULL DEFAULT 'mqtt'",
            "payload_source": "VARCHAR(30) NOT NULL DEFAULT 'unknown'",
            "timestamp_source": "VARCHAR(30) NOT NULL DEFAULT 'unknown'",
            "source_uptime_ms": "BIGINT",
        },
        "scans": {
            "scan_type": "VARCHAR(30) NOT NULL DEFAULT 'device'",
        },
        "findings": {
            "component_name": "VARCHAR(100)",
            "component_version": "VARCHAR(80)",
            "match_status": "VARCHAR(30) NOT NULL DEFAULT 'potential'",
            "confidence": "VARCHAR(20) NOT NULL DEFAULT 'low'",
        },
        "cves": {
            "cvss_vector": "VARCHAR(120)",
        },
    }
    for table_name, new_columns in migrations.items():
        if not inspector.has_table(table_name):
            continue
        existing_columns = {
            column["name"] for column in inspector.get_columns(table_name)
        }
        missing_columns = {
            name: definition
            for name, definition in new_columns.items()
            if name not in existing_columns
        }
        if missing_columns:
            with db.engine.begin() as connection:
                for name, definition in missing_columns.items():
                    connection.execute(
                        text(
                            f"ALTER TABLE {table_name} "
                            f"ADD COLUMN {name} {definition}"
                        )
                    )


def ensure_telemetry_device_id_column(
    telemetry_device_id: str,
    vendor: str,
    model: str,
) -> None:
    inspector = inspect(db.engine)
    if not inspector.has_table("devices"):
        return

    columns = {column["name"] for column in inspector.get_columns("devices")}
    if "telemetry_device_id" not in columns:
        with db.engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE devices ADD COLUMN telemetry_device_id VARCHAR(80)")
            )

    index_name = "uq_devices_telemetry_device_id"
    indexes = {index["name"] for index in inspect(db.engine).get_indexes("devices")}
    if index_name not in indexes:
        with db.engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE UNIQUE INDEX uq_devices_telemetry_device_id "
                    "ON devices (telemetry_device_id)"
                )
            )

    matches = db.session.execute(
        text(
            "SELECT id, telemetry_device_id FROM devices "
            "WHERE name = :name AND vendor = :vendor AND model = :model "
            "ORDER BY id"
        ),
        {
            "name": telemetry_device_id,
            "vendor": vendor,
            "model": model,
        },
    ).all()
    existing_assignment = db.session.execute(
        text(
            "SELECT id FROM devices "
            "WHERE telemetry_device_id = :telemetry_device_id"
        ),
        {"telemetry_device_id": telemetry_device_id},
    ).scalar_one_or_none()

    if (
        len(matches) == 1
        and matches[0].telemetry_device_id in (None, telemetry_device_id)
        and existing_assignment in (None, matches[0].id)
    ):
        with db.engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE devices SET telemetry_device_id = :telemetry_device_id "
                    "WHERE id = :device_id AND telemetry_device_id IS NULL"
                ),
                {
                    "telemetry_device_id": telemetry_device_id,
                    "device_id": matches[0].id,
                },
            )
            if "simulation_status" in columns:
                connection.execute(
                    text(
                        "UPDATE devices SET simulation_status = 'simulated' "
                        "WHERE id = :device_id"
                    ),
                    {"device_id": matches[0].id},
                )


def ensure_device_component_schema() -> None:
    inspector = inspect(db.engine)
    if not inspector.has_table("devices"):
        return

    columns = {column["name"] for column in inspector.get_columns("devices")}
    if "simulation_status" not in columns:
        with db.engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE devices ADD COLUMN simulation_status "
                    "VARCHAR(30) NOT NULL DEFAULT 'unknown'"
                )
            )

    from app.models.device_component import DeviceComponent

    DeviceComponent.__table__.create(db.engine, checkfirst=True)
