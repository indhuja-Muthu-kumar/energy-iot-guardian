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


def ensure_telemetry_columns() -> None:
    inspector = inspect(db.engine)
    if not inspector.has_table("scans"):
        return

    migrations = {
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
