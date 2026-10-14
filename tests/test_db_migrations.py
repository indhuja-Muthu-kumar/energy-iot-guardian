from sqlalchemy import inspect, text

from app import create_app
from app.db_migrations import (
    ensure_firmware_version_column,
    ensure_telemetry_columns,
)
from app.extensions import db
from app.models.cve import CVE
from app.models.device import Device
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.telemetry import TelemetryReading
from app.models.user import User


def test_firmware_version_migration_preserves_rows_and_unknown_values():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        with db.engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE devices ("
                    "id INTEGER PRIMARY KEY, "
                    "firmware VARCHAR(120)"
                    ")"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO devices (id, firmware) "
                    "VALUES (1, '1.2.3'), (2, 'unknown'), (3, '')"
                )
            )

        ensure_firmware_version_column()
        ensure_firmware_version_column()

        columns = {
            column["name"]
            for column in inspect(db.engine).get_columns("devices")
        }
        assert "firmware_version" in columns
        rows = db.session.execute(
            text(
                "SELECT id, firmware, firmware_version "
                "FROM devices ORDER BY id"
            )
        ).all()
        assert rows == [
            (1, "1.2.3", "1.2.3"),
            (2, "unknown", None),
            (3, "", None),
        ]


def test_telemetry_migration_adds_columns_idempotently_without_rewriting_rows():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        with db.engine.begin() as connection:
            connection.execute(text("CREATE TABLE scans (id INTEGER PRIMARY KEY)"))
            connection.execute(text("CREATE TABLE findings (id INTEGER PRIMARY KEY)"))
            connection.execute(text("CREATE TABLE cves (id VARCHAR(32) PRIMARY KEY)"))
            connection.execute(
                text(
                    "CREATE TABLE telemetry_readings ("
                    "id INTEGER PRIMARY KEY, "
                    "source_message_id VARCHAR(80) NOT NULL"
                    ")"
                )
            )
            connection.execute(text("INSERT INTO scans (id) VALUES (1)"))
            connection.execute(
                text(
                    "INSERT INTO telemetry_readings (id, source_message_id) "
                    "VALUES (1, 'legacy-reading')"
                )
            )
        ensure_telemetry_columns()
        ensure_telemetry_columns()

        assert {
            column["name"] for column in inspect(db.engine).get_columns("scans")
        } >= {"id", "scan_type"}
        assert {
            column["name"] for column in inspect(db.engine).get_columns("findings")
        } >= {
            "id",
            "component_name",
            "component_version",
            "match_status",
            "confidence",
        }
        assert {
            column["name"] for column in inspect(db.engine).get_columns("cves")
        } >= {"id", "cvss_vector"}
        assert {
            column["name"]
            for column in inspect(db.engine).get_columns("telemetry_readings")
        } >= {"id", "source_message_id", "ingest_source"}
        assert db.session.execute(
            text(
                "SELECT ingest_source FROM telemetry_readings "
                "WHERE source_message_id = 'legacy-reading'"
            )
        ).scalar_one() == "mqtt"
        assert db.session.execute(text("SELECT id FROM scans")).scalar_one() == 1


def test_init_db_creates_telemetry_table_without_removing_history():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.create_all()
        device = Device(
            name="Archived test inverter",
            vendor="Example Energy",
            model="INV-1",
            firmware="unknown",
            status="archived",
        )
        user = User(
            username="migration-admin",
            email="migration-admin@example.com",
            is_admin=True,
        )
        user.set_password("migration-test-password")
        cve = CVE(id="CVE-2025-1133", description="Historical advisory")
        scan = Scan(
            device=device,
            status="completed",
            summary="Historical scan summary",
        )
        finding = Finding(
            scan=scan,
            device=device,
            cve=cve,
            severity="HIGH",
            summary="Historical finding summary",
            evidence="Historical evidence",
        )
        db.session.add_all([device, user, cve, scan, finding])
        db.session.commit()
        device_id = device.id
        user_id = user.id
        scan_id = scan.id
        finding_id = finding.id
        password_hash = user.password_hash
        TelemetryReading.__table__.drop(db.engine)

    result = app.test_cli_runner().invoke(args=["init-db"])

    assert result.exit_code == 0, result.output
    with app.app_context():
        tables = set(inspect(db.engine).get_table_names())
        assert "telemetry_readings" in tables
        assert db.session.query(Device).count() == 1
        assert db.session.query(User).count() == 1
        assert db.session.query(Scan).count() == 1
        assert db.session.query(Finding).count() == 1
        assert db.session.query(CVE).count() == 1
        assert db.session.get(Device, device_id).status == "archived"
        assert db.session.get(User, user_id).password_hash == password_hash
        assert db.session.get(Scan, scan_id).summary == "Historical scan summary"
        assert db.session.get(Finding, finding_id).evidence == "Historical evidence"
