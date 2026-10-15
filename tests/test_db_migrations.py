import pytest
from sqlalchemy import inspect, text

from app import create_app
from app.db_migrations import (
    ensure_device_component_schema,
    ensure_firmware_evidence_columns,
    ensure_firmware_version_column,
    ensure_telemetry_columns,
    ensure_telemetry_device_id_column,
)
from app.extensions import db
from app.models.cve import CVE
from app.models.device import Device
from app.models.device_component import DeviceComponent
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.telemetry import TelemetryReading
from app.models.user import User
from app.services.device_bootstrap import (
    SMA_REFERENCE_MODELS,
    SMA_REFERENCE_URL,
    SMA_REFERENCE_VERSION,
    ensure_arduino_uno_device,
    ensure_sma_firmware_reference_device,
)


def test_component_evidence_migration_adds_simulation_status_and_table_safely():
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
                    "name VARCHAR(150) NOT NULL"
                    ")"
                )
            )
            connection.execute(
                text("INSERT INTO devices (id, name) VALUES (1, 'Existing asset')")
            )

        ensure_device_component_schema()
        ensure_device_component_schema()

        assert "simulation_status" in {
            column["name"] for column in inspect(db.engine).get_columns("devices")
        }
        assert "device_components" in inspect(db.engine).get_table_names()
        assert db.session.execute(
            text(
                "SELECT id, name, simulation_status FROM devices"
            )
        ).one() == (1, "Existing asset", "unknown")


def test_arduino_uno_bootstrap_is_repeatable_and_keeps_unverified_versions_unknown():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.create_all()

        first = ensure_arduino_uno_device()
        second = ensure_arduino_uno_device()

        assert first.id == second.id
        assert Device.query.filter_by(
            name="ArduinoUno-SecurityLab-01"
        ).count() == 1
        assert first.vendor == "Arduino"
        assert first.model == "Arduino Uno (revision unknown)"
        assert first.asset_tag == "ArduinoUno-SecurityLab-01"
        assert first.site == "Security Lab"
        assert first.simulation_status == "unknown"
        assert first.firmware_version is None
        assert first.firmware_verification_status == "UNKNOWN"
        assert {
            component.component_key for component in first.components
        } == {
            "board",
            "microcontroller",
            "application",
            "framework",
            "bootloader",
        }
        assert all(
            component.version is None
            for component in DeviceComponent.query.filter(
                DeviceComponent.device_id == first.id,
                DeviceComponent.component_type == "software",
            )
        )
        assert Device.query.count() == 1


def test_arduino_uno_bootstrap_clears_misattributed_sma_firmware_without_deleting_device():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.create_all()
        device = ensure_arduino_uno_device()
        device.firmware = SMA_REFERENCE_VERSION
        device.firmware_version = SMA_REFERENCE_VERSION
        device.firmware_verification_status = "REPORTED"
        device.firmware_confidence = "low"
        device.firmware_evidence_source = "Operator entry"
        device.firmware_evidence_method = "Manual inventory entry"
        db.session.commit()
        device_id = device.id

        corrected = ensure_arduino_uno_device()

        assert corrected.id == device_id
        assert Device.query.count() == 1
        assert corrected.firmware == "unknown"
        assert corrected.firmware_version is None
        assert corrected.firmware_verification_status == "UNKNOWN"
        assert corrected.firmware_confidence == "none"
        assert corrected.firmware_evidence_source is None
        assert "not this Arduino Uno" in corrected.firmware_evidence_note


def test_sma_reference_bootstrap_records_exact_documented_pairs_without_duplicates():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.create_all()
        legacy_test_device = Device(
            name="SMA Sunny Boy TL-21 Test Device",
            vendor="SMA Solar Technology",
            model="Sunny Boy TL-21",
            firmware="2.60.03.R",
            firmware_version="2.60.03.R",
        )
        db.session.add(legacy_test_device)
        db.session.commit()

        first = ensure_sma_firmware_reference_device()
        second = ensure_sma_firmware_reference_device()
        components = {
            component.product: component
            for component in DeviceComponent.query.filter_by(device_id=first.id)
        }

        assert first.id == second.id == legacy_test_device.id
        assert Device.query.count() == 1
        assert first.simulation_status == "reference"
        assert first.firmware == "unknown"
        assert first.firmware_version is None
        assert first.firmware_verification_status == "UNKNOWN"
        assert set(components) == set(SMA_REFERENCE_MODELS)
        assert all(
            component.version == SMA_REFERENCE_VERSION
            and component.evidence_source == SMA_REFERENCE_URL
            and component.evidence_status == "REFERENCE"
            and component.confidence == "high"
            and "not firmware observed" in component.evidence_note
            for component in components.values()
        )
        assert components["SB 4000TL-21"].version == "2.60.03.R"
        assert "Sunny Boy TL-21" not in components


def test_sma_reference_bootstrap_refuses_duplicate_reference_records():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.create_all()
        db.session.add_all(
            [
                Device(
                    name="SMA Sunny Boy TL-21 Test Device",
                    vendor="SMA Solar Technology",
                    model="Sunny Boy TL-21",
                    firmware="2.60.03.R",
                    firmware_version="2.60.03.R",
                ),
                Device(
                    name="SMA Sunny Boy TL-21 Firmware Reference (not installed)",
                    vendor="SMA Solar Technology",
                    model="Sunny Boy TL-21",
                    firmware="2.60.03.R",
                    firmware_version="2.60.03.R",
                ),
            ]
        )
        db.session.commit()

        with pytest.raises(RuntimeError, match="Multiple SMA firmware reference"):
            ensure_sma_firmware_reference_device()

        assert Device.query.count() == 2
        assert DeviceComponent.query.count() == 0


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


def test_firmware_evidence_migration_is_additive_idempotent_and_marks_legacy_as_reported():
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
                    "firmware VARCHAR(120), "
                    "firmware_version VARCHAR(120)"
                    ")"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO devices (id, firmware, firmware_version) "
                    "VALUES (1, '2.1.0', '2.1.0'), "
                    "(2, 'unknown', NULL)"
                )
            )

        ensure_firmware_evidence_columns()
        ensure_firmware_evidence_columns()

        columns = {
            column["name"]
            for column in inspect(db.engine).get_columns("devices")
        }
        assert {
            "firmware_evidence_source",
            "firmware_evidence_method",
            "firmware_evidence_note",
            "firmware_evidence_collected_at",
            "firmware_verification_status",
            "firmware_confidence",
        } <= columns
        rows = db.session.execute(
            text(
                "SELECT id, firmware, firmware_version, "
                "firmware_verification_status, firmware_confidence, "
                "firmware_evidence_source "
                "FROM devices ORDER BY id"
            )
        ).all()
        assert rows == [
            (1, "2.1.0", "2.1.0", "REPORTED", "low", "Legacy inventory"),
            (2, "unknown", None, "UNKNOWN", "none", None),
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
        } >= {
            "id",
            "source_message_id",
            "ingest_source",
            "payload_source",
            "timestamp_source",
            "source_uptime_ms",
        }
        assert db.session.execute(
            text(
                "SELECT ingest_source FROM telemetry_readings "
                "WHERE source_message_id = 'legacy-reading'"
            )
        ).scalar_one() == "mqtt"
        assert db.session.execute(
            text(
                "SELECT payload_source FROM telemetry_readings "
                "WHERE source_message_id = 'legacy-reading'"
            )
        ).scalar_one() == "unknown"
        assert db.session.execute(
            text(
                "SELECT timestamp_source, source_uptime_ms "
                "FROM telemetry_readings WHERE source_message_id = 'legacy-reading'"
            )
        ).one() == ("unknown", None)
        assert db.session.execute(text("SELECT id FROM scans")).scalar_one() == 1


def test_stable_telemetry_device_id_migration_is_additive_and_idempotent():
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
                    "name VARCHAR(150) NOT NULL, "
                    "vendor VARCHAR(120) NOT NULL, "
                    "model VARCHAR(120) NOT NULL, "
                    "status VARCHAR(50)"
                    ")"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO devices (id, name, vendor, model, status) "
                    "VALUES (1, 'SolarGuard-01', 'SMA Solar Technology', "
                    "'Sunny Boy TL-21', 'active'), "
                    "(2, 'Another device', 'Example', 'INV-1', 'active')"
                )
            )

        ensure_telemetry_device_id_column(
            "SolarGuard-01",
            "SMA Solar Technology",
            "Sunny Boy TL-21",
        )
        ensure_telemetry_device_id_column(
            "SolarGuard-01",
            "SMA Solar Technology",
            "Sunny Boy TL-21",
        )

        assert db.session.execute(
            text(
                "SELECT id, name, telemetry_device_id "
                "FROM devices ORDER BY id"
            )
        ).all() == [
            (1, "SolarGuard-01", "SolarGuard-01"),
            (2, "Another device", None),
        ]
        assert "uq_devices_telemetry_device_id" in {
            index["name"] for index in inspect(db.engine).get_indexes("devices")
        }


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
        assert db.session.query(Device).count() == 2
        uno = Device.query.filter_by(name="ArduinoUno-SecurityLab-01").one()
        assert uno.simulation_status == "unknown"
        assert uno.firmware_version is None
        assert db.session.query(User).count() == 1
        assert db.session.query(Scan).count() == 1
        assert db.session.query(Finding).count() == 1
        assert db.session.query(CVE).count() == 1
        assert db.session.get(Device, device_id).status == "archived"
        assert db.session.get(User, user_id).password_hash == password_hash
        assert db.session.get(Scan, scan_id).summary == "Historical scan summary"
        assert db.session.get(Finding, finding_id).evidence == "Historical evidence"
        result = app.test_cli_runner().invoke(args=["init-db"])
        assert result.exit_code == 0, result.output
        assert db.session.query(Device).count() == 2
