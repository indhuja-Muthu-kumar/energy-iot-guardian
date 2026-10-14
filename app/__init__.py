from __future__ import annotations

import logging
import os
from getpass import getpass

import click
from dotenv import load_dotenv
from click import ClickException
from flask import Flask, render_template

from app.config import config
from app.extensions import csrf, db, limiter, login_manager

load_dotenv()


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config["default"])

    if test_config:
        app.config.from_mapping(test_config)
    else:
        app.config.from_prefixed_env()

    environment = app.config.get("ENV")
    if not isinstance(environment, str) or environment.lower() not in {
        "development",
        "testing",
        "production",
    }:
        raise RuntimeError(
            "FLASK_ENV must be one of: development, testing, or production."
        )
    app.config["ENV"] = environment.lower()

    if app.config["ENV"] == "production":
        secret_key = app.config.get("SECRET_KEY")
        explicit_secret = (
            test_config is not None and "SECRET_KEY" in test_config
        ) or bool(os.getenv("SECRET_KEY"))
        if (
            not explicit_secret
            or not isinstance(secret_key, str)
            or len(secret_key) < 32
            or secret_key != secret_key.strip()
            or secret_key.lower()
            in {
                "change-me",
                "change-this-secret-key",
                "dev-secret-key",
                "replace-with-a-random-secret",
            }
            or len(set(secret_key)) < 12
        ):
            raise RuntimeError(
                "Production requires a private SECRET_KEY of at least 32 "
                "characters. Generate one with a cryptographically secure "
                "random generator."
            )

        explicit_database_url = (
            test_config is not None
            and "SQLALCHEMY_DATABASE_URI" in test_config
        ) or bool(
            os.getenv("DATABASE_URL")
            or os.getenv("FLASK_SQLALCHEMY_DATABASE_URI")
        )
        if (
            not explicit_database_url
            or not app.config.get("SQLALCHEMY_DATABASE_URI")
        ):
            raise RuntimeError(
                "Production requires an explicit DATABASE_URL; the local "
                "SQLite fallback is for development only."
            )

        app.config.update(
            DEBUG=False,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Lax",
            SESSION_COOKIE_SECURE=True,
            REMEMBER_COOKIE_HTTPONLY=True,
            REMEMBER_COOKIE_SECURE=True,
        )

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    from app.blueprints.auth import auth_bp
    from app.blueprints.pages import pages_bp
    from app.blueprints.api_devices import api_devices_bp
    from app.blueprints.api_scans import api_scans_bp
    from app.blueprints.api_cves import api_cves_bp
    from app.blueprints.api_dashboard import api_dashboard_bp
    from app.blueprints.api_kev import api_kev_bp
    from app.blueprints.api_reports import api_reports_bp
    from app.blueprints.api_admin import api_admin_bp

    app.register_blueprint(pages_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(api_devices_bp, url_prefix="/api/devices")
    app.register_blueprint(api_scans_bp, url_prefix="/api/scans")
    app.register_blueprint(api_cves_bp, url_prefix="/api/cves")
    app.register_blueprint(api_dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(api_kev_bp, url_prefix="/api/kev")
    app.register_blueprint(api_reports_bp, url_prefix="/api/reports")
    app.register_blueprint(api_admin_bp, url_prefix="/api/admin")

    login_manager.login_view = "auth.login"

    @login_manager.user_loader
    def load_user(user_id: str):
        from app.models.user import User

        return db.session.get(User, int(user_id))

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(500)
    def internal_error(_error):
        return render_template("errors/500.html"), 500

    logging.basicConfig(level=logging.INFO)

    @app.cli.command("init-db")
    def init_db_cmd():
        from app.models.alert import SecurityAlert  # noqa: F401
        from app.models.audit import AuditLog  # noqa: F401
        from app.models.cve import CVE  # noqa: F401
        from app.models.device import Device  # noqa: F401
        from app.models.finding import Finding  # noqa: F401
        from app.models.kev import KEVEntry  # noqa: F401
        from app.models.patch import PatchCandidate  # noqa: F401
        from app.models.scan import Scan  # noqa: F401
        from app.models.sync_log import SyncLog  # noqa: F401
        from app.models.telemetry import TelemetryReading  # noqa: F401
        from app.models.user import User  # noqa: F401

        db.create_all()
        from app.db_migrations import (
            ensure_firmware_version_column,
            ensure_telemetry_columns,
        )

        ensure_firmware_version_column()
        ensure_telemetry_columns()
        print("Database initialized.")


    @app.cli.command("setup-wokwi-device")
    def setup_wokwi_device_cmd():
        from app.models.device import ARCHIVED_DEVICE_STATUS, Device

        matches = Device.query.filter_by(
            name=app.config["TELEMETRY_DEVICE_ID"]
        ).order_by(Device.id.asc()).all()
        if len(matches) > 1:
            raise ClickException(
                "Multiple SolarGuard-01 records exist. Resolve the duplicate "
                "records manually; none were changed."
            )
        if matches:
            device = matches[0]
            expected_identity = (
                app.config["TELEMETRY_DEVICE_VENDOR"],
                app.config["TELEMETRY_DEVICE_MODEL"],
            )
            if (device.vendor, device.model) != expected_identity:
                raise ClickException(
                    "The existing SolarGuard-01 record has different vendor/"
                    "model labels. No records were changed."
                )
            if device.status == ARCHIVED_DEVICE_STATUS:
                raise ClickException(
                    "SolarGuard-01 exists but is archived. No records were "
                    "changed; have an administrator explicitly restore it or "
                    "resolve the archived record before setup."
                )
            print(f"SolarGuard-01 already exists as active device ID {device.id}.")
            return

        device = Device(
            name=app.config["TELEMETRY_DEVICE_ID"],
            vendor=app.config["TELEMETRY_DEVICE_VENDOR"],
            model=app.config["TELEMETRY_DEVICE_MODEL"],
            firmware="unknown",
            firmware_version=None,
            status="active",
            notes=(
                "Simulated solar asset metadata for the Wokwi ESP32 demo; "
                "not verified as SMA inverter hardware."
            ),
        )
        db.session.add(device)
        db.session.commit()
        print(f"Registered SolarGuard-01 as active device ID {device.id}.")


    @app.cli.command("telemetry-worker")
    def telemetry_worker_cmd():
        from app.services.telemetry_mqtt import run_telemetry_subscriber

        run_telemetry_subscriber(app)


    @app.cli.command("create-admin")
    def create_admin_cmd():
        from app.models.user import User

        username = input("Username: ").strip()
        email = input("Email: ").strip()

        if not username or not email:
            print("Username and email are required.")
            return

        if User.query.filter(
            (User.username == username) | (User.email == email)
        ).first():
            print("That username or email already exists.")
            return

        password = getpass("Password (hidden): ")
        confirmation = getpass("Confirm password (hidden): ")

        if len(password) < 14:
            print("Password must be at least 14 characters.")
            return

        if password != confirmation:
            print("Passwords do not match.")
            return

        user = User(username=username, email=email, is_admin=True)
        user.set_password(password)
        db.session.add(user)

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            print("Account creation failed. Check the database and try again.")
            return

        print(f"Admin created: {username}")


    @app.cli.command("sync-kev")
    def sync_kev_cmd():
        from app.services.kev_client import sync_kev_catalog

        records = sync_kev_catalog()
        print(f"Synced {records} KEV entries.")

    @app.cli.command("sync-nvd")
    @click.option("--keyword", default="Espressif ESP32")
    def sync_nvd_cmd(keyword: str):
        from app.services.nvd_sync_service import sync_nvd_catalog

        records = sync_nvd_catalog(keyword)
        print(f"Synced {records} NVD CVE records.")

    @app.cli.command("seed-demo-device")
    def seed_demo_device_cmd():
        from app.models.device import Device

        device = Device.query.filter_by(name="SMA Sunny Boy TL-21 Demo").first()
        if not device:
            device = Device(
                name="SMA Sunny Boy TL-21 Demo",
                vendor="SMA Solar Technology",
                model="Sunny Boy TL-21",
                firmware="unknown",
                site="Demo site",
                serial="DEMO-001",
                status="active",
                notes="Demo inventory item created by seed command.",
            )
            db.session.add(device)
            db.session.commit()
            print("Demo device created.")
        else:
            print("Demo device already exists.")

    return app
