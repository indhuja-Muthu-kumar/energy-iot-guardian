from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    ENV = os.getenv("FLASK_ENV", "development")
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///energy_iot_cve_monitor.db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CPE_API_BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")
    KEV_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    TELEMETRY_MQTT_BROKER_HOST = os.getenv(
        "TELEMETRY_MQTT_BROKER_HOST",
        "test.mosquitto.org",
    )
    TELEMETRY_MQTT_BROKER_PORT = int(
        os.getenv("TELEMETRY_MQTT_BROKER_PORT", "1883")
    )
    TELEMETRY_MQTT_TOPIC = os.getenv(
        "TELEMETRY_MQTT_TOPIC",
        "energy-iot-cve-monitor/477780562303197185/SolarGuard-01/telemetry",
    )
    TELEMETRY_MQTT_USERNAME = os.getenv("TELEMETRY_MQTT_USERNAME", "")
    TELEMETRY_MQTT_PASSWORD = os.getenv("TELEMETRY_MQTT_PASSWORD", "")
    TELEMETRY_MQTT_TLS = os.getenv(
        "TELEMETRY_MQTT_TLS",
        "false",
    ).strip().lower() in {"1", "true", "yes"}
    TELEMETRY_STALE_AFTER_SECONDS = 10
    TELEMETRY_HISTORY_LIMIT = 12
    TELEMETRY_DEVICE_ID = "SolarGuard-01"
    TELEMETRY_DEVICE_VENDOR = "SMA Solar Technology"
    TELEMETRY_DEVICE_MODEL = "Sunny Boy TL-21"
    JSON_SORT_KEYS = False


class DevelopmentConfig(Config):
    DEBUG = True
    ENV = "development"


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    ENV = "testing"


class ProductionConfig(Config):
    DEBUG = False
    ENV = "production"


config = {
    "default": Config,
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
