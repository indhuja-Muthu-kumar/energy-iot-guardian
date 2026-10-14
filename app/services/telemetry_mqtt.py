from __future__ import annotations

import logging
import os

import paho.mqtt.client as mqtt
from flask import Flask

from app.extensions import db
from app.services.telemetry_service import (
    TelemetryDeviceError,
    TelemetryValidationError,
    ingest_telemetry_message,
)

logger = logging.getLogger(__name__)


def run_telemetry_subscriber(app: Flask) -> None:
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"energy-iot-cve-monitor-{os.getpid()}",
    )
    client.reconnect_delay_set(min_delay=1, max_delay=30)
    username = app.config["TELEMETRY_MQTT_USERNAME"]
    password = app.config["TELEMETRY_MQTT_PASSWORD"]
    if password and not username:
        raise ValueError(
            "TELEMETRY_MQTT_PASSWORD requires TELEMETRY_MQTT_USERNAME."
        )
    if username:
        client.username_pw_set(username, password)
    if app.config["TELEMETRY_MQTT_TLS"]:
        client.tls_set()

    def on_connect(client, _userdata, _flags, reason_code, _properties):
        if reason_code.is_failure:
            logger.error("MQTT connection failed: %s", reason_code)
            return
        topic = app.config["TELEMETRY_MQTT_TOPIC"]
        logger.info("Connected to MQTT broker; subscribing to %s", topic)
        result, message_id = client.subscribe(topic, qos=0)
        if result != mqtt.MQTT_ERR_SUCCESS:
            logger.error(
                "MQTT subscribe request failed for %s (result=%s)",
                topic,
                result,
            )
        else:
            logger.info(
                "MQTT subscribe request sent for %s (message_id=%s); "
                "waiting for broker acknowledgement",
                topic,
                message_id,
            )

    def on_subscribe(
        _client,
        _userdata,
        message_id,
        reason_codes,
        _properties,
    ):
        if any(reason_code.is_failure for reason_code in reason_codes):
            logger.error(
                "MQTT broker rejected subscription (message_id=%s, reasons=%s)",
                message_id,
                reason_codes,
            )
        else:
            logger.info(
                "MQTT subscription acknowledged (message_id=%s, reasons=%s)",
                message_id,
                reason_codes,
            )

    def on_disconnect(
        _client,
        _userdata,
        _disconnect_flags,
        reason_code,
        _properties,
    ):
        if reason_code.is_failure:
            logger.warning("MQTT disconnected unexpectedly: %s", reason_code)
        else:
            logger.info("MQTT disconnected: %s", reason_code)

    def on_message(_client, _userdata, message):
        with app.app_context():
            try:
                inserted = ingest_telemetry_message(message.topic, message.payload)
                logger.info(
                    "Telemetry %s from topic %s",
                    "stored" if inserted else "duplicate ignored",
                    message.topic,
                )
            except (TelemetryValidationError, TelemetryDeviceError) as error:
                logger.warning("Rejected MQTT telemetry: %s", error)
            except Exception:
                db.session.rollback()
                logger.exception("Could not store MQTT telemetry.")

    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    host = app.config["TELEMETRY_MQTT_BROKER_HOST"]
    port = app.config["TELEMETRY_MQTT_BROKER_PORT"]
    logger.info("Connecting telemetry subscriber to %s:%s", host, port)
    client.connect_async(host, port, keepalive=60)
    client.loop_forever(retry_first_connection=True)
