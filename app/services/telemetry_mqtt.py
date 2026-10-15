from __future__ import annotations

import json
import logging
import os
import re
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import paho.mqtt.client as mqtt
from flask import Flask, current_app
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.services.telemetry_service import (
    MESSAGE_ID_PATTERN,
    TelemetryDeviceError,
    TelemetryValidationError,
    ingest_telemetry_message,
)

logger = logging.getLogger(__name__)
MAX_ACK_FIELD_LENGTH = 80
DEVICE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,80}")


def _read_lock_owner_pid(pid_path: Path) -> int | None:
    try:
        value = pid_path.read_text(encoding="ascii").strip()
        pid = int(value)
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return pid if pid > 0 else None


def _process_is_running(pid: int) -> bool | None:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        open_process.restype = wintypes.HANDLE
        get_exit_code = kernel32.GetExitCodeProcess
        get_exit_code.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        )
        get_exit_code.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        process = open_process(0x1000, False, pid)
        if not process:
            error_code = ctypes.get_last_error()
            if error_code == 87:
                return False
            if error_code == 5:
                return True
            return None

        try:
            exit_code = wintypes.DWORD()
            if not get_exit_code(process, ctypes.byref(exit_code)):
                return None
            return exit_code.value == 259
        finally:
            close_handle(process)

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


def _message_identity(raw: bytes) -> tuple[str | None, str | None]:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        return None, None
    if not isinstance(payload, dict):
        return None, None

    message_id = payload.get("message_id")
    device_id = payload.get("device_id")
    return (
        message_id
        if isinstance(message_id, str)
        and len(message_id) <= MAX_ACK_FIELD_LENGTH
        and MESSAGE_ID_PATTERN.fullmatch(message_id)
        else None,
        device_id
        if isinstance(device_id, str)
        and len(device_id) <= MAX_ACK_FIELD_LENGTH
        and DEVICE_ID_PATTERN.fullmatch(device_id)
        else None,
    )


def _payload_keys(raw: bytes) -> tuple[str, ...]:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        return ("<invalid-json>",)
    if not isinstance(payload, dict):
        return ("<non-object>",)
    return tuple(
        sorted(key for key in payload if isinstance(key, str))[:32]
    )


def _build_acknowledgement(
    message_id: str | None,
    device_id: str | None,
    outcome: str,
    reason: str,
    *,
    duplicate: bool = False,
    worker_id: str,
) -> bytes:
    payload = {
        "schema_version": 1,
        "type": "telemetry_ack",
        "message_id": message_id,
        "device_id": device_id,
        "outcome": outcome,
        "reason": reason[:200],
        "duplicate": duplicate,
        "worker_id": worker_id,
        "processed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def process_telemetry_message(client, topic: str, raw: bytes) -> dict:
    """Validate and store one message, then publish its storage outcome."""
    message_id, device_id = _message_identity(raw)
    worker_id = f"telemetry-worker-{os.getpid()}"

    try:
        inserted = ingest_telemetry_message(topic, raw)
    except (TelemetryValidationError, TelemetryDeviceError) as error:
        acknowledgement = _build_acknowledgement(
            message_id,
            device_id,
            "rejected",
            str(error),
            worker_id=worker_id,
        )
    except SQLAlchemyError:
        db.session.rollback()
        logger.exception("Database failed while storing MQTT telemetry.")
        acknowledgement = _build_acknowledgement(
            message_id,
            device_id,
            "error",
            "Storage failed; retry this message with the same message_id.",
            worker_id=worker_id,
        )
    else:
        acknowledgement = _build_acknowledgement(
            message_id,
            device_id,
            "stored",
            (
                "Telemetry committed to the database."
                if inserted
                else "Message was already committed; duplicate delivery ignored."
            ),
            duplicate=not inserted,
            worker_id=worker_id,
        )

    ack_topic = current_app.config["TELEMETRY_MQTT_ACK_TOPIC"]
    acknowledgement_payload = json.loads(acknowledgement)
    if acknowledgement_payload["outcome"] == "rejected":
        logger.warning(
            "Rejected MQTT telemetry "
            "(worker_id=%s, message_id=%s, device_id=%s, topic=%r, "
            "payload_keys=%r, reason=%s).",
            worker_id,
            message_id,
            device_id,
            topic,
            _payload_keys(raw),
            acknowledgement_payload["reason"],
        )
    try:
        result = client.publish(ack_topic, acknowledgement, qos=1, retain=False)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            logger.warning(
                "Could not publish telemetry acknowledgement (result=%s).",
                result.rc,
            )
        else:
            logger.debug(
                "Telemetry acknowledgement queued "
                "(message_id=%s, outcome=%s, duplicate=%s).",
                message_id,
                acknowledgement_payload["outcome"],
                acknowledgement_payload["duplicate"],
            )
    except Exception:
        logger.exception("Could not publish telemetry acknowledgement.")

    return acknowledgement_payload


@contextmanager
def _single_worker_lock(app: Flask):
    lock_path = Path(app.instance_path) / "telemetry-worker.lock"
    pid_path = lock_path.with_suffix(".pid")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = lock_path.open("a+b")
    lock_file.seek(0, os.SEEK_END)
    if lock_file.tell() == 0:
        lock_file.write(b"\0")
        lock_file.flush()
    lock_file.seek(0)

    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        owner_pid = _read_lock_owner_pid(pid_path)
        owner_is_running = (
            _process_is_running(owner_pid)
            if owner_pid is not None
            else None
        )
        lock_file.close()
        if owner_pid is None:
            owner_detail = "owner PID is unavailable"
        elif owner_is_running is True:
            owner_detail = f"owner PID {owner_pid} is still running"
        elif owner_is_running is False:
            owner_detail = (
                f"recorded owner PID {owner_pid} is stale, but the OS lock "
                "is still held"
            )
        else:
            owner_detail = f"could not verify owner PID {owner_pid}"
        raise RuntimeError(
            "A telemetry worker already holds the project worker lock. "
            f"{owner_detail}; stop that worker before starting another."
        ) from error

    try:
        pid_path.write_text(f"{os.getpid()}\n", encoding="ascii")
        yield
    finally:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()


def run_telemetry_subscriber(app: Flask) -> None:
    with _single_worker_lock(app):
        _run_telemetry_subscriber(app)


def _run_telemetry_subscriber(app: Flask) -> None:
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=(
            f"{app.config['TELEMETRY_MQTT_CLIENT_ID']}-{os.getpid()}"
        ),
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
        result, message_id = client.subscribe(topic, qos=1)
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
                acknowledgement = process_telemetry_message(
                    _client,
                    message.topic,
                    message.payload,
                )
                logger.info(
                    "Processed MQTT telemetry "
                    "(worker_id=%s, message_id=%s, device_id=%s, "
                    "outcome=%s, duplicate=%s).",
                    acknowledgement["worker_id"],
                    acknowledgement["message_id"],
                    acknowledgement["device_id"],
                    acknowledgement["outcome"],
                    acknowledgement["duplicate"],
                )
            except Exception:
                db.session.rollback()
                logger.exception("Unexpected telemetry worker processing failure.")

    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    host = app.config["TELEMETRY_MQTT_BROKER_HOST"]
    port = app.config["TELEMETRY_MQTT_BROKER_PORT"]
    logger.info(
        "Connecting telemetry subscriber to %s:%s (acknowledgements on %s)",
        host,
        port,
        app.config["TELEMETRY_MQTT_ACK_TOPIC"],
    )
    client.connect_async(host, port, keepalive=60)
    client.loop_forever(retry_first_connection=True)
