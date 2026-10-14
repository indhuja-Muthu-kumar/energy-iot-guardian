
import json
import os

import paho.mqtt.client as mqtt
from dotenv import load_dotenv

load_dotenv()

DEFAULT_BROKER = os.getenv(
    "TELEMETRY_MQTT_BROKER_HOST",
    os.getenv("ENERGY_GUARDIAN_MQTT_BROKER", "test.mosquitto.org"),
)

DEFAULT_PORT = int(
    os.getenv(
        "TELEMETRY_MQTT_BROKER_PORT",
        os.getenv("ENERGY_GUARDIAN_MQTT_PORT", "1883"),
    )
)

DEFAULT_TOPIC = os.getenv(
    "TELEMETRY_MQTT_TOPIC",
    os.getenv(
        "ENERGY_GUARDIAN_MQTT_TOPIC",
        "energy-iot-cve-monitor/477780562303197185/SolarGuard-01/telemetry",
    ),
)


def on_connect(client, userdata, flags, reason_code, properties):
    if hasattr(reason_code, "is_failure"):
        failed = reason_code.is_failure
    else:
        failed = reason_code != 0

    if failed:
        print("MQTT connection failed:", reason_code)
        return

    print("Energy-IoT Guardian connected!")

    result, message_id = client.subscribe(DEFAULT_TOPIC, qos=0)

    if result == mqtt.MQTT_ERR_SUCCESS:
        print(
            f"Subscription request sent for {DEFAULT_TOPIC} "
            f"(message_id={message_id}); waiting for broker acknowledgement."
        )
    else:
        print(f"Subscription request failed for {DEFAULT_TOPIC}: {result}")


def on_subscribe(client, userdata, message_id, reason_codes, properties):
    if any(reason_code.is_failure for reason_code in reason_codes):
        print(
            "Broker rejected subscription "
            f"(message_id={message_id}, reasons={reason_codes})"
        )
        return
    print(
        f"Broker acknowledged subscription "
        f"(message_id={message_id}, reasons={reason_codes})"
    )


def print_telemetry(payload):
    if not isinstance(payload, dict):
        print("Invalid telemetry: expected a JSON object")
        return

    print("\n--- Solar Inverter Telemetry ---")
    print("Device:", payload.get("device_id", "Unknown"))
    print("Manufacturer:", payload.get("manufacturer", "Unknown"))
    print("Model:", payload.get("model", "Unknown"))
    print("Voltage:", payload.get("voltage", "N/A"), "V")
    print("Current:", payload.get("current", "N/A"), "A")
    print("Power:", payload.get("power", "N/A"), "W")
    print("Timestamp:", payload.get("timestamp", "Unknown"))
    print("Status:", payload.get("telemetry_status", "Unknown"))


def on_message(client, userdata, message):
    print("\nMESSAGE RECEIVED!")
    print("Topic:", message.topic)


    try:
        raw_payload = message.payload.decode("utf-8")
        print("RAW MQTT MESSAGE:", raw_payload)
        data = json.loads(raw_payload)
        print_telemetry(data)

    except UnicodeDecodeError as error:
        print("Invalid telemetry: payload is not UTF-8:", error)
    except json.JSONDecodeError as error:
        print("Invalid JSON:", error)


def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    if hasattr(reason_code, "is_failure"):
        failed = reason_code.is_failure
    else:
        failed = reason_code != 0

    if failed:
        print("MQTT disconnected unexpectedly:", reason_code)
    else:
        print("MQTT disconnected:", reason_code)


def create_client(client_id="Guardian-Python-Receiver"):
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
    )

    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    client.reconnect_delay_set(min_delay=1, max_delay=30)

    return client


def main():
    client = create_client()

    print(
        f"Connecting to MQTT broker "
        f"{DEFAULT_BROKER}:{DEFAULT_PORT}..."
    )

    print(f"Listening on topic: {DEFAULT_TOPIC}")

    try:
        client.connect_async(DEFAULT_BROKER, DEFAULT_PORT, 60)
        client.loop_forever(retry_first_connection=True)

    except KeyboardInterrupt:
        print("\nStopping MQTT listener...")

    except (OSError, mqtt.MQTTException) as error:
        print("Unable to connect to MQTT broker:", error)

    finally:
        client.disconnect()
        print("MQTT listener stopped.")


if __name__ == "__main__":
    main()
