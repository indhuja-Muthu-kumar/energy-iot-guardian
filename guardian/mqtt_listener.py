
import json
import os

import paho.mqtt.client as mqtt

DEFAULT_BROKER = os.getenv("ENERGY_GUARDIAN_MQTT_BROKER", "test.mosquitto.org")
DEFAULT_PORT = int(os.getenv("ENERGY_GUARDIAN_MQTT_PORT", "1883"))
DEFAULT_TOPIC = os.getenv(
    "ENERGY_GUARDIAN_MQTT_TOPIC",
    "energy-guardian/solar-inverter-01/telemetry",
)


def on_connect(client, userdata, flags, reason_code, properties):
    if not hasattr(reason_code, "is_failure"):
        is_failure = reason_code != 0
    else:
        is_failure = reason_code.is_failure

    if not is_failure:
        print("Energy-IoT Guardian connected!")
        client.subscribe(DEFAULT_TOPIC, qos=0)
        print(f"Waiting for ESP32 messages on {DEFAULT_TOPIC}...")
    else:
        print("Connection failed:", reason_code)


def print_telemetry(payload):
    if not isinstance(payload, dict):
        print("Invalid telemetry received: payload is not a JSON object")
        return

    print("\n--- Solar Inverter Telemetry ---")
    print("Device:", payload.get("device_id"))
    print("Firmware:", payload.get("firmware_version"))
    print("Voltage:", payload.get("voltage"), "V")
    print("Power:", payload.get("power"), "W")
    print("Status:", payload.get("status"))


def on_message(client, userdata, message):
    try:
        raw_payload = message.payload.decode("utf-8")
        data = json.loads(raw_payload)
        print_telemetry(data)
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        print("Invalid telemetry received")


def create_client(client_id="Guardian-Python-Receiver"):
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
    )
    client.on_connect = on_connect
    client.on_message = on_message
    return client


def main():
    client = create_client()
    print(f"Connecting to MQTT broker {DEFAULT_BROKER}:{DEFAULT_PORT}...")
    client.connect(DEFAULT_BROKER, DEFAULT_PORT, 60)
    client.loop_forever()


if __name__ == "__main__":
    main()

