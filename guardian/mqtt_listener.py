
import json
import os
import sys
import paho.mqtt.client as mqtt

BROKER = os.getenv(
    "TELEMETRY_MQTT_BROKER_HOST",
    os.getenv("ENERGY_GUARDIAN_MQTT_BROKER", "test.mosquitto.org")
)

PORT = int(os.getenv("TELEMETRY_MQTT_BROKER_PORT", "1883"))

TOPIC = os.getenv(
    "TELEMETRY_MQTT_TOPIC",
    "energy-iot-cve-monitor/477868883321291777/SolarGuard-01/telemetry"
)
DEFAULT_TOPIC = TOPIC

CLIENT_ID = "Guardian-Python-Receiver-Star-2026"


def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code.is_failure:
        print(f"MQTT connection failed: {reason_code}")
        return

    print("Energy-IoT Guardian connected!")
    print(f"Broker: {BROKER}:{PORT}")
    print(f"Subscribing to: {TOPIC}")

    result, mid = client.subscribe(TOPIC, qos=0)

    if result == mqtt.MQTT_ERR_SUCCESS:
        print("Subscription request sent; waiting for broker acknowledgement.")
    else:
        print(f"Subscription failed: {result}")


def on_subscribe(client, userdata, mid, reason_code_list, properties):
    if any(reason_code.is_failure for reason_code in reason_code_list):
        print(f"Broker rejected subscription: {reason_code_list}")
    else:
        print(f"Broker acknowledged subscription: {reason_code_list}")


def on_message(client, userdata, message):
    print("\n" + "=" * 55)
    print("MESSAGE RECEIVED!")
    print(f"Topic: {message.topic}")

    try:
        payload = message.payload.decode("utf-8")
        data = json.loads(payload)

        print("\nDevice:", data.get("device_id", "Unknown"))
        print("Manufacturer:", data.get("manufacturer", "Unknown"))
        print("Model:", data.get("model", "Unknown"))
        print("Voltage:", data.get("voltage", "N/A"), "V")
        print("Current:", data.get("current", "N/A"), "A")
        print("Power:", data.get("power", "N/A"), "W")
        print("Status:", data.get("telemetry_status", "Unknown"))

    except UnicodeDecodeError:
        print("Received payload is not UTF-8.")
    except json.JSONDecodeError:
        print("Received non-JSON or invalid message.")

    print("=" * 55)


def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    if reason_code.is_failure:
        print(f"MQTT disconnected unexpectedly: {reason_code}")
    else:
        print(f"MQTT disconnected: {reason_code}")


def main():
    print(f"Connecting to MQTT broker: {BROKER}:{PORT}")
    print(f"Listening on topic: {TOPIC}")

    try:
        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=CLIENT_ID,
            protocol=mqtt.MQTTv311
        )

        client.on_connect = on_connect
        client.on_subscribe = on_subscribe
        client.on_message = on_message
        client.on_disconnect = on_disconnect

        client.reconnect_delay_set(min_delay=1, max_delay=10)

        client.connect(BROKER, PORT, keepalive=60)

        print("Waiting for Wokwi ESP32 telemetry...")
        client.loop_forever()

    except KeyboardInterrupt:
        print("\nStopping MQTT listener...")

    except (OSError, ValueError, mqtt.MQTTException) as error:
        print(f"MQTT error: {error}")
        sys.exit(1)

    finally:
        print("Listener stopped.")


if __name__ == "__main__":
    main()
