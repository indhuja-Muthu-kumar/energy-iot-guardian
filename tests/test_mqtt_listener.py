from types import SimpleNamespace

from paho.mqtt import client as mqtt

from guardian import mqtt_listener


def test_listener_logs_subscribe_result_and_broker_acknowledgement(capsys):
    class FakeClient:
        def __init__(self):
            self.subscription = None

        def subscribe(self, topic, qos):
            self.subscription = (topic, qos)
            return mqtt.MQTT_ERR_SUCCESS, 12

    client = FakeClient()
    mqtt_listener.on_connect(
        client,
        None,
        None,
        SimpleNamespace(is_failure=False),
        None,
    )
    mqtt_listener.on_subscribe(
        client,
        None,
        12,
        [SimpleNamespace(is_failure=False)],
        None,
    )

    output = capsys.readouterr().out
    assert client.subscription == (mqtt_listener.DEFAULT_TOPIC, 0)
    assert "waiting for broker acknowledgement" in output
    assert "Broker acknowledged subscription" in output


def test_listener_handles_non_utf8_telemetry_without_crashing(capsys):
    message = SimpleNamespace(topic=mqtt_listener.DEFAULT_TOPIC, payload=b"\xff")

    mqtt_listener.on_message(None, None, message)

    assert "payload is not UTF-8" in capsys.readouterr().out
