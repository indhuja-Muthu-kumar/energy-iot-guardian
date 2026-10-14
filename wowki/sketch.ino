#include <Arduino.h>
#include <PubSubClient.h>
#include <WiFi.h>
#include <esp_arduino_version.h>
#include <esp_system.h>
#include <time.h>

#ifndef MQTT_BROKER_HOST
#define MQTT_BROKER_HOST "broker.emqx.io"
#endif

#ifndef MQTT_BROKER_PORT
#define MQTT_BROKER_PORT 1883
#endif

#ifndef MQTT_USERNAME
#define MQTT_USERNAME ""
#endif

#ifndef MQTT_PASSWORD
#define MQTT_PASSWORD ""
#endif

#ifndef MQTT_TELEMETRY_TOPIC
#define MQTT_TELEMETRY_TOPIC \
  "energy-iot-cve-monitor/477780562303197185/SolarGuard-01/telemetry"
#endif

static const char *WIFI_SSID = "Wokwi-GUEST";
static const char *WIFI_PASSWORD = "";
static const char *MANUFACTURER = "SMA Solar Technology";
static const char *ASSET_MODEL = "Sunny Boy TL-21";
static const unsigned long TELEMETRY_INTERVAL_MS = 3000;
static const unsigned long RECONNECT_INTERVAL_MS = 5000;

WiFiClient networkClient;
PubSubClient mqttClient(networkClient);
char bootId[9];
unsigned long messageSequence = 0;
unsigned long lastTelemetryAt = 0;
unsigned long lastReconnectAt = 0;

bool connectToWifi() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  Serial.println("Connecting to Wokwi-GUEST...");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD, 6);
  const unsigned long startedAt = millis();
  while (WiFi.status() != WL_CONNECTED &&
         millis() - startedAt < RECONNECT_INTERVAL_MS) {
    delay(250);
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Wi-Fi unavailable; will retry.");
    return false;
  }
  Serial.print("Wi-Fi connected; IP: ");
  Serial.println(WiFi.localIP());
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  return true;
}

bool connectToMqtt() {
  if (mqttClient.connected()) {
    return true;
  }

  char clientId[48];
  snprintf(clientId, sizeof(clientId), "wokwi-SolarGuard-%s", bootId);
  const bool connected = MQTT_USERNAME[0] == '\0'
      ? mqttClient.connect(clientId)
      : mqttClient.connect(clientId, MQTT_USERNAME, MQTT_PASSWORD);
  if (connected) {
    Serial.println("Connected to the MQTT broker.");
    return true;
  }
  Serial.print("MQTT connection failed; state=");
  Serial.println(mqttClient.state());
  return false;
}

bool makeUtcTimestamp(char *output, size_t outputSize) {
  const time_t now = time(nullptr);
  if (now < 1704067200) {
    return false;
  }
  struct tm utcTime;
  gmtime_r(&now, &utcTime);
  return strftime(output, outputSize, "%Y-%m-%dT%H:%M:%SZ", &utcTime) > 0;
}

void publishReading() {
  const float voltage = random(2100, 2401) / 10.0f;
  const float current = random(20, 101) / 10.0f;
  const float power = voltage * current;
  char timestamp[24];
  if (!makeUtcTimestamp(timestamp, sizeof(timestamp))) {
    Serial.println("Waiting for UTC time synchronization; not publishing yet.");
    return;
  }

  char messageId[48];
  snprintf(messageId, sizeof(messageId), "%s-%lu", bootId, ++messageSequence);
  char payload[512];
  const int payloadLength = snprintf(
      payload,
      sizeof(payload),
      "{\"message_id\":\"%s\",\"device_id\":\"SolarGuard-01\","
      "\"manufacturer\":\"%s\",\"model\":\"%s\","
      "\"voltage\":%.1f,\"current\":%.1f,\"power\":%.1f,"
      "\"timestamp\":\"%s\",\"telemetry_status\":\"SIMULATED\","
      "\"chip_model\":\"%s\",\"chip_revision\":%u,"
      "\"arduino_core_version\":\"%s\",\"esp_idf_version\":\"%s\"}",
      messageId,
      MANUFACTURER,
      ASSET_MODEL,
      voltage,
      current,
      power,
      timestamp,
      ESP.getChipModel(),
      ESP.getChipRevision(),
      ESP_ARDUINO_VERSION_STR,
      esp_get_idf_version());

  if (payloadLength <= 0 || payloadLength >= static_cast<int>(sizeof(payload))) {
    Serial.println("Telemetry payload could not be encoded.");
    return;
  }

  if (mqttClient.publish(MQTT_TELEMETRY_TOPIC, payload, false)) {
    Serial.printf(
        "SIMULATED %s | %.1f V | %.1f A | %.1f W\n",
        timestamp,
        voltage,
        current,
        power);
  } else {
    Serial.println("Telemetry publish failed; will reconnect and retry.");
  }
}

void setup() {
  Serial.begin(115200);
  randomSeed(esp_random());
  snprintf(bootId, sizeof(bootId), "%08lx", (unsigned long)esp_random());
  mqttClient.setServer(MQTT_BROKER_HOST, MQTT_BROKER_PORT);
  mqttClient.setBufferSize(512);
  WiFi.mode(WIFI_STA);
  configTime(0, 0, "pool.ntp.org", "time.google.com");
}

void loop() {
  if (WiFi.status() != WL_CONNECTED || !mqttClient.connected()) {
    const unsigned long now = millis();
    if (now - lastReconnectAt >= RECONNECT_INTERVAL_MS) {
      lastReconnectAt = now;
      if (connectToWifi()) {
        connectToMqtt();
      }
    }
  } else {
    mqttClient.loop();
    const unsigned long now = millis();
    if (now - lastTelemetryAt >= TELEMETRY_INTERVAL_MS) {
      lastTelemetryAt = now;
      publishReading();
    }
  }
  delay(10);
}
