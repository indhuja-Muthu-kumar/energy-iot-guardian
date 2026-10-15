
#include <Arduino.h>
#include <PubSubClient.h>
#include <WiFi.h>
#include <esp_system.h>
#include <time.h>
#include "ack_state.h"

#ifndef MQTT_BROKER_HOST
#define MQTT_BROKER_HOST "test.mosquitto.org"
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
  "energy-iot-cve-monitor/477868883321291777/SolarGuard-01/telemetry"
#endif

#ifndef MQTT_ACK_TOPIC
#define MQTT_ACK_TOPIC MQTT_TELEMETRY_TOPIC "/ack"
#endif

static const char *WIFI_SSID = "Wokwi-GUEST";
static const char *WIFI_PASSWORD = "";
static const char *MANUFACTURER = "Espressif";
static const char *ASSET_MODEL =
    "ESP32 development board (Wokwi esp32dev target)";

static const unsigned long TELEMETRY_INTERVAL_MS = 3000;
static const unsigned long RECONNECT_INTERVAL_MS = 5000;
static const unsigned long MAX_RECONNECT_INTERVAL_MS = 60000;
static const unsigned long WIFI_CONNECT_TIMEOUT_MS = 10000;
static const int32_t MQTT_CONNECT_TIMEOUT_MS = 3000;
static const unsigned long ACK_TIMEOUT_MS = 8000;
static const unsigned long ACK_RETRY_INTERVAL_MS = 2000;
static const unsigned long MAX_ACK_RETRY_INTERVAL_MS = 30000;
static const size_t MQTT_BUFFER_SIZE = 1024;

class BoundedWiFiClient : public WiFiClient {
 public:
  int connect(IPAddress ip, uint16_t port) override {
    return WiFiClient::connect(ip, port, MQTT_CONNECT_TIMEOUT_MS);
  }

  int connect(const char *host, uint16_t port) override {
    return WiFiClient::connect(host, port, MQTT_CONNECT_TIMEOUT_MS);
  }
};

BoundedWiFiClient networkClient;
PubSubClient mqttClient(networkClient);

char bootId[17];
unsigned long messageSequence = 0;
unsigned long lastTelemetryAt = 0;
unsigned long lastWifiAttemptAt = 0;
unsigned long wifiAttemptStartedAt = 0;
unsigned long lastMqttAttemptAt = 0;
unsigned long wifiReconnectIntervalMs = RECONNECT_INTERVAL_MS;
unsigned long mqttReconnectIntervalMs = RECONNECT_INTERVAL_MS;
unsigned long nextActionAt = 0;
unsigned long nextRetryIntervalMs = ACK_RETRY_INTERVAL_MS;
unsigned int retryCount = 0;
char pendingMessageId[48];
char lastCompletedMessageId[48];
char pendingPayload[768];
bool hasPendingMessage = false;
bool awaitingAcknowledgement = false;
bool wifiAttemptActive = false;
bool wifiWasConnected = false;
bool timeSyncConfigured = false;
bool utcSyncReported = false;
bool mqttBufferReady = false;

bool extractJsonString(
    const char *json,
    const char *field,
    char *output,
    size_t outputSize
) {
  char key[40];
  snprintf(key, sizeof(key), "\"%s\"", field);
  const char *position = strstr(json, key);
  if (position == nullptr) {
    return false;
  }

  position = strchr(position + strlen(key), ':');
  if (position == nullptr) {
    return false;
  }
  position++;
  while (*position == ' ' || *position == '\t') {
    position++;
  }
  if (*position != '"') {
    return false;
  }
  position++;

  size_t index = 0;
  while (*position != '\0' && *position != '"') {
    if (*position == '\\' && position[1] != '\0') {
      position++;
    }
    if (index + 1 >= outputSize) {
      return false;
    }
    output[index++] = *position++;
  }
  if (*position != '"') {
    return false;
  }
  output[index] = '\0';
  return true;
}

bool hasSchemaVersionOne(const char *json) {
  const char *position = strstr(json, "\"schema_version\"");
  if (position == nullptr) {
    return false;
  }
  position = strchr(position, ':');
  if (position == nullptr) {
    return false;
  }
  position++;
  while (*position == ' ' || *position == '\t') {
    position++;
  }
  return *position == '1' &&
      (position[1] == ',' || position[1] == '}' ||
       position[1] == ' ' || position[1] == '\n');
}

bool extractJsonBoolean(const char *json, const char *field, bool *output) {
  char key[40];
  snprintf(key, sizeof(key), "\"%s\"", field);
  const char *position = strstr(json, key);
  if (position == nullptr) {
    return false;
  }

  position = strchr(position + strlen(key), ':');
  if (position == nullptr) {
    return false;
  }
  position++;
  while (*position == ' ' || *position == '\t') {
    position++;
  }
  if (strncmp(position, "true", 4) == 0 &&
      (position[4] == ',' || position[4] == '}' ||
       position[4] == ' ' || position[4] == '\n')) {
    *output = true;
    return true;
  }
  if (strncmp(position, "false", 5) == 0 &&
      (position[5] == ',' || position[5] == '}' ||
       position[5] == ' ' || position[5] == '\n')) {
    *output = false;
    return true;
  }
  return false;
}

void onMqttMessage(char *topic, byte *payload, unsigned int length) {
  if (strcmp(topic, MQTT_ACK_TOPIC) != 0) {
    Serial.println("Ignored MQTT message on an unexpected topic.");
    return;
  }

  char response[512];
  if (length >= sizeof(response)) {
    Serial.println("Ignored oversized acknowledgement.");
    return;
  }
  memcpy(response, payload, length);
  response[length] = '\0';

  char acknowledgedId[48];
  char acknowledgedDevice[80];
  char outcome[24];
  char acknowledgementType[32];
  char workerId[80] = "unknown";
  char reason[200] = "No reason supplied.";
  bool duplicate = false;
  if (!hasSchemaVersionOne(response) ||
      !extractJsonString(response, "type", acknowledgementType, sizeof(acknowledgementType)) ||
      strcmp(acknowledgementType, "telemetry_ack") != 0 ||
      !extractJsonString(response, "message_id", acknowledgedId, sizeof(acknowledgedId)) ||
      !extractJsonString(response, "device_id", acknowledgedDevice, sizeof(acknowledgedDevice)) ||
      !extractJsonString(response, "outcome", outcome, sizeof(outcome)) ||
      !extractJsonBoolean(response, "duplicate", &duplicate)) {
    Serial.println("Ignored malformed telemetry acknowledgement.");
    return;
  }
  extractJsonString(response, "reason", reason, sizeof(reason));
  extractJsonString(response, "worker_id", workerId, sizeof(workerId));

  const AckDisposition disposition = classifyTelemetryAcknowledgement(
      acknowledgedDevice,
      acknowledgedId,
      outcome,
      duplicate,
      "SolarGuard-01",
      hasPendingMessage,
      pendingMessageId,
      lastCompletedMessageId
  );
  if (disposition == AckDisposition::WRONG_DEVICE) {
    Serial.println("Ignored acknowledgement for a different device.");
    return;
  }
  if (disposition == AckDisposition::REPEATED_COMPLETED_MESSAGE) {
    Serial.printf(
        "Ignored repeated acknowledgement for already completed message %s.\n",
        acknowledgedId
    );
    return;
  }
  if (disposition == AckDisposition::NO_PENDING_MESSAGE ||
      disposition == AckDisposition::WRONG_MESSAGE_ID) {
    if (disposition == AckDisposition::NO_PENDING_MESSAGE) {
      Serial.printf(
          "Ignored acknowledgement without a pending message: %s.\n",
          acknowledgedId
      );
    } else {
      Serial.printf(
          "Ignored unknown or late acknowledgement for message %s.\n",
          acknowledgedId
      );
    }
    return;
  }

  Serial.printf(
      "ACK received | message=%s | outcome=%s | worker=%s | reason=%s\n",
      acknowledgedId,
      outcome,
      workerId,
      reason
  );

  if (disposition == AckDisposition::STORED ||
      disposition == AckDisposition::DUPLICATE_STORED) {
    Serial.printf(
        "STORAGE CONFIRMED | %s | duplicate=%s | %s\n",
        acknowledgedId,
        duplicate ? "true" : "false",
        reason
    );
    snprintf(
        lastCompletedMessageId,
        sizeof(lastCompletedMessageId),
        "%s",
        acknowledgedId
    );
    hasPendingMessage = false;
    awaitingAcknowledgement = false;
    retryCount = 0;
    nextRetryIntervalMs = ACK_RETRY_INTERVAL_MS;
  } else if (disposition == AckDisposition::REJECTED) {
    Serial.printf(
        "REJECTED | %s | %s\n",
        acknowledgedId,
        reason
    );
    snprintf(
        lastCompletedMessageId,
        sizeof(lastCompletedMessageId),
        "%s",
        acknowledgedId
    );
    hasPendingMessage = false;
    awaitingAcknowledgement = false;
    retryCount = 0;
    nextRetryIntervalMs = ACK_RETRY_INTERVAL_MS;
  } else if (disposition == AckDisposition::RETRY) {
    retryCount++;
    Serial.printf(
        "PENDING | storage requested retry %u in %lu ms | %s\n",
        retryCount,
        nextRetryIntervalMs,
        reason
    );
    awaitingAcknowledgement = false;
    nextActionAt = millis() + nextRetryIntervalMs;
    nextRetryIntervalMs = min(
        nextRetryIntervalMs * 2,
        MAX_ACK_RETRY_INTERVAL_MS
    );
  } else {
    Serial.printf(
        "Ignored malformed or unknown acknowledgement outcome: %s\n",
        outcome
    );
  }
}

void serviceWifiConnection(unsigned long now) {
  if (WiFi.status() == WL_CONNECTED) {
    wifiAttemptActive = false;
    if (!wifiWasConnected) {
      wifiWasConnected = true;
      wifiReconnectIntervalMs = RECONNECT_INTERVAL_MS;
      Serial.print("Wi-Fi connected; IP: ");
      Serial.println(WiFi.localIP());
      if (!timeSyncConfigured) {
        Serial.println("Requesting UTC synchronization.");
        configTime(0, 0, "pool.ntp.org", "time.google.com");
        timeSyncConfigured = true;
        Serial.println("UTC synchronization request started.");
      }
    }
    return;
  }

  if (wifiWasConnected) {
    wifiWasConnected = false;
    if (mqttClient.connected()) {
      mqttClient.disconnect();
    }
    Serial.println("Wi-Fi disconnected; MQTT session closed.");
  }

  if (wifiAttemptActive) {
    if (now - wifiAttemptStartedAt < WIFI_CONNECT_TIMEOUT_MS) {
      return;
    }
    Serial.println("Wi-Fi connection timed out.");
    WiFi.disconnect(false, false);
    wifiAttemptActive = false;
    lastWifiAttemptAt = now;
    wifiReconnectIntervalMs = min(
        wifiReconnectIntervalMs * 2,
        MAX_RECONNECT_INTERVAL_MS
    );
    Serial.printf(
        "Wi-Fi retry scheduled in %lu seconds.\n",
        wifiReconnectIntervalMs / 1000
    );
    return;
  }

  if (now - lastWifiAttemptAt < wifiReconnectIntervalMs) {
    return;
  }

  Serial.println("Starting Wi-Fi connection attempt to Wokwi-GUEST.");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD, 6);
  wifiAttemptStartedAt = now;
  lastWifiAttemptAt = now;
  wifiAttemptActive = true;
}

bool connectToMqtt() {
  if (mqttClient.connected()) {
    return true;
  }

  char clientId[48];

  snprintf(
      clientId,
      sizeof(clientId),
      "wokwi-SolarGuard-%s",
      bootId
  );

  Serial.println("Starting bounded MQTT connection attempt.");
  const bool connected =
      MQTT_USERNAME[0] == '\0'
          ? mqttClient.connect(clientId)
          : mqttClient.connect(
                clientId,
                MQTT_USERNAME,
                MQTT_PASSWORD
            );

  if (connected) {
    Serial.println("Connected to the MQTT broker.");
    if (!mqttClient.subscribe(MQTT_ACK_TOPIC, 1)) {
      Serial.println("Could not subscribe to the telemetry acknowledgement topic.");
      mqttClient.disconnect();
      return false;
    }
    Serial.print(
        "Acknowledgement subscription request sent at QoS 1: "
    );
    Serial.println(MQTT_ACK_TOPIC);
    mqttReconnectIntervalMs = RECONNECT_INTERVAL_MS;
    if (hasPendingMessage) {
      awaitingAcknowledgement = false;
      nextActionAt = millis();
      Serial.printf(
          "Reconnected with pending message %s; it will be retried if no matching acknowledgement arrives.\n",
          pendingMessageId
      );
    }
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

  return strftime(
      output,
      outputSize,
      "%Y-%m-%dT%H:%M:%SZ",
      &utcTime
  ) > 0;
}

void createPendingReading() {
  const float voltage = random(2100, 2401) / 10.0f;
  const float current = random(20, 101) / 10.0f;
  const float power = voltage * current;

  char timestamp[24] = "";
  char timestampField[32];
  const bool hasUtcTimestamp = makeUtcTimestamp(timestamp, sizeof(timestamp));
  if (hasUtcTimestamp) {
    snprintf(timestampField, sizeof(timestampField), "\"%s\"", timestamp);
    if (!utcSyncReported) {
      Serial.println("UTC synchronization confirmed.");
      utcSyncReported = true;
    }
  } else {
    snprintf(timestampField, sizeof(timestampField), "null");
    Serial.println(
        "UTC unavailable; using server receipt time and device uptime."
    );
  }

  snprintf(
      pendingMessageId,
      sizeof(pendingMessageId),
      "%s-%lu",
      bootId,
      ++messageSequence
  );

  const int payloadLength = snprintf(
      pendingPayload,
      sizeof(pendingPayload),
      "{\"schema_version\":1,"
      "\"message_type\":\"telemetry_with_runtime_info\","
      "\"message_id\":\"%s\","
      "\"device_id\":\"SolarGuard-01\","
      "\"source\":\"wokwi_simulation\","
      "\"manufacturer\":\"%s\","
      "\"model\":\"%s\","
      "\"voltage\":%.1f,"
      "\"current\":%.1f,"
      "\"power\":%.1f,"
      "\"timestamp\":%s,"
      "\"timestamp_source\":\"%s\","
      "\"uptime_ms\":%lu,"
      "\"telemetry_status\":\"SIMULATED\","
      "\"chip_model\":\"%s\","
      "\"chip_revision\":%u,"
      "\"arduino_core_version\":\"%u.%u.%u\","
      "\"esp_idf_version\":\"%s\"}",
      pendingMessageId,
      MANUFACTURER,
      ASSET_MODEL,
      voltage,
      current,
      power,
      timestampField,
      hasUtcTimestamp ? "device_utc" : "uptime",
      millis(),
      ESP.getChipModel(),
      ESP.getChipRevision(),
      ESP_ARDUINO_VERSION_MAJOR,
      ESP_ARDUINO_VERSION_MINOR,
      ESP_ARDUINO_VERSION_PATCH,
      esp_get_idf_version()
  );

  if (payloadLength <= 0 ||
      payloadLength >= static_cast<int>(sizeof(pendingPayload))) {
    Serial.println("Telemetry payload could not be encoded.");
    return;
  }

  hasPendingMessage = true;
  awaitingAcknowledgement = false;
  retryCount = 0;
  nextRetryIntervalMs = ACK_RETRY_INTERVAL_MS;
  nextActionAt = millis();
  Serial.printf(
      "PENDING | %s | %.1f V | %.1f A | %.1f W\n",
      pendingMessageId,
      voltage,
      current,
      power
  );
}

void publishPendingReading() {
  if (!hasPendingMessage) {
    return;
  }

  const bool connected = mqttClient.connected();
  const size_t topicLength = strlen(MQTT_TELEMETRY_TOPIC);
  const size_t payloadLength = strlen(pendingPayload);
  const size_t packetBufferRequired = 5 + 2 + topicLength + payloadLength;
  Serial.printf(
      "MQTT publish attempt | message=%s | connected=%s | state=%d | "
      "topic_len=%u | payload_len=%u | packet_required=%u | buffer_size=%u\n",
      pendingMessageId,
      connected ? "true" : "false",
      mqttClient.state(),
      static_cast<unsigned int>(topicLength),
      static_cast<unsigned int>(payloadLength),
      static_cast<unsigned int>(packetBufferRequired),
      static_cast<unsigned int>(MQTT_BUFFER_SIZE)
  );

  if (!mqttBufferReady) {
    Serial.println(
        "MQTT publish result=not_attempted; 1024-byte packet buffer unavailable."
    );
    awaitingAcknowledgement = false;
    nextActionAt = millis() + nextRetryIntervalMs;
    nextRetryIntervalMs = min(
        nextRetryIntervalMs * 2,
        MAX_ACK_RETRY_INTERVAL_MS
    );
    return;
  }
  if (!connected) {
    Serial.println("MQTT publish result=not_attempted; client is disconnected.");
    awaitingAcknowledgement = false;
    nextActionAt = millis() + nextRetryIntervalMs;
    nextRetryIntervalMs = min(
        nextRetryIntervalMs * 2,
        MAX_ACK_RETRY_INTERVAL_MS
    );
    return;
  }

  const bool published =
      mqttClient.publish(MQTT_TELEMETRY_TOPIC, pendingPayload, false);
  Serial.printf(
      "MQTT publish result=%s | message=%s | state=%d\n",
      published ? "success" : "failure",
      pendingMessageId,
      mqttClient.state()
  );

  if (published) {
    awaitingAcknowledgement = true;
    nextActionAt = millis() + ACK_TIMEOUT_MS;
    Serial.printf(
        "MQTT publish queued locally for %s; waiting for database acknowledgement.\n",
        pendingMessageId
    );
  } else {
    awaitingAcknowledgement = false;
    nextActionAt = millis() + nextRetryIntervalMs;
    nextRetryIntervalMs = min(
        nextRetryIntervalMs * 2,
        MAX_ACK_RETRY_INTERVAL_MS
    );
    Serial.printf(
        "MQTT publish failed locally for %s; state=%d. Same message remains pending.\n",
        pendingMessageId,
        mqttClient.state()
    );
  }
}

void setup() {
  Serial.begin(115200);

  Serial.println("Wokwi telemetry demo; simulated values only.");
  Serial.println(
      "SMA Sunny Boy TL-21 is a represented scenario only; "
      "no physical inverter is connected."
  );

  randomSeed(esp_random());

  const uint64_t bootNonce =
      (static_cast<uint64_t>(esp_random()) << 32) | esp_random();
  snprintf(
      bootId,
      sizeof(bootId),
      "%016llx",
      static_cast<unsigned long long>(bootNonce)
  );

  mqttClient.setServer(
      MQTT_BROKER_HOST,
      MQTT_BROKER_PORT
  );

  mqttBufferReady = mqttClient.setBufferSize(MQTT_BUFFER_SIZE);
  if (!mqttBufferReady) {
    Serial.printf(
        "ERROR: Could not allocate %u-byte MQTT packet buffer; "
        "telemetry publishing is disabled.\n",
        static_cast<unsigned int>(MQTT_BUFFER_SIZE)
    );
  }
  mqttClient.setSocketTimeout(3);
  mqttClient.setKeepAlive(30);
  networkClient.setTimeout(3000);
  mqttClient.setCallback(onMqttMessage);

  WiFi.mode(WIFI_STA);
  lastWifiAttemptAt = millis() - RECONNECT_INTERVAL_MS;
  lastMqttAttemptAt = millis() - RECONNECT_INTERVAL_MS;
  Serial.printf("Boot ID: %s\n", bootId);
}

void loop() {
  const unsigned long now = millis();
  serviceWifiConnection(now);

  if (WiFi.status() == WL_CONNECTED && !mqttClient.connected() &&
      now - lastMqttAttemptAt >= mqttReconnectIntervalMs) {
    lastMqttAttemptAt = now;
    if (!connectToMqtt()) {
      mqttReconnectIntervalMs = min(
          mqttReconnectIntervalMs * 2,
          MAX_RECONNECT_INTERVAL_MS
      );
      Serial.printf(
          "MQTT retry scheduled in %lu seconds.\n",
          mqttReconnectIntervalMs / 1000
      );
    }
  }

  if (WiFi.status() == WL_CONNECTED && mqttClient.connected()) {
    mqttClient.loop();

    const unsigned long loopNow = millis();

    if (hasPendingMessage) {
      if (static_cast<long>(loopNow - nextActionAt) >= 0) {
        if (awaitingAcknowledgement) {
          awaitingAcknowledgement = false;
          retryCount++;
          Serial.printf(
              "ACKNOWLEDGEMENT TIMEOUT | %s | retry %u scheduled.\n",
              pendingMessageId,
              retryCount
          );
          nextActionAt = loopNow + nextRetryIntervalMs;
          nextRetryIntervalMs = min(
              nextRetryIntervalMs * 2,
              MAX_ACK_RETRY_INTERVAL_MS
          );
        } else {
          publishPendingReading();
        }
      }
    } else if (loopNow - lastTelemetryAt >= TELEMETRY_INTERVAL_MS) {
      lastTelemetryAt = loopNow;
      createPendingReading();
      publishPendingReading();
    }
  }

  delay(10);
}
