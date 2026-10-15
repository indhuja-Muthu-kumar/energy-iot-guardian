# Energy-IoT CVE Monitor

This project is a Flask web application for tracking energy and industrial IoT assets, correlating firmware versions to CVEs, and surfacing known exploited vulnerabilities from CISA KEV.

## Windows setup and startup

The app defaults to SQLite in Flask's `instance` directory and does not require
MySQL. The MySQL steps below are optional; use them only if you intentionally
configure a MySQL `DATABASE_URL`. Keep the existing SQLite file when it is your
active database.

The local Windows setup uses a MySQL 8 server running on `127.0.0.1:3306`.
Start the MySQL80 Windows service from an elevated PowerShell prompt if it is not
already running:

```powershell
Start-Service MySQL80
```

Create the application database and a least-privilege local user. Replace the
example password with a strong password and use the same value in `.env`:

```powershell
mysql -u root -p
```

At the MySQL prompt, run:

```sql
CREATE DATABASE energy_iot_cve_monitor
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'replace-with-a-strong-password';
GRANT SELECT, INSERT, UPDATE, DELETE
  ON energy_iot_cve_monitor.* TO 'appuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Then, from the project directory in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
notepad .env
```

Set `SECRET_KEY` to a new random value and set:

```dotenv
DATABASE_URL=mysql+pymysql://appuser:replace-with-a-strong-password@127.0.0.1:3306/energy_iot_cve_monitor
FLASK_ENV=development
```

Generate a key with `python -c "import secrets; print(secrets.token_hex(32))"`
and replace the example `SECRET_KEY` value with the output.

If the database password contains URL-reserved characters, percent-encode them
in `DATABASE_URL`. Save `.env`, then initialize and start the application:

```powershell
flask --app app init-db
flask --app app create-admin
flask --app app seed-demo-device
flask --app app sync-kev
flask --app app run --debug
```

`sync-kev` requires outbound HTTPS access to CISA. Visit `http://localhost:5000`
and sign in with the administrator credentials created by the CLI. The app also
supports SQLite by default when `DATABASE_URL` is omitted, but MySQL is the
documented local setup.

When upgrading an existing database after pulling a schema update, first make
a backup, then run `flask --app app init-db`. This additive, idempotent command
preserves existing rows and adds the nullable `firmware_version` and firmware
evidence fields. Older known firmware values are retained as `REPORTED` with
low confidence and an unknown collection time; legacy data is not promoted to
verified. New operator-entered values are also `REPORTED` with low confidence.
The evidence source, method, note and server-side collection time are stored
separately from the version. A reported version or firmware value from the ESP32
does not independently verify the product firmware.
The same command now additively creates the component-evidence table and
simulation-status field, then idempotently registers
`ArduinoUno-SecurityLab-01` if it is absent. The device is labeled
`Arduino Uno (revision unknown)` with unknown simulation state. Its board
documentation is only a reference; sketch, framework, microcontroller, and
bootloader evidence remain explicitly not assessed unless collected from the
actual asset. The SMA `2.60.03.R` reference is kept only on the separately
labelled SMA reference inventory; a legacy copy on the Uno is cleared to
Unknown because it is not Arduino firmware evidence. The repository's
PlatformIO target is the separate Wokwi ESP32, so those ESP32 build versions
are never copied onto the Uno.

From an authenticated device profile, **Run Scan** uses the saved identity and
component evidence, queries NVD, records scan/CVE/finding/alert records, and
creates review-only remediation candidates only when NVD returns an HTTPS
reference tagged `Vendor Advisory`. Such a link is a review lead, not a
verified fixed version; no installer or firmware flasher is run. Repeated
scans preserve separate scan history while de-duplicating repeated CVE entries
within one scan and reusing the same remediation candidate and alert.

### Wokwi simulated telemetry

The hosted Wokwi project at
<https://wokwi.com/projects/477868883321291777> is a separate copy and does not
automatically synchronize with this repository. Before a live demo, compare its
**sketch.ino**, **diagram.json**, **libraries.txt**, and **ack_state.h** with the
checked-in files and update the hosted project if they differ. A public project
URL does not send data to Flask until the simulation is started. The checked-in
sketch connects to Wi-Fi and publishes simulated JSON readings to MQTT every
three seconds; its Serial Monitor output is not proof of delivery.

The default
broker is `test.mosquitto.org`, port `1883`; it is a public, unauthenticated
demonstration broker. The public Wokwi source and public MQTT broker do not
authenticate the publisher: another user could observe or inject messages on
the topic. Use only non-sensitive demo telemetry. Do not use these messages as
trusted physical-device measurements or expose a production service through
this broker. Do not publish credentials, personal information, or other
sensitive data to it. Broker hostname, port, topic, and optional
subscriber credentials/TLS are configurable with `TELEMETRY_MQTT_BROKER_HOST`,
`TELEMETRY_MQTT_BROKER_PORT`, `TELEMETRY_MQTT_TOPIC`,
`TELEMETRY_MQTT_ACK_TOPIC`,
`TELEMETRY_MQTT_USERNAME`, `TELEMETRY_MQTT_PASSWORD`, and
`TELEMETRY_MQTT_TLS`. The topic must match the `MQTT_TELEMETRY_TOPIC` macro
near the top of `wowki/sketch.ino`; change both settings together if you
customize it. Optional broker credentials for the Wokwi publisher are left
empty in the sketch's `MQTT_USERNAME` and `MQTT_PASSWORD` macros; do not commit
real credentials. The current Wokwi demo uses plain MQTT on port 1883, so keep
TLS disabled unless both the broker and firmware have been configured for TLS.

`wowki/diagram.json` selects the ESP32 DevKit C V4 board in the hosted Wokwi
simulator, and `wowki/libraries.txt` resolves PubSubClient there. The hosted
project does not need a local `wokwi.toml`. For local builds and VS Code
IntelliSense, the repository also has a PlatformIO project at its root. Open
the repository folder in VS Code with the PlatformIO IDE extension enabled,
then run `pio run` from the repository root. PlatformIO installs the
Espressif ESP32 Arduino platform and PubSubClient declared in `platformio.ini`;
the C/C++ extension obtains the real header paths from PlatformIO rather than
using manually guessed include directories. No packages are installed by
these project configuration files alone.

The sketch starts Wi-Fi asynchronously, times out an attempt after 10 seconds,
and backs off retries up to 60 seconds. MQTT reconnect attempts are similarly
backed off; the WiFiClient transport connect and PubSubClient socket response
timeouts are each three seconds. PubSubClient's synchronous connect call can
briefly occupy the loop, but it does not wait indefinitely. Telemetry is
published at QoS 0 with retain disabled;
the device subscribes to acknowledgements at QoS 1, and Flask publishes its
storage-result acknowledgement at QoS 1 with retain disabled. PubSubClient's
default clean session is used. A successful publish only means the MQTT client
accepted the message for sending; the matching `stored` acknowledgement is the
application-level confirmation that Flask committed it.

The firmware uses device UTC when available. If UTC is not synchronized, it
sends a null `timestamp`, `timestamp_source: "uptime"`, and its 32-bit uptime
counter. Flask timestamps that record at receipt and stores that provenance
separately, so a missing NTP response no longer blocks telemetry or masquerades
uptime as a calendar timestamp. The dashboard/API expose the message ID and
timestamp evidence. The public broker and public Wokwi project are not
authenticated production channels.

The firmware includes `wowki/ack_state.h` for acknowledgement-state checks.
Keep this header beside `sketch.ino` in both the local PlatformIO project and
the hosted Wokwi project. The host-side acknowledgement-state test runs with
`pytest tests/test_firmware_ack_state.py` when a native C++ compiler is
available.

In PowerShell, install the updated requirements, apply the additive schema
changes, and register the one demo asset idempotently:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe -m flask --app app setup-wokwi-device
.\.venv\Scripts\python.exe -m flask --app app setup-sma-reference-device
```

Keep the existing database file. `init-db` creates the new telemetry table
and adds telemetry/CVE metadata columns to existing tables (using defaults
where required), records MQTT transport separately from the payload's
`wokwi_simulation` / `local_demo` source (`unknown` for older messages),
records timestamp provenance and optional device uptime (`unknown` / null for
older messages), and adds the nullable unique `telemetry_device_id` field.
If exactly one existing SolarGuard-01 row matches its configured simulated
ESP32 vendor and model, the migration associates the stable telemetry ID with
that row; other inventory rows remain unassigned. `setup-wokwi-device`
reclassifies the known legacy SMA demo labels as the simulated Espressif ESP32
while preserving telemetry, scans, findings, and users. It refuses conflicting
or archived records instead of silently modifying them.
`setup-sma-reference-device` updates the existing test/reference record
idempotently; it will not merge that reference with SolarGuard-01.

Run the subscriber and web app in two separate PowerShell windows:

```powershell
# Window 1: MQTT subscriber
.\.venv\Scripts\python.exe -m flask --app app telemetry-worker
```

```powershell
# Window 2: authenticated website
.\.venv\Scripts\python.exe -m flask --app app run --debug
```

Start the Wokwi simulation. The dashboard's authenticated telemetry endpoint
shows “Waiting for telemetry” before the first message, updates metrics and
history from database-stored messages, and labels readings “Stale” after ten
seconds without a new message. The subscriber runs only when explicitly
started, so Flask's debug reloader and tests do not create duplicate
subscribers. The default broker and topic now match between the ESP32, Flask
worker, and standalone listener. The worker logs the subscription request and
broker acknowledgement; an ESP32 `publish()` success only means its local
MQTT client accepted the packet and does not prove that a subscriber received
it. Device ID, asset labels, and `SIMULATED` status are validated
before storage; duplicate message IDs are ignored. Archived device history
remains in the database and can still be viewed, but archived devices cannot
receive live readings or be scanned.

#### Application-level storage acknowledgement

The device publishes telemetry to
`energy-iot-cve-monitor/<wokwi-project-id>/<device-id>/telemetry`; the Flask
subscriber sends the corresponding response to the separate
`.../telemetry/ack` topic. `TELEMETRY_MQTT_ACK_TOPIC` configures the subscriber
topic and should match `MQTT_ACK_TOPIC` in the sketch. Each event has a random
boot identifier plus sequence number, schema version, device ID, simulation
source label and device timestamp. The source label is payload metadata, not
proof of publisher identity. The ESP32 keeps one event pending and
retries that exact payload and ID if it does not receive a response, using an
eight-second acknowledgement timeout and capped retry backoff.

The worker sends its acknowledgement only after validation and the database
transaction succeeds. The versioned response includes event type, message ID,
device ID, outcome (`stored`, `rejected`, or `retry`), reason, duplicate flag
and server processing time. A repeated already-committed event is acknowledged
as stored but is not inserted again. A database failure produces a `retry`
outcome, never a storage confirmation. A rejection is terminal for that event;
inspect its reason before correcting the sketch or server.

An MQTT publish result only tells the local MQTT client whether it accepted a
packet; it does not prove that the subscriber received it. The application
acknowledgement indicates that the worker reports a committed database write,
but a public, unauthenticated broker can expose, inject, delay or forge both
telemetry and acknowledgements. Correlation IDs match replies to pending
events; they do **not** authenticate senders, prevent forgery, or make
public-broker telemetry trustworthy. The ESP32 ignores malformed or wrong-type
acknowledgements and wrong device/message IDs. A matching `stored`
acknowledgement confirms storage whether `duplicate` is false (new insert) or
true (the ID was already committed). Once that ID is completed, later
acknowledgements for it are ignored and identified as repeats; they cannot
complete a newer pending event. Retries reuse the original pending payload and
message ID, with capped backoff for storage retries and immediate retry after a
successful reconnect.

For production, use MQTT over TLS, authenticated per-device clients, strict
publish/subscribe topic ACLs, protected credentials and message
authenticity/integrity controls. Never put secrets in the public Wokwi sketch.

If the public broker or Wokwi is unavailable, create one clearly marked local
sample using the existing validation and database pipeline:

```powershell
.\.venv\Scripts\python.exe -m flask --app app telemetry-demo
```

The dashboard marks this as `LOCAL DEMO · NOT LIVE`; the command contacts no
MQTT broker or physical device. The sample is intentionally fixed synthetic
data, not evidence of device connectivity.

Troubleshooting:

- Confirm the ESP32 and subscriber use the same broker host, port, and exact
  topic. The defaults are `test.mosquitto.org:1883` and
  `energy-iot-cve-monitor/477868883321291777/SolarGuard-01/telemetry`.
- Start `telemetry-worker` before the Wokwi simulation. Check its logs for a
  broker subscription acknowledgement, then check for accepted or rejected
  telemetry messages.
- The ESP32 retries failed network connections with a capped backoff. Its
  local publish-success log is not an end-to-end delivery acknowledgement.
- Public MQTT service and internet access are external dependencies. Use
  `telemetry-demo` to present dashboard/database functionality when they are
  unavailable, and keep the data visibly labeled as local simulation.

SolarGuard-01 is an Espressif ESP32 development-board simulation for a
solar-monitoring scenario; the represented SMA inverter is not connected and
its exact model and installed firmware are unknown. The application sketch
version, bootloader version, and exact PlatformIO/compiler toolchain version
are also unknown because no versioned sketch build, bootloader readout, or
pinned toolchain build evidence is present. Runtime-reported Arduino-ESP32 core
and ESP-IDF versions are tracked separately from application firmware. They
come over unauthenticated simulated MQTT, so matching CVEs remain potential
candidates rather than confirmed physical-device findings.

SMA's official off-grid inverter guide specifies firmware **2.60.03.R or
higher** for SB 3000TL-21, SB 3600TL-21, SB 4000TL-21, SB 5000TL-21, and
SB 6000TL-21. The reference inventory stores each exact model/version pair as
`REFERENCE` evidence, not installed firmware. The guide does not identify which
exact variant, if any, the SolarGuard scenario represents. See the
[official SMA compatibility table](https://manuals.sma.de/OffGridSystem-PL/en-US/1862614539.html).
For inventory scans, an unverified version within an NVD range remains a
potential candidate, and an unverified version outside the range cannot rule
out applicability. No matching CVEs does not prove a device is secure.
Administrators can run the ESP32 component scan after telemetry arrives.

Device-profile contextual priorities are separate from CVSS severity. An
evaluated affected finding in the stored CISA KEV catalog is `CRITICAL`;
unresolved applicability with a KEV listing is `HIGH`. Without a KEV listing,
evaluated matches retain their severity band, while potential/indeterminate
matches are lowered one band (critical to high, high to medium, medium to low).
Unknown severity and score require `REVIEW`, not a low-risk conclusion, and
not-applicable findings are labeled `NOT PRIORITIZED` while their history is
retained. These rules do not yet include device criticality or measured network
exposure. KEV labels reflect the locally stored catalog; a missing listing is
not proof that a CVE is absent from a fresh catalog.

Telemetry checks use configurable demonstration ceilings (280 V, 20 A, and
3500 W by default) that are not manufacturer operating limits. Exceedances are
saved as grouped, medium-severity telemetry alerts in the same database
transaction as the reading. Alert text identifies the demo rule and explicitly
states that it is not evidence of a physical equipment fault. Repeated
exceedances for one device/measurement update the existing open alert rather
than creating an unbounded stream of duplicate alerts.
It uses the latest reported versions and evaluates version applicability only
when the component has a usable version and exact NVD CPE identity. If the
version is missing or unsupported, an exact NVD product/CPE match may still
produce potential or indeterminate candidates; the component remains
not-assessed, and a keyword hit alone is never a confirmed match. Unmapped
components are called out as incomplete; potential, indeterminate,
affected-version, and not-applicable results remain distinct. The ordinary
vendor/model scan is intentionally blocked for SolarGuard-01 to avoid treating
the descriptive SMA label as verified inverter software.

### Docker Compose

The Compose deployment uses a separate MySQL database; it does not use or
replace the local SQLite file. Before starting Compose, add these values to the
project `.env` file. Use new random values for both passwords and the secret
key; do not commit `.env`:

```dotenv
SECRET_KEY=paste-a-random-secret-of-at-least-32-characters
MYSQL_ROOT_PASSWORD=paste-a-random-url-safe-password
MYSQL_USER=energy_app
MYSQL_PASSWORD=paste-another-random-url-safe-password
```

Generate URL-safe values in PowerShell with:

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
```

Use a `token_hex` value for `SECRET_KEY` and `token_urlsafe` values for the two
database passwords. The passwords are embedded in the internal MySQL connection
URL, so URL-safe characters avoid connection-string parsing problems. Then
start the services with:

```powershell
docker compose up --build
```

Compose requires all three secret values and refuses to start if they are
missing. MySQL is reachable only on the private Compose network; only the web
application port is published to the host. MySQL data is stored in the named
`mysql_data` volume and survives ordinary `docker compose down`. Do not use
`docker compose down --volumes` unless you intentionally want to delete that
Compose database. This volume is separate from the existing SQLite database.
The database setup SQL file creates only the database; Compose creates its
application account from the environment variables instead of a stored
password.

## Dashboard review and remediation

The dashboard's open-alert count includes only alerts whose current status is
`open`; acknowledged, in-progress, resolved, and rejected records are excluded.
Each listed open alert links to its saved detail page.

“Awaiting review” counts only patch candidates in the `discovered` state.
Administrators can approve or reject discovered simulated candidates. These
actions record workflow state; approval does not install a patch, and
verification of a simulated candidate is not evidence that a real device was
updated. Rejection is recorded in the audit log. Non-simulated candidates must
be reviewed through their recorded source evidence; this application does not
perform vendor patch installation.

Recent activity is assembled from saved scans, NVD/CISA KEV sync attempts,
telemetry readings, security alerts, and remediation candidates. It shows
recorded timestamps and statuses, including failed sync attempts. Telemetry
records marked simulated remain labeled as simulated.

## Data sources

The scan endpoint queries NVD CVE 2.0 by vendor and model, including every
reported result page. It evaluates supported NVD CPE `AND`, `OR`, and negation
rules and compares a known numeric firmware version with published version
ranges. Keyword-only matches are always potential, never affected. Unknown
firmware stays unknown; malformed, unsupported, or ambiguous CPE rules are
reported as potential or indeterminate rather than confirmed. A device CPE
match still cannot independently verify the real device identity or prove
exploitability.

The app does not treat missing firmware as either vulnerable or safe. Findings
include the NVD detail URL and the available CPE applicability reasoning.
`NVD_API_KEY` is optional and can be set in `.env` to increase NVD request
limits. CISA KEV entries are loaded separately with
`flask --app app sync-kev`; KEV membership is not yet used to confirm scan
findings. A KEV label is shown only for entries attributed to the CISA KEV
source. Successful and failed KEV refresh attempts are recorded in
`sync_logs`, and the dashboard reports the age of the last successful fetch.
The current importer upserts entries but does not remove entries missing from
a newer feed, so a recent fetch timestamp does not prove the stored KEV set is
fully reconciled with CISA's current catalog. Treat KEV membership as stored
catalog evidence, not proof of current status.

## Windows tests

From PowerShell in the project directory, run:

```powershell
.\.venv\Scripts\pytest.exe -q
.\.venv\Scripts\ruff.exe check app tests
```

The default database is SQLite and resolves under Flask's `instance` directory.
Keep the existing database file when upgrading; `flask --app app init-db`
creates any missing tables and applies safe, additive schema updates.

For a production-like run, set a strong `SECRET_KEY`, set
`FLASK_ENV=production`, and serve the app behind HTTPS. Production mode disables
debug and requires secure session cookies. Do not expose the Flask development
server to the internet.

## Security notes

- No secret values are committed to the repository.
- The app relies on Flask-Login, CSRF protection, and safe session cookies.
- The app never claims a device is secure based on no matches alone; it phrases
  results as “No known matches found in the data sources checked at this time.”

# energy-iot-guardian

IoT-based energy monitoring and CVE vulnerability detection.
