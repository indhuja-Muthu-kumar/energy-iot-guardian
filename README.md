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

When upgrading an existing database after pulling a schema update, run
`flask --app app init-db`. This idempotently adds the nullable
`firmware_version` column and copies over known values from the existing
`firmware` column; unknown and empty values remain unknown. Existing database
rows are retained.

### Wokwi simulated telemetry

The Wokwi sketch is in the existing `wowki/` directory. Its
`libraries.txt` installs PubSubClient, and `sketch.ino` publishes simulated
JSON readings to the configured MQTT topic every three seconds. The default
broker is `broker.emqx.io`, port `1883`; it is a public, unauthenticated
demonstration broker. Do not publish credentials, personal information, or
other sensitive data to it. Broker hostname, port, topic, and optional
subscriber credentials/TLS are configurable with `TELEMETRY_MQTT_BROKER_HOST`,
`TELEMETRY_MQTT_BROKER_PORT`, `TELEMETRY_MQTT_TOPIC`,
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

In PowerShell, install the updated requirements, apply the additive schema
changes, and register the one demo asset idempotently:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m flask --app app init-db
.\.venv\Scripts\python.exe -m flask --app app setup-wokwi-device
```

Keep the existing database file. `init-db` creates the new telemetry table
and adds telemetry/CVE metadata columns to existing tables (using defaults
where required); it does not reset or delete devices, scans, findings, or users. The setup command
reuses a matching active SolarGuard-01 record and refuses conflicting or
archived records instead of silently modifying them.

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
subscribers. Device ID, asset labels, and `SIMULATED` status are validated
before storage; duplicate message IDs are ignored. Archived device history
remains in the database and can still be viewed, but archived devices cannot
receive live readings or be scanned.

The asset vendor/model are descriptive simulation labels, not proof of SMA
hardware. The reported Arduino ESP32 core and ESP-IDF versions are shown as
ESP32 runtime information, separate from inverter firmware. An administrator
can run an ESP32 component scan from the new-scan page after telemetry arrives.
It uses the latest reported versions and only evaluates components for which
NVD provides an exact CPE identity and version applicability data. Unmapped
components are called out as incomplete; potential, indeterminate, affected
version, and not-applicable results remain distinct. The ordinary vendor/model
scan is intentionally blocked for SolarGuard-01 to avoid treating the
descriptive SMA label as verified inverter software.

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

## Data sources

The scan endpoint queries NVD CVE 2.0 by vendor and model, including every
reported result page. It evaluates supported NVD CPE `AND`, `OR`, and negation
rules and compares a known numeric firmware version with published version
ranges. Keyword-only matches are always potential, never affected. Unknown
firmware stays unknown; malformed, unsupported, or ambiguous CPE rules are
reported as potential or indeterminate rather than confirmed. A device CPE
match still cannot independently verify the real device identity or prove
exploitability.

The app does not treat missing firmware as either vulnerable or safe.
`NVD_API_KEY` is optional and can be set in `.env` to increase NVD request
limits. CISA KEV entries are loaded separately with
`flask --app app sync-kev`; KEV membership is not yet used to confirm scan
findings.

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
