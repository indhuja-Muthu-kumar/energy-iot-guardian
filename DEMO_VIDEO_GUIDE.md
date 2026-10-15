# Energy-IoT CVE Monitor demo guide

This guide is for a real local Flask/SQLite run and a real message from the
hosted Wokwi simulator. A successful firmware publish is not proof that Flask
stored the message; use the matching `stored` acknowledgement and saved
dashboard/API record as the evidence.

## Before recording

1. Open the repository in PowerShell:

   ```powershell
   Set-Location 'C:\Users\ARUNA MUTHUKUMAR\Desktop\QUANTUM PHY\tcs\energy-iot-cve-monitor'
   ```

2. Check port 5001 and check for an existing telemetry worker before starting
   anything. Do not start a second worker:

   ```powershell
   Get-NetTCPConnection -LocalPort 5001 -State Listen -ErrorAction SilentlyContinue |
     Select-Object LocalAddress, LocalPort, OwningProcess
   Get-CimInstance Win32_Process |
     Where-Object { $_.CommandLine -match 'flask.*telemetry-worker' } |
     Select-Object ProcessId, ParentProcessId, ExecutablePath, CommandLine
   ```

   If the app or worker is already running, reuse it only after confirming it
   uses this repository and its `.venv`. To apply code changes, stop the old
   process with Ctrl+C in its owning PowerShell window before restarting it.
   Do not terminate an unrelated process or launch a duplicate worker.

3. The hosted Wokwi project is a separate copy. The most recent observed
   rejection was `schema_version must be integer 1`; the exact live payload
   and saved hosted sketch have not been independently inspected. In the
   hosted editor at
   <https://wokwi.com/projects/477868883321291777>, replace the full
   `sketch.ino` with the checked-in `wowki\sketch.ino` and replace
   `ack_state.h` with `wowki\ack_state.h`. Keep the existing telemetry and ACK
   topic values. Confirm the hosted project still has the ESP32 DevKit C V4
   diagram and PubSubClient library, then save the hosted project. Do not
   change SolarGuard-01 to the SMA identity to make the validation pass.

   The expected identity fields in the sketch are `SolarGuard-01`,
   `Espressif`, and `ESP32 development board (Wokwi esp32dev target)`.
   `wowki\libraries.txt` contains `PubSubClient`; `wowki\diagram.json` selects
   the ESP32 DevKit C V4 board. The hosted source must be updated manually;
   local edits do not sync to Wokwi.

## Start the local app and worker

Use two separate PowerShell windows, both opened in the repository root.
Start only one worker.

**PowerShell window 1 — Flask app:**

```powershell
& '.venv\Scripts\python.exe' -m flask --app app run --debug --port 5001
```

**PowerShell window 2 — MQTT worker:**

```powershell
& '.venv\Scripts\python.exe' -m flask --app app telemetry-worker
```

The worker should report connection and subscription acknowledgement for:

```text
energy-iot-cve-monitor/477868883321291777/SolarGuard-01/telemetry
```

The application acknowledgement topic is that topic plus `/ack`. The public
broker `test.mosquitto.org:1883` is unauthenticated and is only suitable for
non-sensitive demonstration data.

## URLs and recording order

Open these pages in a browser:

- Sign in: <http://127.0.0.1:5001/auth/login>
- Dashboard: <http://127.0.0.1:5001/dashboard>
- Device inventory: <http://127.0.0.1:5001/devices>
- Telemetry API (requires login): <http://127.0.0.1:5001/api/dashboard/telemetry>
- Vulnerability Intel: <http://127.0.0.1:5001/cves>
- Scans: <http://127.0.0.1:5001/scans>
- Alerts: <http://127.0.0.1:5001/alerts>
- Remediation: <http://127.0.0.1:5001/remediation>
- Reports: <http://127.0.0.1:5001/reports>

Sign in with the existing local application account. Do not show passwords,
environment files, or secret values in the recording.

### Suggested 3–5 minute sequence and speaking notes

1. **Dashboard (20–30 seconds).** Introduce the monitor and point out actual
   inventory, scans, findings, alerts, and feed freshness. Explain that missing
   or stale feed data is labelled as such, not presented as a live sync.
2. **SolarGuard-01 profile (30–40 seconds).** Open Devices, select
   SolarGuard-01, and show the simulated ESP32 identity, Unknown product
   firmware, component evidence, and the distinction between the controller
   and any represented inverter. As an administrator, use **Scan ESP32
   components** on the profile. Do not call runtime-reported versions
   independently verified. If a runtime version is missing or unsupported,
   an exact NVD product/CPE match can still appear as a potential candidate;
   that component remains not assessed, and keyword matches are never
   confirmed vulnerabilities.
3. **Wokwi and live telemetry (60–90 seconds).** Start the hosted simulation
   and open its Serial Monitor. Look for Wi-Fi connected, MQTT connected,
   acknowledgement-topic subscription, a published message ID, and then an
   ACK for that *same* ID with    outcome `stored` (or `stored` with `duplicate=true` on a repeated
   delivery). In the worker window, find the matching message ID with
   `outcome=stored`. Refresh the dashboard telemetry panel and the authenticated
   telemetry API; confirm that the latest `message_id` is identical and the
   payload source is `wokwi_simulation`. Show voltage, current, power, and
   timestamp provenance from that record. A `rejected` ACK is not a successful
   end-to-end demonstration.
4. **Scan and explain evidence (45–60 seconds).** On the device profile, run a
   scan and wait for its saved result. Open its scan-detail page and distinguish
   confirmed affected-version matches from potential candidates and unassessed
   components. Zero findings means no matching CVE was found for the available
   evidence; it does not prove the device is secure. Do not add or describe a
   fabricated CVE just to create a result.
5. **KEV, remediation, reports (30–45 seconds).** Show CISA KEV status only
   where the catalog records it. Explain that a remediation candidate is for
   review and is not a patch installed or a vulnerability fixed. Finish on
   Reports and mention the public-broker and simulation limitations.

For a concise narration: “SolarGuard-01 is a simulated ESP32 controller. The
application keeps its product firmware unknown and records runtime evidence
with its source and confidence. A scan reports only what the stored inventory
and authoritative vulnerability data support. Here I am checking a Wokwi
message end to end: the device message ID, the worker result, the matching
storage acknowledgement, and the same persisted reading in the application.”

## Evidence and troubleshooting

- On the Wokwi Serial Monitor, a timeout/retry or `rejected` result means the
  full live flow has not passed. Check that the hosted sketch was replaced as
  above and that both identity fields and topics match the local sketch and
  Flask configuration.
- If the worker logs `Simulated asset metadata did not match.`, the hosted
  sketch is still sending the represented SMA inverter identity. Correct the
  hosted firmware; do not relax Flask validation.
- If the worker receives a message but reports a different validation reason,
  preserve that reason and message ID, then inspect the payload fields against
  the schema in `app\services\telemetry_service.py`. Do not publish credentials
  or private payloads when sharing logs.
- If there is no worker receipt, check that exactly one worker is connected to
  the configured broker/topic and that the hosted simulation is running. A
  successful MQTT publish alone is not application storage confirmation.
- If Wokwi or the public broker is unavailable, show the actual last saved
  readings with their source labels and describe the live flow as unverified.
  Do not substitute synthetic/local demo data and call it live.
- The worker uses a project-local OS lock plus
`instance\telemetry-worker.pid` for owner diagnostics. The OS lock is
authoritative and is released when its process exits, so a stale PID does not
prevent a new worker from starting. Do not delete the lock file. Stop any
workers started before this guard was installed from their own terminals
before starting a new worker.

MQTT QoS 1 requests broker delivery attempts and permits redelivery; it does
not prove database persistence. The application-level ACK reports the worker's
post-commit storage result for the matching message ID.

The telemetry API requires an authenticated browser session. If it redirects
  to login, sign in first and retry.
- Run scans only when outbound NVD access is available. A failed or incomplete
  scan must be shown as failed/incomplete; do not imply the results are current.

## Verification limits to state on camera

- Hosted Wokwi changes must be copied and saved manually; updating the local
  sketch alone does not update the simulator.
- The firmware build is not confirmed until a supported local PlatformIO build
  or Wokwi compile succeeds.
- The public MQTT broker is unauthenticated and is not suitable for production.
- Wokwi telemetry is simulated, not a physical inverter or proof of real-world
  energy generation.
- Product firmware and several runtime component versions remain unknown or
  reported rather than independently verified.
- A scan with zero applicable matches does not establish security.
- Show an end-to-end pass only after observing the same fresh message ID in
  Wokwi publish output, worker processing, matching ACK, and the persisted
  telemetry API/dashboard record.
