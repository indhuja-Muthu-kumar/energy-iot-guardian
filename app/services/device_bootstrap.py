from __future__ import annotations

import re
from datetime import UTC, datetime

from sqlalchemy import select

from app.extensions import db
from app.models.device import Device
from app.models.device_component import DeviceComponent

UNO_DEVICE_NAME = "ArduinoUno-SecurityLab-01"
UNO_REFERENCE_URL = "https://docs.arduino.cc/hardware/uno-rev3/"
UNO_R4_REFERENCE_URL = "https://docs.arduino.cc/hardware/uno-r4-minima/"
SMA_REFERENCE_URL = (
    "https://manuals.sma.de/OffGridSystem-PL/en-US/1862614539.html"
)
SMA_REFERENCE_DEVICE_NAME = (
    "SMA Sunny Boy TL-21 Firmware Reference (not installed)"
)
SMA_REFERENCE_VERSION = "2.60.03.R"
SMA_REFERENCE_MODELS = (
    "SB 3000TL-21",
    "SB 3600TL-21",
    "SB 4000TL-21",
    "SB 5000TL-21",
    "SB 6000TL-21",
)
SOLAR_GUARD_COMPONENTS = (
    {
        "component_key": "esp32_board",
        "name": "ESP32 board / build target",
        "component_type": "hardware",
        "vendor": "Espressif",
        "product": "ESP32 development board (Wokwi esp32dev target)",
        "evidence_method": "PlatformIO and Wokwi project configuration inspection",
        "evidence_note": (
            "The project targets PlatformIO board esp32dev in Wokwi. This is "
            "a simulated development-board target, not proof of a specific "
            "physical board revision."
        ),
        "evidence_status": "REFERENCE",
        "confidence": "medium",
    },
    {
        "component_key": "esp32_chip",
        "name": "ESP32 chip model",
        "component_type": "hardware",
        "vendor": "Espressif",
        "product": "ESP32 chip (runtime model reported in telemetry)",
        "evidence_method": "Wokwi ESP32 runtime self-report",
        "evidence_note": (
            "The chip_model field is reported by the simulated ESP32 at "
            "runtime. It identifies a chip model, not the development board."
        ),
        "evidence_status": "NOT_ASSESSED",
        "confidence": "none",
    },
    {
        "component_key": "application",
        "name": "Application sketch",
        "component_type": "software",
        "vendor": None,
        "product": "SolarGuard Wokwi telemetry sketch",
        "evidence_method": "Repository source and build configuration inspection",
        "evidence_note": (
            "No application sketch version is declared or reported. Record a "
            "version only after a versioned release/build identifier and "
            "evidence tying that build to the running image are available."
        ),
        "evidence_status": "NOT_ASSESSED",
        "confidence": "none",
    },
    {
        "component_key": "arduino_esp32_core",
        "name": "Arduino ESP32 framework / core",
        "component_type": "software",
        "vendor": "Espressif",
        "product": "Arduino-ESP32 core (runtime-reported version)",
        "evidence_method": "ESP_ARDUINO_VERSION compile-time constants via simulated MQTT",
        "evidence_note": (
            "The runtime may report the exact Arduino-ESP32 core version. A "
            "received MQTT value is reported evidence, not authenticated "
            "physical-device evidence."
        ),
        "evidence_status": "NOT_ASSESSED",
        "confidence": "none",
    },
    {
        "component_key": "esp_idf_runtime",
        "name": "ESP-IDF framework",
        "component_type": "software",
        "vendor": "Espressif",
        "product": "ESP-IDF (runtime-reported version)",
        "evidence_method": "esp_get_idf_version via simulated MQTT",
        "evidence_note": (
            "The runtime may report the exact ESP-IDF version. A received "
            "MQTT value is reported evidence, not authenticated physical-device "
            "evidence."
        ),
        "evidence_status": "NOT_ASSESSED",
        "confidence": "none",
    },
    {
        "component_key": "toolchain",
        "name": "Build toolchain",
        "component_type": "software",
        "vendor": "PlatformIO / Espressif",
        "product": "PlatformIO espressif32 platform and compiler toolchain",
        "evidence_method": "PlatformIO configuration inspection",
        "evidence_note": (
            "platformio.ini does not pin the espressif32 platform or compiler "
            "version. A pinned build configuration and build metadata are "
            "needed to report an exact toolchain version."
        ),
        "evidence_status": "NOT_ASSESSED",
        "confidence": "none",
    },
    {
        "component_key": "bootloader",
        "name": "Bootloader",
        "component_type": "software",
        "vendor": None,
        "product": "ESP32 bootloader",
        "evidence_method": "Not collected",
        "evidence_note": (
            "The bootloader version is not reported by this telemetry sketch. "
            "A bootloader/build identifier read from the actual target is "
            "needed; it cannot be inferred from the SMA reference."
        ),
        "evidence_status": "NOT_ASSESSED",
        "confidence": "none",
    },
    {
        "component_key": "mqtt_client_library",
        "name": "MQTT client library",
        "component_type": "software",
        "vendor": None,
        "product": "PubSubClient",
        "evidence_method": "PlatformIO and Wokwi dependency declaration inspection",
        "evidence_note": (
            "platformio.ini declares knolleary/PubSubClient @ ^2.8.0 and "
            "wowki/libraries.txt names PubSubClient. No resolved dependency "
            "lock or successful local firmware build is available, so the "
            "installed library version and exact CPE are unknown."
        ),
        "evidence_status": "NOT_ASSESSED",
        "confidence": "none",
    },
    {
        "component_key": "represented_inverter",
        "name": "Represented inverter (scenario label only)",
        "component_type": "reference",
        "vendor": "SMA Solar Technology",
        "product": "Sunny Boy TL-21 family; exact inverter model unknown",
        "evidence_source": SMA_REFERENCE_URL,
        "evidence_method": "Simulation scenario label compared with manufacturer reference",
        "evidence_note": (
            "This is a solar-monitoring scenario label only. No physical SMA "
            "inverter is connected or identified. The manufacturer guide lists "
            "specific TL-21 variants separately; it does not identify the "
            "variant represented by this simulation."
        ),
        "evidence_status": "REFERENCE",
        "confidence": "low",
    },
)

_UNO_COMPONENTS = (
    {
        "component_key": "board",
        "name": "Board",
        "component_type": "hardware",
        "vendor": "Arduino",
        "product": "Arduino Uno (revision unknown)",
        "evidence_source": UNO_REFERENCE_URL,
        "evidence_method": "Manufacturer documentation reference",
        "evidence_note": (
            "The inventory label identifies the Arduino Uno family only. "
            "This Uno Rev3 page is a reference, not confirmation of the "
            "physical board or its revision."
        ),
        "evidence_status": "REFERENCE",
        "confidence": "low",
    },
    {
        "component_key": "microcontroller",
        "name": "Microcontroller",
        "component_type": "hardware",
        "vendor": None,
        "product": "Revision-dependent; not identified",
        "evidence_source": UNO_R4_REFERENCE_URL,
        "evidence_method": "Revision comparison; physical inspection required",
        "evidence_note": (
            "Arduino Uno revisions use different microcontrollers. The exact "
            "board revision has not been observed, so no MCU is asserted."
        ),
        "evidence_status": "NOT_ASSESSED",
        "confidence": "none",
    },
    {
        "component_key": "application",
        "name": "Application / sketch",
        "component_type": "software",
        "vendor": None,
        "product": "Arduino Uno application firmware",
        "evidence_source": None,
        "evidence_method": "Repository build-configuration inspection",
        "evidence_note": (
            "No Arduino Uno sketch or build target is present in this repository. "
            "The available firmware target is Wokwi ESP32; no Uno application "
            "version can be inferred from it."
        ),
        "evidence_status": "NOT_ASSESSED",
        "confidence": "none",
    },
    {
        "component_key": "framework",
        "name": "Framework / platform",
        "component_type": "software",
        "vendor": "Arduino",
        "product": "Arduino Uno platform package",
        "evidence_source": None,
        "evidence_method": "Repository build-configuration inspection",
        "evidence_note": (
            "platformio.ini targets espressif32 / esp32dev / arduino. That is "
            "the separate Wokwi ESP32 build, not an installed Uno framework "
            "version."
        ),
        "evidence_status": "NOT_ASSESSED",
        "confidence": "none",
    },
    {
        "component_key": "bootloader",
        "name": "Bootloader",
        "component_type": "software",
        "vendor": None,
        "product": "Arduino Uno bootloader",
        "evidence_source": None,
        "evidence_method": "Not collected",
        "evidence_note": (
            "The bootloader version is not available from the repository build "
            "configuration and has not been read from a physical board."
        ),
        "evidence_status": "NOT_ASSESSED",
        "confidence": "none",
    },
)


def ensure_arduino_uno_device() -> Device:
    matches = list(
        db.session.scalars(
            select(Device)
            .where(Device.name == UNO_DEVICE_NAME)
            .order_by(Device.id.asc())
        )
    )
    if len(matches) > 1:
        raise RuntimeError(
            f"Multiple {UNO_DEVICE_NAME} records exist; none were changed."
        )

    if matches:
        device = matches[0]
        if device.vendor != "Arduino":
            raise RuntimeError(
                f"{UNO_DEVICE_NAME} exists with a conflicting vendor; "
                "no records were changed."
            )
        recorded_versions = {
            version.strip()
            for version in (device.firmware, device.firmware_version)
            if isinstance(version, str)
            and version.strip()
            and version.strip().lower() != "unknown"
        }
        if (
            device.model == "Arduino Uno (revision unknown)"
            and recorded_versions == {SMA_REFERENCE_VERSION}
        ):
            device.firmware = "unknown"
            device.firmware_version = None
            device.firmware_verification_status = "UNKNOWN"
            device.firmware_confidence = "none"
            device.firmware_evidence_source = None
            device.firmware_evidence_method = None
            device.firmware_evidence_collected_at = None
            device.firmware_evidence_note = (
                "The prior operator-entered value 2.60.03.R was documented "
                "for specific SMA Sunny Boy inverter models, not this Arduino "
                "Uno. It was cleared; installed Arduino firmware remains "
                "unknown pending device-specific evidence."
            )
    else:
        device = Device(
            name=UNO_DEVICE_NAME,
            vendor="Arduino",
            model="Arduino Uno (revision unknown)",
            firmware="unknown",
            firmware_version=None,
            firmware_verification_status="UNKNOWN",
            firmware_confidence="none",
            asset_tag=UNO_DEVICE_NAME,
            site="Security Lab",
            simulation_status="unknown",
            status="active",
            notes=(
                "Operator-provided inventory label. Physical board revision, "
                "microcontroller, simulation status, installed sketch, "
                "framework, and bootloader have not been independently "
                "verified. Do not infer Uno software versions from the "
                "separate Wokwi ESP32 firmware."
            ),
        )
        db.session.add(device)
        db.session.flush()

    existing_keys = {
        component.component_key for component in device.components
    }
    for component in _UNO_COMPONENTS:
        if component["component_key"] not in existing_keys:
            db.session.add(
                DeviceComponent(device_id=device.id, **component)
            )

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    return device


def _save_components(
    device: Device,
    definitions: tuple[dict, ...],
    collected_at: datetime,
) -> None:
    existing = {component.component_key: component for component in device.components}
    for definition in definitions:
        data = dict(definition)
        key = data.pop("component_key")
        component = existing.get(key)
        preserve_runtime_evidence = False
        if component is None:
            component = DeviceComponent(
                device_id=device.id,
                component_key=key,
                **data,
            )
            db.session.add(component)
        else:
            preserve_runtime_evidence = (
                key in {"arduino_esp32_core", "esp_idf_runtime"}
                and (
                    component.evidence_status == "VERIFIED"
                    or (
                        component.version is not None
                        and component.evidence_status == "REPORTED"
                    )
                )
            )
            for field, value in data.items():
                if preserve_runtime_evidence and field in {
                    "evidence_method",
                    "evidence_note",
                    "evidence_source",
                    "evidence_status",
                    "confidence",
                    "version",
                }:
                    continue
                setattr(component, field, value)
        if not preserve_runtime_evidence:
            component.collected_at = collected_at


def ensure_solar_guard_components(device: Device) -> None:
    if device.name != "SolarGuard-01":
        raise RuntimeError("Component evidence can only be bootstrapped for SolarGuard-01.")
    _save_components(
        device,
        SOLAR_GUARD_COMPONENTS,
        datetime.now(UTC).replace(tzinfo=None),
    )
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise


def _reference_model_key(model: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", model.lower()).strip("_")


def ensure_sma_firmware_reference_device() -> Device:
    legacy_name = "SMA Sunny Boy TL-21 Test Device"
    matches = list(
        db.session.scalars(
            select(Device)
            .where(
                Device.name.in_((SMA_REFERENCE_DEVICE_NAME, legacy_name))
            )
            .order_by(Device.id.asc())
        )
    )
    if len(matches) > 1:
        raise RuntimeError(
            "Multiple SMA firmware reference inventory records exist; none were changed."
        )

    if matches:
        device = matches[0]
        if device.vendor != "SMA Solar Technology":
            raise RuntimeError(
                "The existing SMA reference record has a conflicting vendor; "
                "no records were changed."
            )
        if device.status == "archived":
            raise RuntimeError(
                "The SMA reference record is archived; no records were changed."
            )
    else:
        candidates = list(
            db.session.scalars(
                select(Device)
                .where(
                    Device.vendor == "SMA Solar Technology",
                    Device.firmware_version == SMA_REFERENCE_VERSION,
                )
                .order_by(Device.id.asc())
            )
        )
        reference_candidates = [
            candidate
            for candidate in candidates
            if "test" in candidate.name.lower()
            or "reference" in candidate.name.lower()
        ]
        if len(reference_candidates) > 1:
            raise RuntimeError(
                "Multiple existing devices carry the SMA reference version; "
                "none were changed."
            )
        if candidates and not reference_candidates:
            raise RuntimeError(
                "A device already uses the SMA reference version but is not "
                "labelled as a test/reference record; no records were changed."
            )
        device = reference_candidates[0] if reference_candidates else None
        if device is not None and device.status == "archived":
            raise RuntimeError(
                "The existing SMA reference candidate is archived; "
                "no records were changed."
            )

    if device is None:
        device = Device(
            name=SMA_REFERENCE_DEVICE_NAME,
            vendor="SMA Solar Technology",
            model="Sunny Boy TL-21 family (reference; exact variant unknown)",
            firmware="unknown",
            firmware_version=None,
            status="active",
        )
        db.session.add(device)
        db.session.flush()

    device.name = SMA_REFERENCE_DEVICE_NAME
    device.vendor = "SMA Solar Technology"
    device.model = "Sunny Boy TL-21 family (reference; exact variant unknown)"
    device.firmware = "unknown"
    device.firmware_version = None
    device.firmware_evidence_source = SMA_REFERENCE_URL
    device.firmware_evidence_method = (
        "Official manufacturer compatibility table; reference only"
    )
    device.firmware_evidence_note = (
        "SMA specifies 2.60.03.R or higher for the exact TL-21 models listed "
        "in component evidence for off-grid use. This is not installed "
        "firmware evidence; no physical inverter or exact variant was inspected."
    )
    device.firmware_evidence_collected_at = datetime.now(UTC).replace(tzinfo=None)
    device.firmware_verification_status = "UNKNOWN"
    device.firmware_confidence = "none"
    device.simulation_status = "reference"
    note = (
        "Reference inventory only; not a physical or simulated installed "
        "inverter. Installed firmware and exact family variant are unknown."
    )
    if note not in (device.notes or ""):
        device.notes = f"{device.notes.rstrip()}\n{note}".strip() if device.notes else note

    collected_at = datetime.now(UTC).replace(tzinfo=None)
    definitions = tuple(
        {
            "component_key": f"sma_firmware_reference_{_reference_model_key(model)}",
            "name": "Documented minimum firmware (reference only)",
            "component_type": "software",
            "vendor": "SMA Solar Technology",
            "product": model,
            "version": SMA_REFERENCE_VERSION,
            "evidence_source": SMA_REFERENCE_URL,
            "evidence_method": (
                "Official SMA off-grid compatibility table; minimum version "
                "requirement"
            ),
            "evidence_note": (
                f"SMA lists {SMA_REFERENCE_VERSION} or higher for {model} in "
                "the documented off-grid-system context. This is a documented "
                "requirement only, not firmware observed on an installed device."
            ),
            "evidence_status": "REFERENCE",
            "confidence": "high",
            "collected_at": collected_at,
        }
        for model in SMA_REFERENCE_MODELS
    )
    _save_components(device, definitions, collected_at)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    return device
