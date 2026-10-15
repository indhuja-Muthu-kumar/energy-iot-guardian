const SVG_NS = "http://www.w3.org/2000/svg";
const SEVERITY_COLORS = ["critical", "high", "medium", "low"];

function svgElement(name, attributes = {}) {
  const element = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attributes)) {
    element.setAttribute(key, value);
  }
  return element;
}

function renderTrendChart(svg) {
  const points = JSON.parse(svg.dataset.trendPoints || "[]");
  const state = document.querySelector("[data-trend-state]");
  if (!points.length) {
    state.textContent = "No completed scans with trend data yet.";
    return;
  }

  const values = points.map((point) => Number(point.potential));
  const maxValue = Math.max(1, ...values);
  const xStart = 42;
  const xEnd = 688;
  const yTop = 22;
  const yBottom = 143;
  const x = (index) => points.length === 1
    ? (xStart + xEnd) / 2
    : xStart + (xEnd - xStart) * index / (points.length - 1);
  const y = (value) => yBottom - (value / maxValue) * (yBottom - yTop);

  const axis = svg.querySelector("[data-trend-axis]");
  [0, 1, 2, 3].forEach((step) => {
    const label = svgElement("text", { x: "3", y: String(143 - step * 40 + 3) });
    label.textContent = String(Math.round(maxValue * step / 3));
    axis.append(label);
  });

  const linePoints = points.map((point, index) => `${x(index)},${y(Number(point.potential))}`);
  const line = svg.querySelector("[data-trend-line]");
  line.setAttribute("d", `M ${linePoints.join(" L ")}`);
  svg.querySelector("[data-trend-area]").setAttribute(
    "d",
    `M ${x(0)},${yBottom} L ${linePoints.join(" L ")} L ${x(points.length - 1)},${yBottom} Z`,
  );

  const dots = svg.querySelector("[data-trend-dots]");
  const labels = svg.querySelector("[data-trend-labels]");
  points.forEach((point, index) => {
    const dot = svgElement("circle", {
      class: "trend-dot",
      cx: String(x(index)),
      cy: String(y(Number(point.potential))),
      r: "3.2",
    });
    const title = svgElement("title");
    title.textContent = `${point.label}: ${point.potential} potential findings`;
    dot.append(title);
    dots.append(dot);

    const label = svgElement("text", {
      x: String(x(index)),
      y: "164",
    });
    label.textContent = point.label;
    labels.append(label);
  });

  state.hidden = true;
}

function renderSeverityDonut(svg) {
  const values = JSON.parse(svg.dataset.severityValues || "[]").map(Number);
  const total = values.reduce((sum, value) => sum + value, 0);
  if (!total) return;

  const circumference = 2 * Math.PI * 48;
  const segments = svg.querySelector("[data-donut-segments]");
  let offset = 0;
  values.forEach((value, index) => {
    if (value <= 0) return;
    const segmentLength = circumference * value / total;
    segments.append(svgElement("circle", {
      class: `donut-segment ${SEVERITY_COLORS[index]}`,
      cx: "60",
      cy: "60",
      r: "48",
      "stroke-dasharray": `${segmentLength} ${circumference - segmentLength}`,
      "stroke-dashoffset": String(-offset),
    }));
    offset += segmentLength;
  });
}

function startDeviceTelemetry() {
  const panel = document.querySelector("[data-device-telemetry]");
  if (!panel) return;

  const historyBody = panel.querySelector("[data-telemetry-history]");
  const errorMessage = panel.querySelector("[data-telemetry-error]");
  const sessionMessage = panel.querySelector("[data-telemetry-session]");
  const ageElement = panel.querySelector("[data-telemetry-age]");
  const staleAfterSeconds = Number(panel.dataset.staleAfterSeconds || 10);
  const formatter = new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  let lastKnownStatus = null;
  let lastReceivedAt = null;
  let retryDelayMs = 3000;

  const displayText = (selector, value) => {
    panel.querySelector(selector).textContent = String(value);
  };

  function renderEmpty(message) {
    displayText("[data-telemetry-status]", message);
    historyBody.replaceChildren();
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 4;
    cell.textContent = message;
    row.append(cell);
    historyBody.append(row);
    displayText("[data-telemetry-voltage]", "--");
    displayText("[data-telemetry-current]", "--");
    displayText("[data-telemetry-power]", "--");
    displayText("[data-telemetry-message-id]", "--");
    ageElement.textContent = "—";
    lastKnownStatus = null;
    lastReceivedAt = null;
  }

  function updateAge() {
    if (!lastReceivedAt) return;
    const ageSeconds = Math.max(
      0,
      Math.floor((Date.now() - lastReceivedAt.getTime()) / 1000),
    );
    const age = ageSeconds < 2
      ? "just now"
      : `${ageSeconds} second${ageSeconds === 1 ? "" : "s"} ago`;
    ageElement.textContent = age;
    const stale = ageSeconds >= staleAfterSeconds;
    if (errorMessage.hidden) {
      displayText(
        "[data-telemetry-status]",
        stale && lastKnownStatus === "Online · SIMULATED"
          ? `Stale · SIMULATED · last reading is ${age}`
          : lastKnownStatus,
      );
    } else {
      displayText(
        "[data-telemetry-status]",
        stale
          ? `Stale reading · last known ${lastKnownStatus}`
          : `Last known: ${lastKnownStatus}`,
      );
    }
  }

  function showBackendError(message) {
    displayText(
      "[data-telemetry-status]",
      lastKnownStatus ? `Last known: ${lastKnownStatus}` : "Backend unavailable",
    );
    errorMessage.textContent = `${message} Retrying in ${Math.ceil(retryDelayMs / 1000)} seconds.`;
    errorMessage.hidden = false;
    sessionMessage.hidden = true;
    updateAge();
  }

  function showSessionExpired() {
    displayText(
      "[data-telemetry-status]",
      lastKnownStatus ? `Last known: ${lastKnownStatus}` : "Session expired",
    );
    errorMessage.textContent = lastReceivedAt
      ? "Your session expired. The last received reading is retained; sign in to resume updates."
      : "Your session expired. Sign in to view telemetry and resume updates.";
    errorMessage.hidden = false;
    sessionMessage.hidden = false;
    updateAge();
  }

  function renderTelemetry(data) {
    if (!data.latest || !Array.isArray(data.history)) {
      renderEmpty(
        data.state === "archived"
          ? "Device archived; no telemetry history is available."
          : "No telemetry received yet.",
      );
      errorMessage.hidden = true;
      sessionMessage.hidden = true;
      return;
    }

    const latest = data.latest;
    lastReceivedAt = new Date(latest.received_at);
    displayText("[data-telemetry-voltage]", Number(latest.voltage).toFixed(1));
    displayText("[data-telemetry-current]", Number(latest.current).toFixed(1));
    displayText("[data-telemetry-power]", Number(latest.power).toFixed(1));
    const stateText = {
      connected: "Online · SIMULATED",
      stale: "Offline · SIMULATED · no recent telemetry",
      demo: "Local demo · not connected · simulated",
      demo_stale: "Local demo · stale · not live",
      archived: "Archived · history only",
    };
    lastKnownStatus = stateText[data.state] || "Status unknown";
    displayText("[data-telemetry-status]", lastKnownStatus);
    errorMessage.hidden = true;
    sessionMessage.hidden = true;
    const sourceElement = panel.querySelector("[data-telemetry-source]");
    sourceElement.textContent = data.latest.payload_source === "local_demo"
      ? (data.latest.ingest_source === "mqtt"
        ? "SIMULATED DEVICE · MQTT · SYNTHETIC DEMO"
        : "SIMULATED DEVICE · LOCAL DEMO · NOT LIVE")
      : data.latest.payload_source === "wokwi_simulation"
        ? "SIMULATED DEVICE · MQTT · WOKWI-REPORTED"
        : "SIMULATED DEVICE · MQTT · SOURCE UNKNOWN";
    displayText("[data-telemetry-message-id]", latest.message_id);
    const timestampSources = {
      device_utc: "Device UTC clock",
      server_received: "Server receipt time; device supplied uptime fallback",
      server_generated: "Server-generated demo time",
      unknown: "Unknown timestamp source",
    };
    const sourceUptime = latest.source_uptime_ms === null
      ? ""
      : ` · device uptime ${latest.source_uptime_ms} ms`;
    displayText(
      "[data-telemetry-timestamp-source]",
      `${timestampSources[latest.timestamp_source] || "Unknown timestamp source"}${sourceUptime}`,
    );
    const received = new Date(latest.received_at);
    const receivedElement = panel.querySelector("[data-telemetry-received]");
    receivedElement.dateTime = received.toISOString();
    receivedElement.textContent = formatter.format(received);
    updateAge();

    if (data.runtime) {
      displayText(
        "[data-telemetry-chip]",
        `${data.runtime.chip_model} · revision ${data.runtime.chip_revision}`,
      );
      displayText("[data-telemetry-arduino]", data.runtime.arduino_core_version);
      displayText("[data-telemetry-idf]", data.runtime.esp_idf_version);
      displayText(
        "[data-telemetry-evidence]",
        `${data.runtime.evidence_note} Evidence confidence: ${data.runtime.confidence}; independently verified: no.`,
      );
    }

    if (data.product_firmware) {
      const productFirmware = data.product_firmware;
      displayText(
        "[data-product-firmware]",
        productFirmware.status === "unknown"
          ? "Unknown; version-specific applicability cannot be confirmed."
          : `${productFirmware.version} (recorded in inventory; not independently verified).`,
      );
    }

    historyBody.replaceChildren();
    data.history.forEach((item) => {
      const row = document.createElement("tr");
      const time = formatter.format(new Date(item.timestamp));
      [time, Number(item.voltage).toFixed(1), Number(item.current).toFixed(1), Number(item.power).toFixed(1)]
        .forEach((value) => {
          const cell = document.createElement("td");
          cell.textContent = String(value);
          row.append(cell);
        });
      historyBody.append(row);
    });
  }

  async function pollTelemetry() {
    let nextDelay = retryDelayMs;
    try {
      const response = await fetch(panel.dataset.telemetryUrl, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (
        response.status === 401 ||
        response.redirected &&
        new URL(response.url, window.location.href).pathname === "/auth/login"
      ) {
        showSessionExpired();
      } else if (!response.ok) {
        showBackendError(`Telemetry API returned HTTP ${response.status}.`);
      } else if (!response.headers.get("content-type")?.includes("application/json")) {
        showBackendError("Telemetry API returned a non-JSON response.");
      } else {
        renderTelemetry(await response.json());
        retryDelayMs = 3000;
        nextDelay = retryDelayMs;
      }
    } catch (error) {
      console.error("Telemetry could not be refreshed.", error);
      showBackendError(
        error instanceof TypeError
          ? "Could not reach the telemetry service."
          : "The telemetry response could not be read.",
      );
    }

    if (errorMessage.hidden && sessionMessage.hidden) {
      retryDelayMs = 3000;
    } else {
      nextDelay = retryDelayMs;
      retryDelayMs = Math.min(retryDelayMs * 2, 30000);
    }
    window.setTimeout(pollTelemetry, nextDelay);
  }

  pollTelemetry();
  window.setInterval(updateAge, 1000);
}

document.addEventListener("DOMContentLoaded", () => {
  try {
    const trend = document.querySelector("[data-trend-chart]");
    const donut = document.querySelector("[data-severity-chart]");
    if (trend) renderTrendChart(trend);
    if (donut) renderSeverityDonut(donut);
    startDeviceTelemetry();
  } catch (error) {
    console.error("Dashboard charts could not be rendered.", error);
    const state = document.querySelector("[data-trend-state]");
    if (state) {
      state.hidden = false;
      state.textContent = "Charts are unavailable; dashboard counts remain visible.";
    }
  }
});
