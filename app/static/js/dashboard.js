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
  const formatter = new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  const displayText = (selector, value) => {
    panel.querySelector(selector).textContent = String(value);
  };

  function renderWaiting(message) {
    displayText("[data-telemetry-status]", message);
    historyBody.replaceChildren();
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 4;
    cell.textContent = message;
    row.append(cell);
    historyBody.append(row);
  }

  function renderTelemetry(data) {
    if (!data.latest || !Array.isArray(data.history)) {
      renderWaiting(data.message || "Waiting for telemetry from Wokwi.");
      return;
    }

    const latest = data.latest;
    displayText("[data-telemetry-voltage]", Number(latest.voltage).toFixed(1));
    displayText("[data-telemetry-current]", Number(latest.current).toFixed(1));
    displayText("[data-telemetry-power]", Number(latest.power).toFixed(1));
    const stateText = {
      connected: "Connected · SIMULATED",
      stale: "Stale · SIMULATED",
      archived: "Archived · history only",
    };
    displayText("[data-telemetry-status]", stateText[data.state] || "Unknown");
    const received = new Date(latest.received_at);
    const receivedElement = panel.querySelector("[data-telemetry-received]");
    receivedElement.dateTime = received.toISOString();
    receivedElement.textContent = formatter.format(received);

    if (data.runtime) {
      displayText(
        "[data-telemetry-chip]",
        `${data.runtime.chip_model} · revision ${data.runtime.chip_revision}`,
      );
      displayText("[data-telemetry-arduino]", data.runtime.arduino_core_version);
      displayText("[data-telemetry-idf]", data.runtime.esp_idf_version);
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
    try {
      const response = await fetch(panel.dataset.telemetryUrl, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Telemetry API returned HTTP ${response.status}.`);
      }
      renderTelemetry(await response.json());
    } catch (error) {
      console.error("Wokwi telemetry could not be loaded.", error);
      renderWaiting("Telemetry service unavailable; retrying…");
    }
  }

  pollTelemetry();
  window.setInterval(pollTelemetry, 3000);
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
