async function saveDevice(form, endpoint, status, action) {
  const button = form.querySelector('button[type="submit"]');
  const originalLabel = button.textContent;
  button.disabled = true;
  button.textContent = action === "add" ? "Adding..." : "Saving...";
  status.textContent = action === "add" ? "Adding device..." : "Saving device...";
  status.hidden = false;

  try {
    const payload = Object.fromEntries(new FormData(form).entries());
    const response = await fetch(endpoint, {
      method: action === "add" ? "POST" : "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": document.querySelector('meta[name="csrf-token"]').content,
      },
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => null);

    if (!response.ok) {
      if (response.status === 400 && result?.errors) {
        const messages = Object.entries(result.errors).flatMap(
          ([field, errors]) =>
            (Array.isArray(errors) ? errors : [String(errors)]).map(
              (message) => `${field}: ${message}`,
            ),
        );
        throw new Error(`Please correct the following: ${messages.join("; ")}`);
      }
      if (response.status >= 500) {
        throw new Error("The server could not save this device. Please try again.");
      }
      throw new Error(
        result?.error || `The request failed with status ${response.status}.`,
      );
    }
    if (!result) {
      throw new Error("The server returned an invalid response. Please try again.");
    }

    status.textContent =
      action === "add"
        ? "Device added successfully. Refreshing the inventory..."
        : "Device updated successfully. Refreshing the details...";
    window.setTimeout(() => window.location.reload(), 700);
  } catch (error) {
    status.textContent =
      error instanceof TypeError
        ? "Network error: could not reach the server. Check your connection and try again."
        : error.message;
    button.disabled = false;
    button.textContent = originalLabel;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const inventorySearch = document.querySelector("[data-device-search]");
  if (inventorySearch) {
    const rows = Array.from(document.querySelectorAll("[data-device-row]"));
    const empty = document.querySelector("[data-device-empty]");
    inventorySearch.addEventListener("input", () => {
      const needle = inventorySearch.value.trim().toLowerCase();
      let visible = 0;
      rows.forEach((row) => {
        const matches = row.dataset.search.includes(needle);
        row.hidden = !matches;
        visible += Number(matches);
      });
      if (empty) empty.hidden = visible !== 0;
    });
  }

  const editForm = document.querySelector("[data-device-edit]");
  if (editForm) {
    editForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const status = document.querySelector("[data-device-edit-status]");
      saveDevice(
        editForm,
        `/api/devices/${editForm.dataset.deviceId}`,
        status,
        "edit",
      );
    });
  }

  const createForm = document.querySelector("[data-device-create]");
  if (createForm) {
    createForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const status = document.querySelector("[data-device-status]");
      saveDevice(createForm, "/api/devices", status, "add");
    });
  }

  const form = document.querySelector("[data-device-form]");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = document.querySelector("[data-scan-status]");
    const token = document.querySelector('meta[name="csrf-token"]').content;
    try {
      const payload = Object.fromEntries(new FormData(form).entries());
      payload.device_id = Number(payload.device_id);
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": token,
        },
        body: JSON.stringify(payload),
      });
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.summary || result.error || "Unable to run scan.");
      }
      window.location.href = `/scans/${result.id}`;
    } catch (error) {
      status.textContent = error.message;
      status.hidden = false;
    }
  });
});
