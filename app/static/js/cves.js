document.addEventListener("DOMContentLoaded", () => {
  const syncForm = document.querySelector("[data-sync-form]");
  if (syncForm) {
    syncForm.addEventListener("submit", () => {
      const button = syncForm.querySelector('button[type="submit"]');
      const status = syncForm.querySelector("[data-sync-status]");
      button.disabled = true;
      button.textContent = "Syncing…";
      status.hidden = false;
      status.textContent = "Contacting NVD and saving returned records…";
    });
  }

  const search = document.querySelector("[data-cve-search]");
  const list = document.querySelector("[data-cve-list]");
  if (search && list) {
    let timer;
    search.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        const query = search.value.trim();
        list.replaceChildren();
        if (!query) {
          list.append(createMessage("Enter a CVE ID or keyword to search.", "empty-state"));
          return;
        }
        list.append(createMessage("Searching stored CVE records…", "loading-state"));
        try {
          const response = await fetch(`/api/cves?q=${encodeURIComponent(query)}`);
          if (!response.ok) throw new Error(`CVE search failed (${response.status}).`);
          const payload = await response.json();
          list.replaceChildren();
          const items = payload.items || [];
          if (!items.length) {
            list.append(createMessage("No CVE results found.", "empty-state"));
            return;
          }
          items.forEach((item) => list.append(renderCveResult(item)));
        } catch (error) {
          list.replaceChildren();
          list.append(createMessage("Could not load CVEs. Please try again.", "error-state"));
          console.error("CVE search error:", error);
        }
      }, 300);
    });
  }

  const detail = document.querySelector("[data-cve-detail]");
  if (detail) loadCveDetail(detail);
});

function createMessage(text, className, tagName = "li") {
  const message = document.createElement(tagName);
  message.className = className;
  message.textContent = text;
  return message;
}

function renderCveResult(item) {
  const row = document.createElement("li");
  row.className = "cve-result";
  const heading = document.createElement("div");
  heading.className = "cve-result-heading";
  const title = document.createElement("a");
  title.href = `/cves/${encodeURIComponent(item.id || "")}`;
  title.textContent = item.id;
  if (!title.textContent) title.textContent = "Unknown CVE";
  const severity = document.createElement("span");
  severity.className = `severity-badge ${(item.severity || "unknown").toLowerCase()}`;
  severity.textContent = item.severity || "Unknown severity";
  const description = document.createElement("p");
  description.textContent = item.description || "No description available.";
  heading.append(title, severity);
  row.append(heading, description);
  return row;
}

async function loadCveDetail(container) {
  const cveId = container.dataset.cveId;
  try {
    const response = await fetch(`/api/cves/${encodeURIComponent(cveId)}`);
    if (response.status === 404) {
      container.replaceChildren(createMessage("This CVE is not present in the local database.", "empty-state", "p"));
      return;
    }
    if (!response.ok) throw new Error(`CVE detail request failed (${response.status}).`);
    const item = await response.json();
    container.replaceChildren();

    const section = (title, description = "") => {
      const element = document.createElement("section");
      element.className = "cve-detail-section";
      const heading = document.createElement("h2");
      heading.textContent = title;
      element.append(heading);
      if (description) {
        const copy = document.createElement("p");
        copy.textContent = description;
        element.append(copy);
      }
      return element;
    };
    const textRow = (label, value) => {
      const row = document.createElement("p");
      const strong = document.createElement("strong");
      strong.textContent = `${label}: `;
      row.append(strong, document.createTextNode(value || "Not available."));
      return row;
    };

    const severity = document.createElement("span");
    severity.className = `severity-badge ${(item.severity || "unknown").toLowerCase()}`;
    severity.textContent = item.severity || "Unknown severity";
    const summary = section(item.id, item.description || "No description is stored for this CVE.");
    summary.classList.add("cve-summary");
    summary.prepend(severity);
    summary.append(
      textRow("CVSS score", item.cvss_score == null ? "Not available" : String(item.cvss_score)),
      textRow("CVSS vector", item.cvss_vector || "Not available"),
      textRow("Published", item.published_date || "Not available"),
      textRow("Last modified", item.last_modified_date || "Not available"),
      textRow("CWE", item.cwe || "Not available"),
    );

    const productSection = section(
      "Affected products and version ranges",
      "NVD CPE criteria are displayed as source data; ranges are not equivalent to a verified fixed version.",
    );
    const products = item.affected_products || [];
    if (!products.length) {
      productSection.append(createMessage("No CPE version range is stored for this CVE.", "empty-state", "p"));
    }
    products.forEach((product) => {
      const row = document.createElement("article");
      row.className = "evidence-row";
      row.append(textRow("CPE", product.criteria || "Not available."));
      row.append(textRow(
        "NVD range",
        [
          product.versionStartIncluding && `from ${product.versionStartIncluding} (inclusive)`,
          product.versionStartExcluding && `after ${product.versionStartExcluding}`,
          product.versionEndIncluding && `through ${product.versionEndIncluding} (inclusive)`,
          product.versionEndExcluding && `before ${product.versionEndExcluding}`,
        ].filter(Boolean).join("; ") || "No explicit version bounds.",
      ));
      productSection.append(row);
    });

    const assessmentSection = section(
      "Device assessments",
      "A confirmed version match means the recorded software version matched NVD applicability criteria; it does not mean exploitation was observed.",
    );
    const assessments = item.assessments || [];
    if (!assessments.length) {
      assessmentSection.append(createMessage("No device assessment has been recorded.", "empty-state", "p"));
    }
    assessments.forEach((assessment) => {
      const row = document.createElement("article");
      row.className = "evidence-row";
      const status = document.createElement("span");
      status.className = `assessment-tag ${assessment.match_status || "unknown"}`;
      status.textContent = (assessment.match_status || "unknown").replaceAll("_", " ");
      row.append(status);
      row.append(textRow("Device", assessment.device_name));
      row.append(textRow(
        "Component",
        assessment.component_name
          ? `${assessment.component_name} ${assessment.component_version || "version unknown"}`
          : "Not identified",
      ));
      row.append(textRow("Confidence", assessment.confidence || "unknown"));
      row.append(textRow("Evidence source", assessment.matched_by || "Not recorded"));
      row.append(textRow("Evidence", assessment.evidence || assessment.summary || "No evidence stored."));
      assessmentSection.append(row);
    });

    const advisorySection = section("Official vendor advisory", "Links are shown only when the NVD record tags them as a vendor advisory.");
    const advisories = item.vendor_advisories || [];
    if (!advisories.length) {
      advisorySection.append(createMessage("No vendor advisory link is stored in this NVD record.", "empty-state", "p"));
    }
    advisories.forEach((advisory) => {
      const link = document.createElement("a");
      link.href = advisory.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = advisory.url;
      advisorySection.append(link);
    });

    const patchSection = section("Patch and next action");
    const candidates = item.patch_candidates || [];
    if (!candidates.length) {
      patchSection.append(createMessage("No patch candidate is recorded. Do not infer a fix version from this CVE record alone.", "inline-warning", "p"));
    }
    candidates.forEach((candidate) => {
      const row = document.createElement("article");
      row.className = "evidence-row";
      row.append(textRow("Component", candidate.component_name));
      row.append(textRow("Version", candidate.recommended_version || "No verified fixed version."));
      row.append(textRow(
        "Record status",
        candidate.is_simulated ? `SIMULATED ONLY · ${candidate.status}` : candidate.status,
      ));
      row.append(textRow("Evidence", candidate.evidence || "No evidence stored."));
      if (candidate.patch_url && !candidate.is_simulated) {
        const link = document.createElement("a");
        link.href = candidate.patch_url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = "Open recorded patch source";
        row.append(link);
      } else {
        row.append(createMessage("No verified official patch URL is available.", "inline-warning", "p"));
      }
      patchSection.append(row);
    });

    const source = document.createElement("a");
    source.className = "button secondary";
    source.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
    source.target = "_blank";
    source.rel = "noopener noreferrer";
    source.textContent = "Open NVD record";
    container.append(summary, productSection, assessmentSection, advisorySection, patchSection, source);
  } catch (error) {
    container.replaceChildren(createMessage("Could not load CVE details. Please try again.", "error-state", "p"));
    console.error("CVE detail error:", error);
  }
}
