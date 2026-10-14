document.addEventListener("DOMContentLoaded", () => {
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
    const severity = document.createElement("span");
    severity.className = `severity-badge ${(item.severity || "unknown").toLowerCase()}`;
    severity.textContent = item.severity || "Unknown severity";
    const score = document.createElement("p");
    score.className = "cve-detail-score";
    score.textContent = `CVSS score: ${item.cvss_score ?? "Not available"}`;
    const description = document.createElement("p");
    description.className = "cve-detail-description";
    description.textContent = item.description || "No description is stored for this CVE.";
    const cwe = document.createElement("p");
    cwe.textContent = `CWE: ${item.cwe || "Not available"}`;
    const source = document.createElement("a");
    source.className = "button secondary";
    source.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`;
    source.target = "_blank";
    source.rel = "noopener noreferrer";
    source.textContent = "Open NVD source ↗";
    container.append(severity, score, description, cwe, source);
  } catch (error) {
    container.replaceChildren(createMessage("Could not load CVE details. Please try again.", "error-state", "p"));
    console.error("CVE detail error:", error);
  }
}
