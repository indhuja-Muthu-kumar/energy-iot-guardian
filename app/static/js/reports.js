document.addEventListener("DOMContentLoaded", () => {
  const exportButton = document.querySelector("[data-export-csv]");
  if (exportButton) {
    exportButton.addEventListener("click", () => {
      window.location.href = "/api/reports/csv";
    });
  }
});
