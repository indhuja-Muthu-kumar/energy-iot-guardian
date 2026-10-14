document.addEventListener("DOMContentLoaded", () => {
  const flash = document.querySelector(".flash");
  if (flash) {
    setTimeout(() => flash.remove(), 4000);
  }

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
});
