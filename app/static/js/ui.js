document.addEventListener("DOMContentLoaded", () => {
  const flash = document.querySelector(".flash")
  if (flash) {
    setTimeout(() => flash.remove(), 4000);
  }
});
