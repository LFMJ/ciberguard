// Sin scripts en línea: la política CSP solo permite archivos propios.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("form[data-confirm]").forEach((f) => {
    f.addEventListener("submit", (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });

  const arc = document.getElementById("arc");
  if (arc) {
    const len = parseFloat(arc.dataset.len), score = parseFloat(arc.dataset.score);
    arc.style.strokeDashoffset = len;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      arc.style.strokeDashoffset = len * (1 - score / 100);
    }));
  }
});

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-print]").forEach((b) => b.addEventListener("click", () => window.print()));
});
