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

// Menú lateral en celular. Sin JavaScript también funciona con #menu (:target).
document.addEventListener("DOMContentLoaded", () => {
  const menu = document.getElementById("menu");
  const opener = document.querySelector("[data-nav-open]");
  if (!menu || !opener) return;
  const mobile = () => window.matchMedia("(max-width: 960px)").matches;

  const open = () => {
    document.body.classList.add("nav-open");
    opener.setAttribute("aria-expanded", "true");
    const current = menu.querySelector("[aria-current=page]") || menu.querySelector("a");
    current && current.focus();
  };
  const close = (returnFocus) => {
    document.body.classList.remove("nav-open");
    opener.setAttribute("aria-expanded", "false");
    if (location.hash === "#menu") history.replaceState(null, "", location.pathname + location.search);
    if (returnFocus) opener.focus();
  };

  opener.addEventListener("click", (e) => { e.preventDefault(); open(); });
  document.querySelectorAll("[data-nav-close]").forEach((el) =>
    el.addEventListener("click", (e) => { e.preventDefault(); close(true); }));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && document.body.classList.contains("nav-open")) close(true);
    // Mantiene el foco dentro del menú mientras está abierto.
    if (e.key === "Tab" && document.body.classList.contains("nav-open") && mobile()) {
      const items = [...menu.querySelectorAll("a[href], button")].filter((x) => x.offsetParent !== null);
      const first = items[0], last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
  window.matchMedia("(max-width: 960px)").addEventListener("change", (m) => { if (!m.matches) close(false); });
});
