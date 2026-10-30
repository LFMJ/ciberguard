// Generado por /sw.js. Solo guarda archivos estáticos y la página sin conexión: nunca páginas con sesión.
const CACHE = "ciberguard-{{ version }}";
const PRECACHE = {{ precache|safe }};
const OFFLINE = {{ offline|safe }};

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k.startsWith("ciberguard-") && k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET" || new URL(req.url).origin !== location.origin) return;
  if (req.mode === "navigate") {
    // Páginas: siempre de la red. Sin internet se muestra el aviso, no una copia vieja.
    e.respondWith(fetch(req).catch(() => caches.match(OFFLINE)));
    return;
  }
  if (new URL(req.url).pathname.startsWith("/static/")) {
    e.respondWith(caches.match(req).then((hit) => hit || fetch(req).then((resp) => {
      if (resp.ok) { const copy = resp.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
      return resp;
    })));
  }
});
