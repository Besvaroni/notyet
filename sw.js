// NotYet - service worker: permite instalar la app y abrirla sin conexión.
// Las páginas se piden siempre a la red primero (así nunca se queda una versión vieja); la copia guardada solo se usa sin conexión.
const C = "notyet-v1";
const SHELL = ["/app", "/", "/icon-192.png", "/icon-512.png", "/manifest.webmanifest"];
self.addEventListener("install", (e) => { e.waitUntil(caches.open(C).then((c) => c.addAll(SHELL)).catch(() => {})); self.skipWaiting(); });
self.addEventListener("activate", (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== C).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener("fetch", (e) => {
  const r = e.request; if (r.method !== "GET") return;
  const u = new URL(r.url); if (u.origin !== location.origin) return;
  if (r.mode === "navigate") { e.respondWith(fetch(r).then((res) => { const cp = res.clone(); caches.open(C).then((c) => c.put(u.pathname === "/app.html" ? "/app" : u.pathname, cp)).catch(() => {}); return res; }).catch(() => caches.match(u.pathname === "/app.html" ? "/app" : u.pathname).then((m) => m || caches.match("/app")))); return; }
  if (/\.(png|webmanifest)$/.test(u.pathname)) e.respondWith(caches.match(r).then((m) => m || fetch(r)));
});
