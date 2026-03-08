const CACHE = "invkeeper-v1";
const PRECACHE = ["/", "/deliveries", "/items", "/transfers", "/cash"];

self.addEventListener("install", e => {
    e.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE)));
    self.skipWaiting();
});

self.addEventListener("activate", e => {
    e.waitUntil(caches.keys().then(keys =>
        Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ));
    self.clients.claim();
});

self.addEventListener("fetch", e => {
    if (e.request.method !== "GET" || !e.request.url.startsWith("http")) return;
    e.respondWith(
        fetch(e.request).then(res => {
            if (res.ok && e.request.destination === "document") {
                const clone = res.clone();
                caches.open(CACHE).then(c => c.put(e.request, clone));
            }
            return res;
        }).catch(() => caches.match(e.request))
    );
});