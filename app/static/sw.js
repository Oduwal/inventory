const CACHE = "invkeeper-v3";
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
            if (res.ok && e.request.destination === "document" && !e.request.url.includes("/transactions")) {
                const clone = res.clone();
                caches.open(CACHE).then(c => c.put(e.request, clone));
            }
            return res;
        }).catch(() => caches.match(e.request))
    );
});

self.addEventListener("push", e => {
    let data = {};
    try { data = e.data ? e.data.json() : {}; } catch(_) {}
    const title = data.title || "Inventory Keeper";
    e.waitUntil(self.registration.showNotification(title, {
        body:             data.body || "",
        icon:             "/static/icon-192.png",
        badge:            "/static/badge-96.png",
        data:             { link: data.link || "/" },
        tag:              "invkeeper-" + (data.link || "default").replace(/\//g, "-"),
        renotify:         true,
        requireInteraction: false,
        vibrate:          [200, 100, 200],
    }));
});

self.addEventListener("notificationclick", e => {
    e.notification.close();
    const link = (e.notification.data && e.notification.data.link) || "/";
    e.waitUntil(
        clients.matchAll({ type: "window", includeUncontrolled: true }).then(list => {
            for (const c of list) {
                if (c.url.includes(self.location.origin) && "focus" in c) {
                    c.navigate(link);
                    return c.focus();
                }
            }
            return clients.openWindow(link);
        })
    );
});