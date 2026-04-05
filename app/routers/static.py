from fastapi import APIRouter, Request, Depends, Form, HTTPException, BackgroundTasks, Response, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import text, func
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
import json, csv, io, os, logging
from app.core import *
from app.models import *
from app.security import *

router = APIRouter()

#  PWA / STATIC
# ────────────────────────────────────────────────

@router.get("/manifest.json")
def pwa_manifest():
    manifest_path = os.path.join(BASE_DIR, "static", "manifest.json")
    try:
        content = open(manifest_path).read()
    except FileNotFoundError:
        content = "{}"
    return PlainTextResponse(content, headers={"Content-Type": "application/manifest+json; charset=utf-8"})


@router.get("/sw.js", response_class=PlainTextResponse)
def service_worker():
    sw = """const CACHE = "invkeeper-v4";
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
  if (e.request.method !== "GET") return;
  try {
    const url = new URL(e.request.url);
    if (url.origin !== self.location.origin) return;
  } catch(err) { return; }
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
self.addEventListener("push", e => {
  let data = {title: "Inventory Keeper", body: "You have a new notification", link: "/"};
  try { data = Object.assign(data, e.data.json()); } catch(err) {}
  e.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: "/static/icon-192.png",
      badge: "/static/icon-192.png",
      vibrate: [200, 100, 200],
      data: {link: data.link || "/"},
      requireInteraction: true
    })
  );
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = e.notification.data?.link || "/";
  e.waitUntil(
    clients.matchAll({type: "window", includeUncontrolled: true}).then(list => {
      for (const c of list) {
        if (c.url.includes(url) && "focus" in c) return c.focus();
      }
      return clients.openWindow(url);
    })
  );
});"""
    return PlainTextResponse(sw, headers={
        "Content-Type": "application/javascript",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Service-Worker-Allowed": "/",
    })


# NOTE: /debug-login REMOVED [FIX-2]


# ────────────────────────────────────────────────
