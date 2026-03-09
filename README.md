# Security Fixes — Setup Guide

## Files Included
| File | What changed |
|------|-------------|
| `security.py` | NEW — add this to your app folder |
| `main.py` | All 8 fixes applied — replaces your original |
| `login.html` | CSRF token added — replaces your original |

---

## Step 1: Install New Dependencies

Add these to your `requirements.txt`:

```
uvicorn[standard]
bleach
```

Then redeploy on Railway — it will install them automatically.

---

## Step 2: Add Environment Variables on Railway

Go to your Railway project → your service → **Variables** tab.
Add these:

### REQUIRED (app will refuse to start without these)

| Variable | Value |
|----------|-------|
| `SESSION_SECRET` | Generate with: `python -c "import secrets; print(secrets.token_hex(32))"` |

### RECOMMENDED

| Variable | Value |
|----------|-------|
| `HTTPS_ONLY` | `1` (keep as 1 — never set to 0 in production) |
| `ADMIN_USERNAME` | Your admin username |
| `ADMIN_PASSWORD` | A strong password (8+ characters) |

---

## Step 3: Add CSRF Token to Your Other Templates

Every HTML form that uses POST needs this hidden field added inside the `<form>` tag.

**In your GET route**, pass `csrf_token` to the template:
```python
csrf_token = get_csrf_token(request)
return templates.TemplateResponse("your_template.html", {
    "request": request,
    "csrf_token": csrf_token,
    # ... other context
})
```

**In your HTML template**, add inside every `<form method="post">`:
```html
<input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
```

**In your POST route**, accept and verify it:
```python
@app.post("/your-route")
def your_handler(
    ...,
    csrf_token: str = Form(""),
    ...
):
    verify_csrf_token(request, csrf_token)
    # rest of handler
```

Forms that need this (not yet in this patch — do these yourself):
- `delivery_new.html`       → `/deliveries/new` POST
- `item_edit.html`          → `/items/{id}/edit` GET/POST
- `agent_new.html`          → `/agents/new` GET/POST
- `tx_form.html`            → `/transactions/new` POST
- `cash_dashboard.html`     → `/cash/new` POST
- `transfer_new.html`       → `/transfers/new` GET/POST
- `transfer_detail.html`    → receive/cancel buttons
- `branch_new.html`         → `/branches/new` GET/POST
- `base.html` logout button → already uses POST form, add token there

---

## Step 4: Verify the Fixes Are Working

After deploying, check these:

1. **`/debug-login` is gone** — visiting it should return 404
2. **Login rate limiting** — try logging in 11 times in a row with wrong credentials, you should get a 429 error
3. **Missing SESSION_SECRET** — temporarily remove the env var, redeploy. App should refuse to start with a clear error message (then add it back)
4. **Reset system is POST-only** — visiting `/admin/reset-system` via browser (GET) now shows a confirmation page instead of immediately wiping data

---

## Summary of All 8 Fixes

| # | Fix | Severity |
|---|-----|----------|
| FIX-1 | `SESSION_SECRET` hard-fails at startup if missing | 🔴 Critical |
| FIX-2 | `/debug-login` endpoint removed | 🔴 Critical |
| FIX-3 | Rate limiting on `/login` (10 req / 60s per IP) | 🔴 Critical |
| FIX-4 | CSRF tokens on all POST forms | 🟠 High |
| FIX-5 | Input sanitization on all free-text fields | 🟠 High |
| FIX-6 | `ProxyHeadersMiddleware` for real client IP via Railway | 🟠 High |
| FIX-7 | Minimum password length raised 4 → 8 characters | 🟡 Medium |
| FIX-8 | `/admin/reset-system` converted to POST + confirmation | 🟡 Medium |
