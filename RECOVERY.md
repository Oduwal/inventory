# INVENTORY_KEEPER — Recovery Runbook

Last updated: 2026-05-15
Owner: Peace (osaidepeace1@gmail.com)

This is the document you read at 2am when something is broken.
Stay calm. Almost everything here is recoverable in under an hour.

---

## Architecture (so you remember what depends on what)

| Component | Where it lives | Recovery source if lost |
| --- | --- | --- |
| FastAPI app + WhatsApp bot | Hetzner CX22 (Docker) | GitHub repo |
| Postgres database | Railway (managed) | Railway daily backups |
| WhatsApp bot session | Hetzner Docker volume | Backblaze B2 nightly tarball |
| Config / `.env` / Caddyfile | Hetzner `/opt/inventory/` | Backblaze B2 nightly tarball |
| Domain registration | Cloudflare Registrar (or Namecheap) | Account login |
| DNS | Cloudflare (free) | Account login |
| Monitoring | UptimeRobot (free) | Account login |

**Key principle:** the only irreplaceable thing is the database, and it lives on Railway, not Hetzner. Everything else can be rebuilt from git + B2 in ~90 minutes.

---

## Important URLs and accounts (fill these in)

- Production URL: https://_____________
- Hetzner Cloud Console: https://console.hetzner.cloud
- Railway dashboard: https://railway.app
- Cloudflare dashboard: https://dash.cloudflare.com
- Backblaze B2: https://secure.backblaze.com
- UptimeRobot: https://uptimerobot.com
- GitHub repo: https://github.com/_____________
- Twilio console: https://console.twilio.com
- VAPI dashboard: https://dashboard.vapi.ai

Server SSH: `ssh deploy@<production-ip>`
DR fallback provider account: __________ (Netcup / OVH / DigitalOcean — pick one and create the account NOW, before you need it)

---

## Quick triage — site is down, what now?

Run this checklist top to bottom. Stop when you find the cause.

1. **Check UptimeRobot** — is it actually down or just slow?
2. **Check Hetzner status:** https://status.hetzner.com
   - If red → it's their fault, wait it out. Tweet @hetzner_online if >1 hour.
3. **Check Railway status:** https://status.railway.app
   - If red → database is the issue, the VPS is fine. Wait.
4. **Try SSH:** `ssh deploy@<ip>`
   - SSH works → jump to "App is broken but server is up"
   - SSH fails → jump to "Server unreachable"
5. **Check Cloudflare:** if DNS is misconfigured, the site is "down" even though everything works
6. **Check your domain registrar:** did the domain expire? (set auto-renew on day one)

---

## Scenario A — App is broken but server is up

You can SSH in. Something inside Docker is wrong.

```bash
ssh deploy@<ip>
cd /opt/inventory
docker compose ps                          # see what's running
docker compose logs --tail=200 web         # FastAPI logs
docker compose logs --tail=200 whatsapp_bot # bot logs
docker compose logs --tail=200 caddy       # reverse proxy logs
```

Common fixes:

- **A container is exited:** `docker compose up -d <service>`
- **A container is restart-looping:** read the logs, fix the bug, redeploy
- **All containers running but app 502s:** Caddy may not be reaching the app — check `docker compose logs caddy` for upstream errors
- **Disk full:** `df -h`. If `/var/lib/docker` is huge: `docker system prune -af`

### Rollback a bad deploy
```bash
cd /opt/inventory
git log --oneline -10                  # find last good commit
git checkout <good-sha>
docker compose up -d --build
```

### Restart everything
```bash
docker compose restart                 # gentle
docker compose down && docker compose up -d   # hard
```

---

## Scenario B — Server unreachable (SSH fails, ping fails)

1. **Check Hetzner Cloud Console** → your server → status
2. If running but unreachable: click **"Power Cycle"** (force reboot)
3. Wait 90 seconds, try SSH again
4. SSH back, check containers came up: `docker compose ps`

If power-cycle doesn't fix it, or Hetzner shows hardware issue → go to Scenario C.

---

## Scenario C — VM is dead, hardware issue, or accidentally deleted

This is the disaster scenario. Estimated recovery time: **30 minutes from snapshot**, **90 minutes from B2 backups**.

### C1. Restore from Hetzner snapshot (fastest)

1. Hetzner Console → Snapshots → find latest → **"Create server from snapshot"**
2. Same region, same SSH key, same VM type
3. Note the new IP
4. Cloudflare → DNS → update A record for your domain to new IP (TTL 60s)
5. Wait ~5 min for DNS propagation
6. SSH in, verify: `docker compose ps`
7. Caddy will auto-reissue Let's Encrypt certs
8. Done. No webhook changes needed (DNS-based).

### C2. No usable snapshot — full rebuild from scratch

```bash
# 1. Provision new Hetzner CX22 (Ubuntu 24.04)
# 2. SSH in as root, set up base
adduser deploy && usermod -aG sudo deploy
mkdir -p /home/deploy/.ssh
# (paste your public key into /home/deploy/.ssh/authorized_keys)
chown -R deploy:deploy /home/deploy/.ssh && chmod 600 /home/deploy/.ssh/authorized_keys

# 3. Install Docker + firewall
curl -fsSL https://get.docker.com | sh
apt install -y docker-compose-plugin ufw rclone
usermod -aG docker deploy
ufw allow 22 && ufw allow 80 && ufw allow 443 && ufw --force enable

# 4. As deploy user
su - deploy
mkdir -p /opt/inventory && cd /opt/inventory
git clone https://github.com/<you>/inventory-keeper.git .

# 5. Configure rclone for B2 (one-time, use the same remote name as in your backup script)
rclone config   # interactive, set up "b2" remote

# 6. Restore config + bot session from B2
rclone copy b2:inventory-backups/config-LATEST.tar.gz /tmp/
rclone copy b2:inventory-backups/wa-LATEST.tar.gz /tmp/
tar xzf /tmp/config-LATEST.tar.gz -C /
tar xzf /tmp/wa-LATEST.tar.gz -C /

# 7. Start everything
docker compose up -d --build

# 8. Update DNS at Cloudflare → point to new IP
# 9. Verify https://yourdomain.com loads
```

**No webhook changes needed** because Twilio/VAPI/WhatsApp point at your *domain*, not the IP.

---

## Scenario D — Hetzner won't give you a new VM (capacity rationing)

This is the scenario from the 2026-04-28 capacity notice. You need a new VM but Hetzner is saying "no."

### D1. First, try other regions
Hetzner capacity is per-location. Try in this order:
1. **Helsinki (Finland)** — usually most available
2. **Ashburn (US East)** — added 2025, often has capacity
3. **Hillsboro (US West)** — same
4. **Singapore** — newer, may have room
5. Falkenstein / Nuremberg (Germany) — usually most constrained
6. Try a different VM size (CX32 instead of CX22) — sometimes one is available when the other isn't

### D2. If all Hetzner regions are full → fail over to backup provider

Have ONE of these accounts pre-created so you can act fast:

| Provider | Equivalent VM | Price | Sign up |
| --- | --- | --- | --- |
| **Netcup VPS 1000 G11** | 2 vCPU, 4GB | ~€4 | netcup.eu (German, similar to Hetzner) |
| **OVH VPS Value** | 2 vCPU, 4GB | ~€6 | ovhcloud.com |
| **DigitalOcean Basic** | 2 vCPU, 4GB | $24 | digitalocean.com (always available, US-focused) |
| **Vultr Cloud Compute** | 2 vCPU, 4GB | $24 | vultr.com |
| **Contabo VPS S** | 4 vCPU, 8GB | ~€5 | contabo.com (cheap, oversold, OK for emergencies) |

**Recommended primary fallback:** DigitalOcean. More expensive but always available, and you can drop back to Hetzner later when capacity returns.

### D3. Failover procedure (any provider)

The Docker-based architecture means failover is the same as Scenario C2:

```bash
# 1. Provision Ubuntu 24.04 VM at fallback provider
# 2. Same steps as C2 (install Docker, clone repo, restore from B2)
# 3. Update Cloudflare DNS → new IP
# 4. Run docker compose up -d --build
```

Total time: ~90 minutes. Cost: a few dollars more per month until you migrate back.

### D4. Migrating back to Hetzner when capacity returns

1. Check Hetzner availability weekly
2. When a region opens up: spin up new CX22
3. Repeat C2 procedure pointing at the new Hetzner IP
4. Update DNS, verify, destroy the fallback VM

---

## Scenario E — Database issues (Railway side)

The DB is on Railway, separate from the VPS. Different failure modes.

### Railway is down
- Check https://status.railway.app
- App will return 500s for any DB query
- **Wait it out** — Railway recovers usually <1 hour
- Nothing to do on your VPS

### Database corruption / accidental data loss
- Railway → your DB → **"Backups"** tab
- Daily automated backups, retained per your plan
- Click **"Restore"** to roll back to a known-good point
- ⚠️ This restores the whole DB, losing changes since the backup

### You ran a bad migration
1. Railway has point-in-time recovery on paid plans — use it
2. Or: connect with `psql $DATABASE_URL`, manually reverse the change
3. Always test migrations on a Railway "fork" of the DB first

### Need to move off Railway entirely
1. `pg_dump $DATABASE_URL > backup.sql` (run from anywhere with the URL)
2. Provision new Postgres (Neon, Supabase Pro, self-hosted, etc.)
3. `psql $NEW_DATABASE_URL < backup.sql`
4. Update `DATABASE_URL` env var on Hetzner, restart containers

---

## Scenario F — Lost WhatsApp bot session

The bot pairs with WhatsApp via QR code, and the auth state is stored in `whatsapp_bot/.wwebjs_auth/baileys/`. If that directory is lost or corrupted, you need to re-pair.

### Symptoms
- Bot logs show repeated "connection closed" or "auth failed"
- WhatsApp messages aren't being received/sent

### Fix
1. SSH in: `docker compose logs whatsapp_bot --tail=100`
2. If you see a QR code in the logs, scan it with WhatsApp on your phone (Linked Devices → Link a Device)
3. Wait ~30 seconds for re-pairing
4. Verify: send a test message to the bot's group

### If the QR doesn't appear
```bash
docker compose stop whatsapp_bot
# nuclear option: wipe auth and re-pair from scratch
rm -rf /opt/inventory/whatsapp_bot/.wwebjs_auth/baileys/*
docker compose up -d whatsapp_bot
docker compose logs -f whatsapp_bot   # watch for QR
```

### If you need to restore from backup
```bash
rclone copy b2:inventory-backups/wa-LATEST.tar.gz /tmp/
docker compose stop whatsapp_bot
tar xzf /tmp/wa-LATEST.tar.gz -C /
docker compose up -d whatsapp_bot
```

---

## Scenario G — Hetzner suspended your account

Rare but it happens. Causes: ToS violation, abuse report, payment failure, random review.

1. **Check email** — Hetzner usually emails first. Look in spam.
2. **Reply to the suspension email** with calm, factual response
3. **Meanwhile, fail over to backup provider** (Scenario D3) — don't wait
4. **Your data is safe** (DB on Railway, code in git, config in B2)
5. Recovery: ~90 min to be running on the fallback provider

---

## Scenario H — Domain expired

You lost the domain. The site is "down" even though everything works.

1. Log in to registrar (Cloudflare Registrar / Namecheap)
2. Renew immediately — usually works within minutes if within grace period
3. **Going forward:** enable auto-renew. Set a calendar reminder for 30 days before expiry.

---

## Day-one setup checklist (do this BEFORE you need recovery)

These items must all be done before you put anything important on Hetzner.

- [ ] Hetzner snapshots enabled, baseline snapshot taken
- [ ] Backblaze B2 bucket created, rclone configured on VPS
- [ ] Nightly backup cron tested (kill the bot session, restore from B2, verify it works)
- [ ] DR fallback provider account created (DigitalOcean / Netcup / OVH)
- [ ] SSH keys backed up to a password manager (NOT just on your laptop)
- [ ] Cloudflare DNS configured, domain auto-renew on
- [ ] UptimeRobot monitoring https://yourdomain.com/healthz every 5 min
- [ ] Email alerts on UptimeRobot going to an email you actually check
- [ ] All env vars saved to a password manager (separate from the server)
- [ ] Railway DB backups verified (download one, check it actually contains data)
- [ ] This RECOVERY.md kept up to date, accessible from your phone (GitHub mobile)
- [ ] You've actually practiced a recovery once — destroy a test VM, rebuild from B2, time it

---

## Useful commands cheat sheet

```bash
# Container status
docker compose ps
docker compose logs -f --tail=100 <service>

# Restart one service
docker compose restart web

# Deploy latest code
cd /opt/inventory && git pull && docker compose up -d --build

# Manually trigger a backup
sudo /etc/cron.daily/backup

# Check disk space
df -h
docker system df       # what's docker using

# Clean up disk
docker system prune -af

# DB shell (from VPS)
docker compose exec web python -c "from app.database import engine; print(engine.url)"
# Or directly:
psql $DATABASE_URL

# Tail nginx-like access logs (Caddy)
docker compose logs -f caddy | grep -v healthz

# Check what's listening
ss -tlnp

# Memory / CPU
free -h
top
```

---

## Phone numbers / human escalation

- Hetzner support (email only, no phone): support@hetzner.com — response 12–48h
- Railway support: via dashboard chat — usually responsive in hours
- Cloudflare support (free tier): community forum
- Twilio support: console.twilio.com → Help (paid plans get faster)

**No paid support exists on the free/cheap tiers of any of these.** Your support is this runbook + Stack Overflow.

---

## Final advice

1. **Practice recovery once before going live.** A runbook you've never used is fiction.
2. **Keep this file up to date.** When your stack changes, update this doc.
3. **Don't panic at 2am.** Almost every scenario here is "annoying" not "catastrophic." Your data is safe on Railway. Your code is safe on GitHub. Everything else is rebuildable in under 2 hours.
4. **The capacity rationing is the most likely "surprise" failure.** Have a DigitalOcean account pre-created so failover is just running the C2 procedure on a different provider.
