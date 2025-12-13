# JustPasted

A small, self-hosted paste & file sharing application (Node.js + Express + SQLite).

[Live Demo](https://justpasted.com) — self-host it and control your data.

## Features
- Instant file & text sharing
- Per-user storage quota (default 1 GB)
- User accounts (email + password)
- Admin UI at `/admin/` (stats, users, blocked IPs, SMTP tests)
- Optional email verification and encrypted stored settings
- Lightweight presence (online user count) via heartbeat

---

## Quick Start

1. Prerequisites

	- Node.js 18+ installed
	- A domain (optional for HTTPS)

2. Clone & install

```bash
git clone https://github.com/lord3nd3r/justpasted.com.git
cd justpasted.com
npm install
```

3. Run (development)

```bash
# run on an unprivileged port (recommended for dev)
HTTP_PORT=3000 node server.js
```

Open http://localhost:3000/ and http://localhost:3000/admin/

---

## Configuration

The project uses `config.js` with sensible defaults and supports environment variables:

- `HTTP_PORT` (default 80)
- `HTTPS_PORT` (default 443)
- `UPLOAD_DIR` (default `uploads`)
- `QUOTA_BYTES` (default 1 GiB)
- `OWNER_EMAIL` (owner address for test mails)
- `EMAIL_VERIFICATION_ENABLED` (set `1` to require email verification)
- `MAIL_HOST`, `MAIL_PORT`, `MAIL_USER`, `MAIL_PASS`, `MAIL_FROM` (SMTP settings)
- `SETTINGS_KEY` (optional AES-GCM key — used to encrypt `MAIL.AUTH_PASS` in DB)

If using Let's Encrypt, provide certs under `/etc/letsencrypt/live/<domain>/`.

---

## Database & migrations

- SQLite database `pastebin.db` lives in the repo root.
- On first run the server creates tables. Migrations are run via `ALTER TABLE` statements (safe to re-run).
- Admin settings live in the `settings` table and may be encrypted when `SETTINGS_KEY` is set.

Wipe local DB (dev only):

```bash
rm -f pastebin.db && rm -rf uploads
```

---

## Admin UI

- Visit `/admin/` when logged in as an admin.
- Features: global config, SMTP probe, blocked IP management, user search, per-user shares, role/ban actions, and stats.

---

## Presence / Online Count

Clients call `/api/ping` periodically (30s) to update their session `last_seen`. The admin `stats` endpoint reports `onlineCount` (sessions with `last_seen` within the last 5 minutes).

To limit DB writes, the server only updates `last_seen` when it is older than 30 seconds.

---

## Running tests

Basic Jest integration tests are included. Run:

```bash
npm test
```

Tests may create and remove `pastebin.db` — run them in an isolated environment.

---

## Deployment notes

- Use a process manager (systemd, PM2) for production.
- Do not run Node as root; use a reverse proxy (nginx) for TLS and privileged ports.
- Set `SETTINGS_KEY` in production to encrypt secrets stored in the DB.

---

