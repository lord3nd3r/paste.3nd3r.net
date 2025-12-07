// ==============================
//  Pastebin – Server (admin, moderation, frame viewer & reports)
// ==============================

const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');

const app = express();

const HTTP_PORT = 80;
const HTTPS_PORT = 443;

const UPLOAD_DIR = path.join(__dirname, 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');

// 1 GB per user
const QUOTA_BYTES = 1024 * 1024 * 1024;

// Owner (hard admin)
const OWNER_EMAIL = 'lord3nd3r@gmail.com';

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// DATABASE
// ---------------------------------------------------------------------------

const db = new sqlite3.Database(path.join(__dirname, 'pastebin.db'));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password_hash TEXT,
      created INTEGER,
      role TEXT DEFAULT 'user',
      is_banned INTEGER DEFAULT 0,
      created_ip TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER,
      created INTEGER,
      expires INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      filename TEXT,
      original_name TEXT,
      size INTEGER,
      mime TEXT,
      created INTEGER,
      user_id INTEGER,
      views INTEGER DEFAULT 0,
      expires INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS pastes (
      id TEXT PRIMARY KEY,
      content TEXT,
      title TEXT,
      created INTEGER,
      user_id INTEGER,
      views INTEGER DEFAULT 0,
      expires INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS blocked_ips (
      ip TEXT PRIMARY KEY,
      reason TEXT,
      created INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT,
      share_id TEXT,
      reporter_user_id INTEGER,
      reporter_ip TEXT,
      reason TEXT,
      created INTEGER,
      status TEXT DEFAULT 'open',
      admin_note TEXT
  )`);

  // Legacy migrations if old DBs exist
  db.run(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'`, err => {
    if (err && !/duplicate column/i.test(err.message || '')) {
      console.error('Error adding users.role column:', err);
    }
  });
  db.run(`ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0`, err => {
    if (err && !/duplicate column/i.test(err.message || '')) {
      console.error('Error adding users.is_banned column:', err);
    }
  });
  db.run(`ALTER TABLE users ADD COLUMN created_ip TEXT`, err => {
    if (err && !/duplicate column/i.test(err.message || '')) {
      console.error('Error adding users.created_ip column:', err);
    }
  });
  db.run(`ALTER TABLE files ADD COLUMN views INTEGER DEFAULT 0`, err => {
    if (err && !/duplicate column/i.test(err.message || '')) {
      console.error('Error adding files.views column:', err);
    }
  });
  db.run(`ALTER TABLE pastes ADD COLUMN views INTEGER DEFAULT 0`, err => {
    if (err && !/duplicate column/i.test(err.message || '')) {
      console.error('Error adding pastes.views column:', err);
    }
  });
  db.run(`ALTER TABLE files ADD COLUMN expires INTEGER`, err => {
    if (err && !/duplicate column/i.test(err.message || '')) {
      console.error('Error adding files.expires column:', err);
    }
  });
  db.run(`ALTER TABLE pastes ADD COLUMN expires INTEGER`, err => {
    if (err && !/duplicate column/i.test(err.message || '')) {
      console.error('Error adding pastes.expires column:', err);
    }
  });
  db.run(`ALTER TABLE reports ADD COLUMN status TEXT DEFAULT 'open'`, err => {
    if (err && !/duplicate column/i.test(err.message || '')) {
      console.error('Error adding reports.status column:', err);
    }
  });
  db.run(`ALTER TABLE reports ADD COLUMN admin_note TEXT`, err => {
    if (err && !/duplicate column/i.test(err.message || '')) {
      console.error('Error adding reports.admin_note column:', err);
    }
  });
});

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

function shrinkName10(name) {
  if (!name) return 'file';
  name = path.basename(String(name));
  const ext = path.extname(name);
  const base = path.basename(name, ext);
  const maxBaseLen = Math.max(1, 10 - ext.length);
  return base.slice(0, maxBaseLen) + ext;
}

function e(str) {
  return String(str).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}

function computeExpiry(code) {
  if (!code) return null;
  const now = Date.now();
  switch (code) {
    case '1h': return now + 1 * 60 * 60 * 1000;
    case '1d': return now + 24 * 60 * 60 * 1000;
    case '7d': return now + 7 * 24 * 60 * 60 * 1000;
    case '30d': return now + 30 * 24 * 60 * 60 * 1000;
    default: return null;
  }
}

function cleanupExpired() {
  const now = Date.now();

  db.run('DELETE FROM sessions WHERE expires IS NOT NULL AND expires <= ?', [now], err => {
    if (err) console.error('Error cleaning sessions:', err);
  });

  db.all('SELECT filename FROM files WHERE expires IS NOT NULL AND expires <= ?', [now], (err, rows) => {
    if (err) {
      console.error('Error selecting expired files:', err);
      return;
    }
    rows.forEach(row => {
      fs.unlink(path.join(UPLOAD_DIR, row.filename), unlinkErr => {
        if (unlinkErr && unlinkErr.code !== 'ENOENT') {
          console.error('Error deleting expired file:', unlinkErr);
        }
      });
    });
    db.run('DELETE FROM files WHERE expires IS NOT NULL AND expires <= ?', [now], err2 => {
      if (err2) console.error('Error deleting expired file rows:', err2);
    });
  });

  db.run('DELETE FROM pastes WHERE expires IS NOT NULL AND expires <= ?', [now], err => {
    if (err) console.error('Error deleting expired pastes:', err);
  });
}

setInterval(cleanupExpired, 6 * 60 * 60 * 1000);

function isAdmin(user) {
  if (!user) return false;
  if (user.email === OWNER_EMAIL) return true;
  if (user.role === 'admin' || user.role === 'mod') return true;
  return false;
}

function isValidShareType(t) {
  return t === 'file' || t === 'paste';
}

function isValidReportStatus(s) {
  return s === 'open' || s === 'reviewed' || s === 'dismissed';
}

// ---------------------------------------------------------------------------
// MULTER STORAGE
// ---------------------------------------------------------------------------

const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => {
    const id = crypto.randomBytes(5).toString('hex'); // 10 chars
    const ext = path.extname(file.originalname);
    cb(null, id + ext);
  }
});

const upload = multer({ storage });

// ---------------------------------------------------------------------------
// MIDDLEWARE
// ---------------------------------------------------------------------------

app.use(cookieParser());
app.use(express.json());
app.use(express.static(PUBLIC_DIR));
app.use('/uploads', express.static(UPLOAD_DIR));

// trust proxy for IP
app.set('trust proxy', true);

// Blocked IP middleware
app.use((req, res, next) => {
  const ip = req.ip;
  db.get('SELECT 1 FROM blocked_ips WHERE ip = ?', [ip], (err, row) => {
    if (err) {
      console.error('IP block lookup error:', err);
      return next();
    }
    if (row) {
      return res.status(403).send('Forbidden');
    }
    next();
  });
});

// Session loader
app.use((req, res, next) => {
  const sid = req.cookies.session_id;
  if (!sid) {
    req.user = null;
    return next();
  }

  const now = Date.now();

  db.get(
    `SELECT users.*, sessions.expires AS session_expires
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.id = ?`,
    [sid],
    (err, row) => {
      if (err) {
        console.error('Session lookup error:', err);
        req.user = null;
        return next();
      }

      if (!row) {
        req.user = null;
        return next();
      }

      if (row.session_expires && row.session_expires <= now) {
        db.run('DELETE FROM sessions WHERE id = ?', [sid], err2 => {
          if (err2) console.error('Session cleanup error:', err2);
        });
        req.user = null;
        return next();
      }

      delete row.session_expires;
      req.user = row;
      next();
    }
  );
});

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  if (req.user.is_banned) return res.status(403).json({ error: 'Account banned' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  if (!isAdmin(req.user)) return res.status(403).json({ error: 'Admin only' });
  next();
}

// ---------------------------------------------------------------------------
// AUTH
// ---------------------------------------------------------------------------

function createSession(userId, res, email) {
  const sid = crypto.randomBytes(30).toString('hex');
  const now = Date.now();
  const expires = now + 90 * 86400 * 1000;

  db.run(
    'INSERT INTO sessions (id, user_id, created, expires) VALUES (?, ?, ?, ?)',
    [sid, userId, now, expires],
    err => {
      if (err) {
        console.error('Session insert error:', err);
        return res.status(500).json({ error: 'Session error' });
      }

      const isProd = process.env.NODE_ENV === 'production';

      res.cookie('session_id', sid, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'lax',
        maxAge: 90 * 86400 * 1000
      });

      res.json({ ok: true, email });
    }
  );
}

app.post('/api/register', (req, res) => {
  const { email, password } = req.body || {};
  const eMail = String(email || '').trim().toLowerCase();
  const p = String(password || '');

  if (!eMail || !p) return res.status(400).json({ error: 'Email and password required' });
  if (p.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  bcrypt.hash(p, 10, (err, hash) => {
    if (err) {
      console.error('Hash error:', err);
      return res.status(500).json({ error: 'Hash error' });
    }

    db.run(
      'INSERT INTO users (email, password_hash, created, created_ip) VALUES (?, ?, ?, ?)',
      [eMail, hash, Date.now(), req.ip],
      function (err2) {
        if (err2) {
          if (err2.message && err2.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Email already registered' });
          }
          console.error('User insert error:', err2);
          return res.status(500).json({ error: 'DB error' });
        }

        createSession(this.lastID, res, eMail);
      }
    );
  });
});

app.post('/api/login', (req, res) => {
  const eMail = String(req.body.email || '').trim().toLowerCase();
  const p = String(req.body.password || '');

  if (!eMail || !p) return res.status(400).json({ error: 'Email and password required' });

  db.get('SELECT * FROM users WHERE email = ?', [eMail], (err, user) => {
    if (err) {
      console.error('User lookup error:', err);
      return res.status(500).json({ error: 'DB error' });
    }
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    if (user.is_banned) {
      return res.status(403).json({ error: 'This account has been banned.' });
    }

    bcrypt.compare(p, user.password_hash, (err2, ok) => {
      if (err2) {
        console.error('Compare error:', err2);
        return res.status(500).json({ error: 'Auth error' });
      }
      if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

      createSession(user.id, res, user.email);
    });
  });
});

app.post('/api/logout', (req, res) => {
  const sid = req.cookies.session_id;
  if (sid) {
    db.run('DELETE FROM sessions WHERE id = ?', [sid], err => {
      if (err) console.error('Session delete error:', err);
    });
  }
  res.clearCookie('session_id');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.user) return res.json({ loggedIn: false });
  res.json({
    loggedIn: true,
    email: req.user.email,
    isAdmin: isAdmin(req.user),
    role: req.user.role || 'user'
  });
});

// ---------------------------------------------------------------------------
// UPLOAD FILE
// ---------------------------------------------------------------------------

app.post('/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });

  const newFileSize = req.file.size;
  const expiryCode = req.body && req.body.expiry;
  const expiresAt = computeExpiry(expiryCode);

  db.get(
    'SELECT IFNULL(SUM(size),0) AS used FROM files WHERE user_id = ?',
    [req.user.id],
    (err, row) => {
      if (err) {
        console.error('Usage query error:', err);
        fs.unlink(req.file.path, () => {});
        return res.status(500).json({ error: 'Server error' });
      }

      const currentlyUsed = row ? row.used : 0;
      const projected = currentlyUsed + newFileSize;

      if (projected > QUOTA_BYTES) {
        fs.unlink(req.file.path, () => {});
        return res.status(400).json({ error: 'Storage quota exceeded (1 GB limit)' });
      }

      const id = path.basename(req.file.filename, path.extname(req.file.filename));
      const shortOriginal = shrinkName10(req.file.originalname);

      db.run(
        `INSERT INTO files (id, filename, original_name, size, mime, created, user_id, views, expires)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
        [
          id,
          req.file.filename,
          shortOriginal,
          req.file.size,
          req.file.mimetype,
          Date.now(),
          req.user.id,
          expiresAt
        ],
        err2 => {
          if (err2) {
            console.error('File DB error:', err2);
            fs.unlink(req.file.path, () => {});
            return res.status(500).json({ error: 'DB save error' });
          }
          // Share frame URL
          res.json({ url: `${req.protocol}://${req.get('host')}/view/file/${id}` });
        }
      );
    }
  );
});

// ---------------------------------------------------------------------------
// CREATE PASTE
// ---------------------------------------------------------------------------

app.post(
  '/paste',
  requireAuth,
  express.text({ type: '*/*', limit: '10mb' }),
  (req, res) => {
    const content = (req.body || '').toString().trim();
    if (!content) return res.status(400).json({ error: 'Empty paste' });

    const id = crypto.randomBytes(6).toString('hex');
    const createdAt = Date.now();

    const ts = new Date(createdAt)
      .toISOString()
      .slice(0, 16)
      .replace('T', ' ');

    const title = `Paste ${ts}`;

    const expiryCode = req.query && req.query.expiry;
    const expiresAt = computeExpiry(expiryCode);

    db.run(
      `INSERT INTO pastes (id, content, title, created, user_id, views, expires)
       VALUES (?, ?, ?, ?, ?, 0, ?)`,
      [id, content, title, createdAt, req.user.id, expiresAt],
      err => {
        if (err) {
          console.error('Paste DB error:', err);
          return res.status(500).json({ error: 'DB error' });
        }
        // Share frame URL
        res.json({ url: `${req.protocol}://${req.get('host')}/view/paste/${id}` });
      }
    );
  }
);

// ---------------------------------------------------------------------------
// REPORTS (public create)
// ---------------------------------------------------------------------------

app.post('/api/report', (req, res) => {
  const { type, shareId, reason } = req.body || {};
  const t = String(type || '').toLowerCase();
  const id = String(shareId || '').trim();
  const why = String(reason || '').trim();

  if (!isValidShareType(t)) {
    return res.status(400).json({ error: 'Invalid type' });
  }
  if (!id) {
    return res.status(400).json({ error: 'Missing shareId' });
  }
  if (!why || why.length < 5) {
    return res.status(400).json({ error: 'Reason too short' });
  }

  const now = Date.now();
  const reporterUserId = req.user ? req.user.id : null;
  const reporterIp = req.ip;
  const table = t === 'file' ? 'files' : 'pastes';

  db.get(
    `SELECT id FROM ${table} WHERE id = ? AND (expires IS NULL OR expires > ?)`,
    [id, now],
    (err, row) => {
      if (err) {
        console.error('Report share lookup error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (!row) {
        return res.status(404).json({ error: 'Share not found or expired' });
      }

      db.run(
        `INSERT INTO reports (type, share_id, reporter_user_id, reporter_ip, reason, created, status)
         VALUES (?, ?, ?, ?, ?, ?, 'open')`,
        [t, id, reporterUserId, reporterIp, why, now],
        function (err2) {
          if (err2) {
            console.error('Report insert error:', err2);
            return res.status(500).json({ error: 'DB error' });
          }
          res.json({ ok: true, reportId: this.lastID });
        }
      );
    }
  );
});

// ---------------------------------------------------------------------------
// VIEW FILE (raw)
// ---------------------------------------------------------------------------

app.get('/f/:id', (req, res) => {
  const id = req.params.id;
  const now = Date.now();

  db.get(
    'SELECT * FROM files WHERE id = ? AND (expires IS NULL OR expires > ?)',
    [id, now],
    (err, file) => {
      if (err) {
        console.error('File query error:', err);
        return res.status(500).send('Server error');
      }
      if (!file) return res.status(404).send('Not found');

      db.run('UPDATE files SET views = views + 1 WHERE id = ?', [id], err2 => {
        if (err2) console.error('Update views error (file):', err2);
      });

      const fp = path.join(UPLOAD_DIR, file.filename);
      const ext = path.extname(fp).toLowerCase();
      const imgs = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg', '.avif'];

      if (imgs.includes(ext)) res.sendFile(fp);
      else res.download(fp, file.original_name);
    }
  );
});

// ---------------------------------------------------------------------------
// VIEW PASTE (raw viewer, no report UI)
// ---------------------------------------------------------------------------

app.get('/p/:id', (req, res) => {
  const id = req.params.id;
  const now = Date.now();

  db.get(
    'SELECT * FROM pastes WHERE id = ? AND (expires IS NULL OR expires > ?)',
    [id, now],
    (err, paste) => {
      if (err) {
        console.error('Paste query error:', err);
        return res.status(500).send('Server error');
      }
      if (!paste) return res.status(404).send('Not found');

      db.run('UPDATE pastes SET views = views + 1 WHERE id = ?', [id], err2 => {
        if (err2) console.error('Update views error (paste):', err2);
      });

      const title = e(paste.title);

      res.send(`<!DOCTYPE html>
<html data-theme="dark">
<head>
  <meta charset="utf-8">
  <title>${title}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
  <style>
    body { font-family:system-ui,-apple-system,sans-serif; background:#020617; color:#e5e7eb; padding:2rem; margin:0; }
    h1 { margin:0 0 1.5rem; font-size:1.4rem; }
    pre { background:#0f172a; padding:1.5rem; border-radius:1rem; overflow:auto; white-space:pre; }
    a { color:#38bdf8; }
    @media (max-width:768px){
      body { padding:1.5rem 1rem; }
      pre { padding:1.2rem; }
    }
  </style>
</head>
<body>
  <h1>${title}</h1>
  <pre><code>${e(paste.content)}</code></pre>
  <p style="margin-top:1.5rem"><a href="/">Home</a></p>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <script>hljs.highlightAll();</script>
</body>
</html>`);
    }
  );
});

// ---------------------------------------------------------------------------
// FRAME VIEWER /view/:type/:id
// ---------------------------------------------------------------------------

app.get('/view/:type/:id', (req, res) => {
  const tRaw = req.params.type;
  const t = tRaw === 'file' ? 'file' : 'paste';
  const id = req.params.id;
  const now = Date.now();

  const table = t === 'file' ? 'files' : 'pastes';

  db.get(
    `SELECT * FROM ${table} WHERE id = ? AND (expires IS NULL OR expires > ?)`,
    [id, now],
    (err, row) => {
      if (err) {
        console.error('View wrapper lookup error:', err);
        return res.status(500).send('Server error');
      }
      if (!row) return res.status(404).send('Not found');

      const homeUrl = '/';
      const rawUrl = t === 'file' ? `/f/${id}` : `/p/${id}`;
      const title = t === 'file'
        ? (row.original_name || `File ${id}`)
        : (row.title || `Paste ${id}`);

      res.send(`<!doctype html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8" />
  <title>${e(title)} – Pastebin</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    html, body {
      margin:0; padding:0;
      height:100%; width:100%;
      font-family:system-ui,-apple-system,sans-serif;
      background:#020617;
      color:#e5e7eb;
    }
    .frame-root {
      display:flex;
      flex-direction:column;
      height:100vh;
    }
    .frame-top {
      padding:0.6rem 1rem;
      border-bottom:1px solid #1f2937;
      background:#020617;
      display:flex;
      justify-content:space-between;
      align-items:center;
      font-size:0.9rem;
    }
    .frame-brand {
      display:flex;
      align-items:center;
      gap:0.5rem;
      font-weight:600;
    }
    .frame-logo {
      width:26px; height:26px;
      border-radius:999px;
      background:radial-gradient(circle at 30% 30%, #38bdf8, #0f172a);
      display:grid; place-items:center;
      font-size:0.8rem;
    }
    .frame-top a {
      color:#38bdf8;
      text-decoration:none;
      font-size:0.85rem;
    }
    .frame-main {
      flex:1 1 auto;
      background:#020617;
    }
    .frame-main iframe {
      border:none;
      width:100%;
      height:100%;
    }
    .frame-bottom {
      padding:0.4rem 0.9rem;
      border-top:1px solid #1f2937;
      background:#020617;
      font-size:0.8rem;
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:0.5rem;
      flex-wrap:wrap;
    }
    .frame-bottom-left {
      display:flex;
      gap:0.5rem;
      align-items:center;
      flex-wrap:wrap;
    }
    .btn-report {
      padding:0.2rem 0.7rem;
      border-radius:999px;
      border:1px solid #f97373;
      background:transparent;
      color:#fecaca;
      font-size:0.75rem;
      cursor:pointer;
    }
    .btn-report:hover { background:rgba(248,113,113,0.1); }
    .frame-link {
      color:#64748b;
      font-size:0.75rem;
    }
    .frame-link a { color:#9ca3af; text-decoration:none; }
    .frame-link a:hover { text-decoration:underline; }

    .report-popup {
      position:fixed;
      inset:0;
      background:rgba(15,23,42,0.85);
      display:none;
      align-items:center;
      justify-content:center;
      z-index:50;
    }
    .report-dialog {
      background:#020617;
      border-radius:0.9rem;
      padding:1rem 1.2rem;
      border:1px solid #1f2937;
      max-width:420px;
      width:100%;
      box-shadow:0 20px 40px rgba(0,0,0,.6);
    }
    .report-dialog h2 {
      margin:0 0 0.5rem;
      font-size:1rem;
    }
    .report-dialog textarea {
      width:100%;
      min-height:80px;
      resize:vertical;
      padding:0.5rem 0.6rem;
      border-radius:0.6rem;
      border:1px solid #374151;
      background:#020617;
      color:#e5e7eb;
      font-size:0.85rem;
      box-sizing:border-box;
    }
    .report-dialog-actions {
      margin-top:0.7rem;
      display:flex;
      justify-content:flex-end;
      gap:0.5rem;
    }
    .btn {
      border-radius:999px;
      padding:0.3rem 0.9rem;
      font-size:0.8rem;
      border:none;
      cursor:pointer;
    }
    .btn-cancel {
      background:transparent;
      color:#9ca3af;
      border:1px solid #374151;
    }
    .btn-submit {
      background:#f97373;
      color:white;
    }
    .report-status {
      margin-top:0.4rem;
      font-size:0.8rem;
      min-height:1em;
    }
    @media (max-width:768px){
      .frame-top, .frame-bottom {
        padding:0.5rem 0.7rem;
      }
    }
  </style>
</head>
<body>
  <div class="frame-root">
    <div class="frame-top">
      <div class="frame-brand">
        <div class="frame-logo">P</div>
        <div>Pastebin</div>
      </div>
      <div>
        <a href="${homeUrl}" target="_top">Go to homepage</a>
      </div>
    </div>

    <div class="frame-main">
      <iframe src="${rawUrl}" loading="lazy" referrerpolicy="no-referrer"></iframe>
    </div>

    <div class="frame-bottom">
      <div class="frame-bottom-left">
        <button class="btn-report" id="reportBtn">Report</button>
        <span class="frame-link">
          <a href="${rawUrl}" target="_blank" rel="noopener">Open raw</a>
        </span>
      </div>
      <div>&copy; ${new Date().getFullYear()} 3nd3r.net</div>
    </div>
  </div>

  <div class="report-popup" id="reportPopup">
    <div class="report-dialog">
      <h2>Report this ${t}</h2>
      <p style="font-size:0.8rem;color:#9ca3af;margin:0 0 0.4rem;">
        If this content is abusive or illegal, briefly describe the issue. Your IP may be logged.
      </p>
      <textarea id="reportReason" placeholder="Describe the problem (required, min 5 characters)"></textarea>
      <div class="report-dialog-actions">
        <button class="btn btn-cancel" id="reportCancel">Cancel</button>
        <button class="btn btn-submit" id="reportSubmit">Submit</button>
      </div>
      <div class="report-status" id="reportStatus"></div>
    </div>
  </div>

  <script>
    (function () {
      const popup = document.getElementById('reportPopup');
      const btn = document.getElementById('reportBtn');
      const cancel = document.getElementById('reportCancel');
      const submit = document.getElementById('reportSubmit');
      const reasonEl = document.getElementById('reportReason');
      const statusEl = document.getElementById('reportStatus');

      if (!popup || !btn || !cancel || !submit || !reasonEl || !statusEl) return;

      btn.addEventListener('click', () => {
        popup.style.display = 'flex';
        statusEl.textContent = '';
        reasonEl.value = '';
      });

      cancel.addEventListener('click', () => {
        popup.style.display = 'none';
      });

      popup.addEventListener('click', (e) => {
        if (e.target === popup) popup.style.display = 'none';
      });

      submit.addEventListener('click', () => {
        const reason = reasonEl.value.trim();
        if (reason.length < 5) {
          statusEl.textContent = 'Please provide at least 5 characters.';
          statusEl.style.color = '#fecaca';
          return;
        }
        statusEl.textContent = 'Sending report…';
        statusEl.style.color = '#9ca3af';

        fetch('/api/report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: '${t}',
            shareId: '${e(id)}',
            reason
          })
        }).then(r => r.json())
        .then(data => {
          if (data && data.ok) {
            statusEl.textContent = 'Thank you. Your report has been submitted.';
            statusEl.style.color = '#4ade80';
          } else {
            statusEl.textContent = 'Error submitting report: ' + (data && data.error || 'unknown');
            statusEl.style.color = '#fecaca';
          }
        })
        .catch(err => {
          console.error('Report submit error:', err);
          statusEl.textContent = 'Error submitting report.';
          statusEl.style.color = '#fecaca';
        });
      });
    })();
  </script>
</body>
</html>`);
    }
  );
});

// ---------------------------------------------------------------------------
// USER DASHBOARD
// ---------------------------------------------------------------------------

app.get('/api/shares', requireAuth, (req, res) => {
  const all = [];
  const now = Date.now();

  db.all(
    "SELECT id, original_name AS title, 'file' AS type, created, size, views, expires FROM files WHERE user_id = ? AND (expires IS NULL OR expires > ?)",
    [req.user.id, now],
    (err, files) => {
      if (err) {
        console.error('Files list error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (files) all.push(...files);

      db.all(
        "SELECT id, title, 'paste' AS type, created, NULL AS size, views, expires FROM pastes WHERE user_id = ? AND (expires IS NULL OR expires > ?)",
        [req.user.id, now],
        (err2, pastes) => {
          if (err2) {
            console.error('Pastes list error:', err2);
            return res.status(500).json({ error: 'DB error' });
          }
          if (pastes) all.push(...pastes);

          all.sort((a, b) => b.created - a.created);
          res.json(all);
        }
      );
    }
  );
});

// ---------------------------------------------------------------------------
// USAGE STATS
// ---------------------------------------------------------------------------

app.get('/api/usage', requireAuth, (req, res) => {
  const now = Date.now();
  db.get(
    'SELECT COUNT(*) AS fileCount, IFNULL(SUM(size),0) AS totalSize FROM files WHERE user_id = ? AND (expires IS NULL OR expires > ?)',
    [req.user.id, now],
    (err, row) => {
      if (err) {
        console.error('Usage stats error:', err);
        return res.status(500).json({ error: 'DB error' });
      }

      const fileCount = row ? row.fileCount : 0;
      const usedBytes = row ? row.totalSize : 0;
      const quotaBytes = QUOTA_BYTES;
      const remainingBytes = Math.max(0, quotaBytes - usedBytes);

      res.json({
        fileCount,
        usedBytes,
        quotaBytes,
        remainingBytes
      });
    }
  );
});

// ---------------------------------------------------------------------------
// DELETE SHARE (user or admin) + delete associated reports
// ---------------------------------------------------------------------------

app.delete('/api/share/:type/:id', requireAuth, (req, res) => {
  const { type, id } = req.params;
  const admin = isAdmin(req.user);

  if (type === 'file') {
    const params = admin ? [id] : [id, req.user.id];
    const where = admin ? 'id = ?' : 'id = ? AND user_id = ?';

    db.get(`SELECT * FROM files WHERE ${where}`, params, (err, f) => {
      if (err) {
        console.error('File lookup error:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      if (!f) return res.status(404).json({ error: 'Not found' });

      fs.unlink(path.join(UPLOAD_DIR, f.filename), () => {
        db.run('DELETE FROM files WHERE id = ?', [id], err2 => {
          if (err2) {
            console.error('File delete DB error:', err2);
            return res.status(500).json({ error: 'Server error' });
          }
          db.run('DELETE FROM reports WHERE type = ? AND share_id = ?', ['file', id], err3 => {
            if (err3) console.error('Report cleanup error (file):', err3);
          });
          res.json({ ok: true });
        });
      });
    });
  } else if (type === 'paste') {
    const params = admin ? [id] : [id, req.user.id];
    const where = admin ? 'id = ?' : 'id = ? AND user_id = ?';

    db.get(`SELECT * FROM pastes WHERE ${where}`, params, (err, p) => {
      if (err) {
        console.error('Paste lookup error:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      if (!p) return res.status(404).json({ error: 'Not found' });

      db.run('DELETE FROM pastes WHERE id = ?', [id], err2 => {
        if (err2) {
          console.error('Paste delete DB error:', err2);
          return res.status(500).json({ error: 'Server error' });
        }
        db.run('DELETE FROM reports WHERE type = ? AND share_id = ?', ['paste', id], err3 => {
          if (err3) console.error('Report cleanup error (paste):', err3);
        });
        res.json({ ok: true });
      });
    });
  } else {
    res.status(400).json({ error: 'Invalid type' });
  }
});

// ---------------------------------------------------------------------------
// ADMIN ENDPOINTS
// ---------------------------------------------------------------------------

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const out = {};
  db.get('SELECT COUNT(*) AS totalUsers FROM users', [], (err, row) => {
    if (err) {
      console.error('Admin stats users error:', err);
      return res.status(500).json({ error: 'DB error' });
    }
    out.totalUsers = row.totalUsers;

    db.get('SELECT COUNT(*) AS totalFiles, IFNULL(SUM(size),0) AS totalSize FROM files', [], (err2, row2) => {
      if (err2) {
        console.error('Admin stats files error:', err2);
        return res.status(500).json({ error: 'DB error' });
      }
      out.totalFiles = row2.totalFiles;
      out.totalFilesSize = row2.totalSize;

      db.get('SELECT COUNT(*) AS totalPastes FROM pastes', [], (err3, row3) => {
        if (err3) {
          console.error('Admin stats pastes error:', err3);
          return res.status(500).json({ error: 'DB error' });
        }
        out.totalPastes = row3.totalPastes;

        db.get('SELECT COUNT(*) AS blockedCount FROM blocked_ips', [], (err4, row4) => {
          if (err4) {
            console.error('Admin stats blocked error:', err4);
            return res.status(500).json({ error: 'DB error' });
          }
          out.blockedIps = row4.blockedCount;
          res.json(out);
        });
      });
    });
  });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  const like = `%${q}%`;

  db.all(
    'SELECT id, email, created, role, is_banned FROM users WHERE LOWER(email) LIKE ? OR CAST(id AS TEXT) = ? ORDER BY created DESC LIMIT 100',
    [like, q],
    (err, rows) => {
      if (err) {
        console.error('Admin users search error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json(rows);
    }
  );
});

app.post('/api/admin/user/role', requireAdmin, (req, res) => {
  const { userId, role } = req.body || {};
  const allowed = ['user', 'admin', 'mod'];

  if (!userId || !allowed.includes(role)) {
    return res.status(400).json({ error: 'Invalid userId or role' });
  }

  db.run(
    'UPDATE users SET role = ? WHERE id = ?',
    [role, userId],
    function (err) {
      if (err) {
        console.error('Admin set role error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
      res.json({ ok: true });
    }
  );
});

app.post('/api/admin/user/ban', requireAdmin, (req, res) => {
  const { userId, banned } = req.body || {};
  if (!userId || typeof banned !== 'boolean') {
    return res.status(400).json({ error: 'Invalid payload' });
  }

  db.run(
    'UPDATE users SET is_banned = ? WHERE id = ?',
    [banned ? 1 : 0, userId],
    function (err) {
      if (err) {
        console.error('Admin ban user error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
      res.json({ ok: true });
    }
  );
});

app.get('/api/admin/user/:id/shares', requireAdmin, (req, res) => {
  const userId = req.params.id;
  const all = [];

  db.all(
    "SELECT id, original_name AS title, 'file' AS type, created, size, views, expires FROM files WHERE user_id = ?",
    [userId],
    (err, files) => {
      if (err) {
        console.error('Admin user files error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (files) all.push(...files);

      db.all(
        "SELECT id, title, 'paste' AS type, created, NULL AS size, views, expires FROM pastes WHERE user_id = ?",
        [userId],
        (err2, pastes) => {
          if (err2) {
            console.error('Admin user pastes error:', err2);
            return res.status(500).json({ error: 'DB error' });
          }
          if (pastes) all.push(...pastes);

          all.sort((a, b) => b.created - a.created);
          res.json(all);
        }
      );
    }
  );
});

app.get('/api/admin/share/:id', requireAdmin, (req, res) => {
  const id = req.params.id;

  db.get(
    'SELECT id, original_name AS title, size, mime, created, user_id, views, expires FROM files WHERE id = ?',
    [id],
    (err, file) => {
      if (err) {
        console.error('Admin share file lookup error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (file) return res.json({ type: 'file', share: file });

      db.get(
        'SELECT id, title, created, user_id, views, expires FROM pastes WHERE id = ?',
        [id],
        (err2, paste) => {
          if (err2) {
            console.error('Admin share paste lookup error:', err2);
            return res.status(500).json({ error: 'DB error' });
          }
          if (paste) return res.json({ type: 'paste', share: paste });
          res.status(404).json({ error: 'Share not found' });
        }
      );
    }
  );
});

app.get('/api/admin/blocked-ips', requireAdmin, (req, res) => {
  db.all(
    'SELECT ip, reason, created FROM blocked_ips ORDER BY created DESC LIMIT 200',
    [],
    (err, rows) => {
      if (err) {
        console.error('Admin blocked IPs error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json(rows);
    }
  );
});

app.post('/api/admin/blocked-ips', requireAdmin, (req, res) => {
  const { ip, reason } = req.body || {};
  const cleanIp = String(ip || '').trim();
  if (!cleanIp) return res.status(400).json({ error: 'IP required' });

  db.run(
    'INSERT OR REPLACE INTO blocked_ips (ip, reason, created) VALUES (?, ?, ?)',
    [cleanIp, String(reason || ''), Date.now()],
    err => {
      if (err) {
        console.error('Admin add blocked IP error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ ok: true });
    }
  );
});

app.delete('/api/admin/blocked-ips/:ip', requireAdmin, (req, res) => {
  const ip = req.params.ip;
  db.run(
    'DELETE FROM blocked_ips WHERE ip = ?',
    [ip],
    function (err) {
      if (err) {
        console.error('Admin delete blocked IP error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ ok: true });
    }
  );
});

// ---------------------------------------------------------------------------
// ADMIN: REPORTS
// ---------------------------------------------------------------------------

app.get('/api/admin/reports', requireAdmin, (req, res) => {
  const status = String(req.query.status || '').trim().toLowerCase();
  let sql = 'SELECT * FROM reports';
  const params = [];

  if (status && status !== 'all') {
    if (!isValidReportStatus(status)) {
      return res.status(400).json({ error: 'Invalid status filter' });
    }
    sql += ' WHERE status = ?';
    params.push(status);
  }

  sql += ' ORDER BY created DESC LIMIT 500';

  db.all(sql, params, (err, rows) => {
    if (err) {
      console.error('Admin reports list error:', err);
      return res.status(500).json({ error: 'DB error' });
    }
    res.json(rows || []);
  });
});

app.post('/api/admin/reports/:id/update', requireAdmin, (req, res) => {
  const reportId = req.params.id;
  const { status, adminNote } = req.body || {};

  const fields = [];
  const params = [];

  if (typeof status !== 'undefined') {
    const s = String(status || '').toLowerCase();
    if (!isValidReportStatus(s)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    fields.push('status = ?');
    params.push(s);
  }

  if (typeof adminNote !== 'undefined') {
    fields.push('admin_note = ?');
    params.push(String(adminNote || ''));
  }

  if (!fields.length) {
    return res.status(400).json({ error: 'No fields to update' });
  }

  params.push(reportId);

  db.run(
    `UPDATE reports SET ${fields.join(', ')} WHERE id = ?`,
    params,
    function (err) {
      if (err) {
        console.error('Admin report update error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Report not found' });
      }
      res.json({ ok: true });
    }
  );
});

// ---------------------------------------------------------------------------
// SPA FALLBACK
// ---------------------------------------------------------------------------

app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// ---------------------------------------------------------------------------
// HTTPS SERVER
// ---------------------------------------------------------------------------

const domain = 'paste.3nd3r.net';

let httpsOptions = null;
try {
  httpsOptions = {
    key: fs.readFileSync(`/etc/letsencrypt/live/${domain}/privkey.pem`),
    cert: fs.readFileSync(`/etc/letsencrypt/live/${domain}/fullchain.pem`)
  };
} catch (err) {
  console.warn('Could not load HTTPS certs, running HTTP-only:', err.message);
}

http.createServer((req, res) => {
  if (httpsOptions) {
    const host = (req.headers.host || '').replace(/:\d+$/, '');
    res.writeHead(301, { Location: `https://${host}${req.url}` });
    res.end();
  } else {
    app(req, res);
  }
}).listen(HTTP_PORT, () => {
  console.log(`HTTP server on :${HTTP_PORT} (redirecting to HTTPS if configured)`);
});

if (httpsOptions) {
  https.createServer(httpsOptions, app).listen(HTTPS_PORT, () => {
    console.log(`Pastebin LIVE over HTTPS on :${HTTPS_PORT}`);
  });
}
