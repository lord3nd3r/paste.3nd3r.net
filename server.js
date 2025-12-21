// ==============================
// Pastebin – Server (with admin, moderation & Sharp)
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
let sharp = null;
try {
  sharp = require('sharp'); // image processing / strip metadata
} catch (e) {
  console.warn('`sharp` module not available — image processing disabled');
}
const nodemailer = require('nodemailer');

const app = express();

// load config from dedicated module
const { CONFIG } = require('./config');

const HTTP_PORT = CONFIG.HTTP_PORT;
const HTTPS_PORT = CONFIG.HTTPS_PORT;

const UPLOAD_DIR = CONFIG.UPLOAD_DIR;
const PUBLIC_DIR = CONFIG.PUBLIC_DIR;

// 1 GB per user
const QUOTA_BYTES = CONFIG.QUOTA_BYTES;

// Owner (hard admin)
const OWNER_EMAIL = CONFIG.OWNER_EMAIL;
if (!CONFIG.SITE_URL) CONFIG.SITE_URL = `http://localhost:${HTTP_PORT}`;

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Database helpers are moved to `db.js`
const { db, initDb, loadAllSettings, setSetting, getSetting } = require('./db');

initDb();
loadAllSettings((err, applied) => {
  if (err) console.warn('Could not load persisted settings at startup');
  else console.log('Loaded persisted admin settings', applied || {});
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

// -----------------------
// Mail helpers (nodemailer)
// -----------------------
const { sendVerificationEmail } = require('./mailer');
// Settings helpers are provided by `db.js` (get/set/loadAllSettings)
// Settings helpers are provided by `db.js` (get/set/loadAllSettings)

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
      // capture and remove session_expires before attaching user
      const sessionLastSeen = row.session_last_seen || row.last_seen || null;
      delete row.session_expires;
      delete row.session_last_seen;
      delete row.last_seen;
      req.user = row;
      // update last_seen only when older than threshold to reduce writes
      try {
        const LAST_SEEN_THRESHOLD = 30 * 1000; // 30 seconds
        if (!sessionLastSeen || (Date.now() - sessionLastSeen) > LAST_SEEN_THRESHOLD) {
          db.run('UPDATE sessions SET last_seen = ? WHERE id = ?', [Date.now(), sid], err => {
            if (err) console.error('Error updating last_seen for session', err);
          });
        }
      } catch (e) {
        console.error('last_seen update failed', e);
      }
      next();
    }
  );
});

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  if (req.user.is_banned) return res.status(403).json({ error: 'Account banned' });
  if (CONFIG.EMAIL_VERIFICATION_ENABLED && !req.user.email_verified) return res.status(403).json({ error: 'Email address not verified' });
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

        if (CONFIG.EMAIL_VERIFICATION_ENABLED) {
          const vcode = crypto.randomBytes(16).toString('hex');
          const vexpires = Date.now() + 24 * 60 * 60 * 1000; // 24h
          db.run('UPDATE users SET email_verified = 0, email_verification_code = ?, email_verification_expires = ? WHERE id = ?', [vcode, vexpires, this.lastID], err3 => {
            if (err3) console.error('Error setting verification code:', err3);
            sendVerificationEmail(this.lastID, eMail, vcode).then(sent => {
              res.json({ ok: true, email: eMail, verificationSent: !!sent });
            }).catch(() => {
              res.json({ ok: true, email: eMail, verificationSent: false });
            });
          });
        } else {
          createSession(this.lastID, res, eMail);
        }
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

    if (CONFIG.EMAIL_VERIFICATION_ENABLED && !user.email_verified) {
      return res.status(403).json({ error: 'Email address not verified. Check your email for a verification link.' });
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

app.get('/api/verify-email', (req, res) => {
  const uid = req.query.uid;
  const code = req.query.code;
  if (!uid || !code) return res.status(400).send('Missing params');

  db.get('SELECT * FROM users WHERE id = ?', [uid], (err, user) => {
    if (err) {
      console.error('Verify lookup error:', err);
      return res.status(500).send('DB error');
    }
    if (!user) return res.status(400).send('Invalid user');

    if (user.email_verified) {
      return res.send('Email already verified');
    }

    if (!user.email_verification_code || String(user.email_verification_code) !== String(code)) {
      return res.status(400).send('Invalid verification code');
    }

    if (user.email_verification_expires && user.email_verification_expires <= Date.now()) {
      return res.status(400).send('Verification code expired');
    }

    db.run('UPDATE users SET email_verified = 1, email_verification_code = NULL, email_verification_expires = NULL WHERE id = ?', [uid], err2 => {
      if (err2) console.error('Error marking email verified:', err2);
      // Create session after verification
      createSession(uid, res, user.email);
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
// ADMIN CONFIG API
// ---------------------------------------------------------------------------

// Public config endpoint (lightweight) for frontend branding
app.get('/api/config', (req, res) => {
  res.json({ SITE_NAME: CONFIG.SITE_NAME || 'JustPasted' });
});

// Register admin routes from separate module
const registerAdminRoutes = require('./adminRoutes');
registerAdminRoutes(app, { requireAdmin, CONFIG, setSetting });

// ---------------------------------------------------------------------------
// UPLOAD FILE  (with Sharp to strip image metadata)
// ---------------------------------------------------------------------------

app.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });

  try {
    // If it's an image, re-encode via Sharp to strip metadata
    const ext = path.extname(req.file.originalname || '').toLowerCase();
    const imgExts = ['.png', '.jpg', '.jpeg', '.webp', '.avif'];
    if (imgExts.includes(ext)) {
      try {
        // Re-encode to strip metadata and normalize format
        let pipeline = sharp(req.file.path, { failOnError: false });

        if (ext === '.png') {
          pipeline = pipeline.png();
          req.file.mimetype = 'image/png';
        } else if (ext === '.webp') {
          pipeline = pipeline.webp();
          req.file.mimetype = 'image/webp';
        } else if (ext === '.avif') {
          pipeline = pipeline.avif();
          req.file.mimetype = 'image/avif';
        } else {
          // jpg / jpeg / other -> jpeg
          pipeline = pipeline.jpeg();
          req.file.mimetype = 'image/jpeg';
        }

        const buffer = await pipeline.toBuffer();
        fs.writeFileSync(req.file.path, buffer);

        // Generate resized and thumbnail variants to improve display of large images
        try {
          const id = path.basename(req.file.filename, path.extname(req.file.filename));
          const resizedFilename = id + '-resized' + ext;
          const thumbFilename = id + '-thumb' + ext;
          const resizedPath = path.join(UPLOAD_DIR, resizedFilename);
          const thumbPath = path.join(UPLOAD_DIR, thumbFilename);

          // Resize parameters: do not upscale if image is smaller
          const RESIZED_MAX_WIDTH = 1200;
          const THUMB_MAX_WIDTH = 400;

          await sharp(req.file.path, { failOnError: false })
            .resize({ width: RESIZED_MAX_WIDTH, withoutEnlargement: true })
            .toFile(resizedPath);

          await sharp(req.file.path, { failOnError: false })
            .resize({ width: THUMB_MAX_WIDTH, withoutEnlargement: true })
            .toFile(thumbPath);

          // Attach generated filenames to request for DB insert
          req.file.resizedFilename = resizedFilename;
          req.file.thumbFilename = thumbFilename;
        } catch (genErr) {
          console.error('Error generating resized/thumb variants:', genErr);
        }
      } catch (imgErr) {
        console.error('Sharp processing error (continuing with original file):', imgErr);
      }
    }

    const stat = fs.statSync(req.file.path);
    const newFileSize = stat.size;
    const expiryCode = req.body && req.body.expiry;
    const expiresAt = computeExpiry(expiryCode);

    // Enforce quota AFTER any re-encoding
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
        const resized = req.file.resizedFilename || null;
        const thumb = req.file.thumbFilename || null;

        db.run(
          `INSERT INTO files (id, filename, original_name, size, mime, created, user_id, views, expires, resized_filename, thumb_filename)
           VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
          [
            id,
            req.file.filename,
            shortOriginal,
            newFileSize,
            req.file.mimetype,
            Date.now(),
            req.user.id,
            expiresAt,
            resized,
            thumb
          ],
          err2 => {
            if (err2) {
              console.error('File DB error:', err2);
              fs.unlink(req.file.path, () => {});
              return res.status(500).json({ error: 'DB save error' });
            }
            res.json({ url: `${req.protocol}://${req.get('host')}/f/${id}` });
          }
        );
      }
    );
  } catch (err) {
    console.error('Upload handler error:', err);
    if (req.file && req.file.path) {
      fs.unlink(req.file.path, () => {});
    }
    res.status(500).json({ error: 'Server error' });
  }
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
        res.json({ url: `${req.protocol}://${req.get('host')}/p/${id}` });
      }
    );
  }
);

// ---------------------------------------------------------------------------
// RAW FILE SERVE (for internal use / iframes if needed)
// ---------------------------------------------------------------------------

app.get('/raw/file/:id', (req, res) => {
  const id = req.params.id;
  const now = Date.now();

  db.get(
    'SELECT * FROM files WHERE id = ? AND (expires IS NULL OR expires > ?)',
    [id, now],
    (err, file) => {
      if (err) {
        console.error('Raw file query error:', err);
        return res.status(500).send('Server error');
      }
      if (!file) return res.status(404).send('Not found');

      const fp = path.join(UPLOAD_DIR, file.filename);
      if (!fs.existsSync(fp)) return res.status(404).send('Not found');

      res.sendFile(fp);
    }
  );
});

// ---------------------------------------------------------------------------
// VIEW FILE (with simple chrome and report link placeholder)
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

      const title = e(file.original_name || 'File');
      const fileUrl = `/raw/file/${encodeURIComponent(id)}`;
      // Prefer served resized variant for viewing if available
      const viewerSrc = file.resized_filename ? `/uploads/${encodeURIComponent(file.resized_filename)}` : fileUrl;

      // Simple frame chrome with header/footer and main viewer
      res.send(`<!DOCTYPE html>
<html data-theme="dark">
<head>
  <meta charset="utf-8">
  <title>${title} - JustPasted</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { margin:0; font-family:system-ui,-apple-system,sans-serif; background:#020617; color:#e5e7eb; display:flex; flex-direction:column; min-height:100vh; }
    header, footer { padding:0.75rem 1rem; background:#0f172a; border-bottom:1px solid #111827; display:flex; align-items:center; justify-content:space-between; }
    footer { border-top:1px solid #111827; border-bottom:none; margin-top:auto; font-size:0.85rem; color:#9ca3af; }
    a { color:#38bdf8; text-decoration:none; }
    a:hover { text-decoration:underline; }
    .brand { font-weight:600; }
    .main { flex:1 1 auto; background:#020617; display:flex; align-items:center; justify-content:center; padding:1rem; }
    .frame { width:100%; height:100%; max-width:1200px; max-height:100vh; display:flex; align-items:center; justify-content:center; }
    img { max-width:100%; max-height:100%; }
    .download-link { margin-left:1rem; font-size:0.9rem; }
    .button { border-radius:999px; border:1px solid #374151; padding:0.25rem 0.75rem; font-size:0.85rem; background:transparent; color:#e5e7eb; cursor:pointer; }
    .button:hover { background:#111827; }
  </style>
</head>
<body>
  <header>
    <div>
      <span class="brand"><a href="/">JustPasted</a></span>
      <span style="margin-left:0.75rem; font-size:0.9rem; color:#9ca3af;">${title}</span>
    </div>
    <div>
      <a href="${fileUrl}" class="download-link" download>Download</a>
    </div>
  </header>
  <div class="main">
    <div class="frame">
      {
        ['.png','.jpg','.jpeg','.gif','.webp','.bmp','.svg','.avif']
          .includes(path.extname(file.filename).toLowerCase())
          ? (`<div style="display:flex;flex-direction:column;align-items:center;gap:0.6rem;">
                <img id="viewerImg" src="${viewerSrc}" alt="${title}">
                <div>
                  <a href="${fileUrl}" class="download-link" download>Download</a>
                  <button class="button" id="toggleFullBtn">Full size</button>
                </div>
             </div>`)
          : `<iframe src="${fileUrl}" style="width:100%;height:80vh;border:none;background:#020617;"></iframe>`
      }
    </div>
  </div>
  <footer>
    <div>© ${new Date().getFullYear()} 3nd3r.net</div>
    <div>
      <!-- Placeholder for report; front-end can POST /api/report if you want to wire it -->
      <span style="opacity:0.8;">Report: include this ID to admin &mdash; ${e(id)}</span>
    </div>
  </footer>
</body>
</html>`);
    }
  );
});

// ---------------------------------------------------------------------------
// VIEW PASTE
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
    body { font-family:system-ui,-apple-system,sans-serif; background:#020617; color:#e5e7eb; margin:0; display:flex; flex-direction:column; min-height:100vh; }
    header, footer { padding:0.75rem 1rem; background:#0f172a; border-bottom:1px solid #111827; display:flex; align-items:center; justify-content:space-between; }
    footer { border-top:1px solid #111827; border-bottom:none; margin-top:auto; font-size:0.85rem; color:#9ca3af; }
    a { color:#38bdf8; text-decoration:none; }
    a:hover { text-decoration:underline; }
    .brand { font-weight:600; }
    main { flex:1 1 auto; padding:2rem; }
    h1 { margin:0 0 1.5rem; font-size:1.4rem; }
    pre { background:#0f172a; padding:1.5rem; border-radius:1rem; overflow:auto; white-space:pre; }
    @media (max-width:768px){
      main { padding:1.5rem 1rem; }
      pre { padding:1.2rem; }
    }
  </style>
</head>
<body>
  <header>
  (function(){
    const btn = document.getElementById('toggleFullBtn');
    const img = document.getElementById('viewerImg');
    if (btn && img) {
      let showingFull = false;
      const resizedSrc = img.getAttribute('src');
      const originalSrc = '${fileUrl}';
      btn.addEventListener('click', function(){
        if (!showingFull) {
          img.setAttribute('src', originalSrc);
          btn.textContent = 'Show scaled';
        } else {
          img.setAttribute('src', resizedSrc);
          btn.textContent = 'Full size';
        }
        showingFull = !showingFull;
      });
    }
  })();
    <div>
      <span class="brand"><a href="/">JustPasted</a></span>
    </div>
    <div style="font-size:0.85rem;color:#9ca3af;">Paste ID: ${e(id)}</div>
  </header>
  <main>
    <h1>${title}</h1>
    <pre><code>${e(paste.content)}</code></pre>
    <p style="margin-top:1.5rem"><a href="/">Home</a></p>
  </main>
  <footer>
    <div>© ${new Date().getFullYear()} 3nd3r.net</div>
    <div><span style="opacity:0.8;">Report this ID to admin: ${e(id)}</span></div>
  </footer>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <script>hljs.highlightAll();</script>
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
  "SELECT id, filename, mime, original_name AS title, 'file' AS type, created, size, views, expires FROM files WHERE user_id = ? AND (expires IS NULL OR expires > ?)",
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
// DELETE SHARE (user or admin)
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
        res.json({ ok: true });
      });
    });
  } else {
    res.status(400).json({ error: 'Invalid type' });
  }
});

// ---------------------------------------------------------------------------
// REPORTING (backend only; UI can call this later)
// ---------------------------------------------------------------------------

// Create a report
app.post('/api/report', (req, res) => {
  const { targetType, targetId, reason } = req.body || {};
  const cleanType = String(targetType || '').toLowerCase();
  const cleanId = String(targetId || '').trim();
  const cleanReason = String(reason || '').trim().slice(0, 1000);

  if (!['file', 'paste'].includes(cleanType)) {
    return res.status(400).json({ error: 'Invalid target type' });
  }
  if (!cleanId) {
    return res.status(400).json({ error: 'Missing target id' });
  }

  const reporterUserId = req.user ? req.user.id : null;
  const reporterIp = req.ip;
  const created = Date.now();

  db.run(
    `INSERT INTO reports (target_type, target_id, reason, status, created, reporter_user_id, reporter_ip)
     VALUES (?, ?, ?, 'open', ?, ?, ?)`,
    [cleanType, cleanId, cleanReason, created, reporterUserId, reporterIp],
    function (err) {
      if (err) {
        console.error('Report insert error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json({ ok: true, id: this.lastID });
    }
  );
});

// Admin: list reports
app.get('/api/admin/reports', requireAdmin, (req, res) => {
  const status = String(req.query.status || 'open').toLowerCase();
  const where = status === 'all' ? '' : 'WHERE status = ?';
  const params = status === 'all' ? [] : ['open'];

  db.all(
    `SELECT * FROM reports ${where} ORDER BY created DESC LIMIT 500`,
    params,
    (err, rows) => {
      if (err) {
        console.error('Admin reports list error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json(rows);
    }
  );
});

// Admin: resolve report
app.post('/api/admin/report/:id/resolve', requireAdmin, (req, res) => {
  const id = Number(req.params.id || 0);
  if (!id) return res.status(400).json({ error: 'Invalid report id' });

  db.run(
    'UPDATE reports SET status = ? WHERE id = ?',
    ['resolved', id],
    function (err) {
      if (err) {
        console.error('Admin resolve report error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (this.changes === 0) return res.status(404).json({ error: 'Report not found' });
      res.json({ ok: true });
    }
  );
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

        db.get("SELECT COUNT(*) AS blockedCount FROM blocked_ips", [], (err4, row4) => {
          if (err4) {
            console.error('Admin stats blocked error:', err4);
            return res.status(500).json({ error: 'DB error' });
          }
          out.blockedIps = row4.blockedCount;

          db.get("SELECT COUNT(*) AS openReports FROM reports WHERE status = 'open'", [], (err5, row5) => {
            if (err5) {
              console.error('Admin stats reports error:', err5);
              return res.status(500).json({ error: 'DB error' });
            }
            out.openReports = row5.openReports;
            // admin count
            db.get("SELECT COUNT(*) AS adminCount FROM users WHERE role = 'admin'", [], (err6, row6) => {
              if (err6) {
                console.error('Admin stats adminCount error:', err6);
                return res.status(500).json({ error: 'DB error' });
              }
              out.adminCount = row6.adminCount || 0;

              // online count: sessions with last_seen in the recent window (5 minutes)
              const windowMs = 5 * 60 * 1000;
              const cutoff = Date.now() - windowMs;
              db.get('SELECT COUNT(*) AS onlineCount FROM sessions WHERE last_seen IS NOT NULL AND last_seen >= ?', [cutoff], (err7, row7) => {
                if (err7) {
                  console.error('Admin stats onlineCount error:', err7);
                  return res.status(500).json({ error: 'DB error' });
                }
                out.onlineCount = row7 ? row7.onlineCount : 0;
                res.json(out);
              });
            });
          });
        });
      });
    });
  });
});

// Existing user search (filtered)
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  const like = `%${q}%`;

  db.all(
    'SELECT id, email, created, role, is_banned, email_verified FROM users WHERE LOWER(email) LIKE ? OR CAST(id AS TEXT) = ? ORDER BY created DESC LIMIT 100',
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

// NEW: list all users (for admin panel "all registered users")
app.get('/api/admin/users-all', requireAdmin, (req, res) => {
  db.all(
    'SELECT id, email, created, role, is_banned, email_verified FROM users ORDER BY created DESC',
    [],
    (err, rows) => {
      if (err) {
        console.error('Admin users-all error:', err);
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

app.post('/api/admin/user/verify', requireAdmin, (req, res) => {
  const { userId, verified } = req.body || {};
  if (!userId || typeof verified !== 'boolean') {
    return res.status(400).json({ error: 'Invalid payload' });
  }

  db.run(
    'UPDATE users SET email_verified = ? WHERE id = ?',
    [verified ? 1 : 0, userId],
    function (err) {
      if (err) {
        console.error('Admin verify user error:', err);
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
    `SELECT files.id, files.original_name AS title, files.size, files.mime, files.created, files.user_id,
            files.views, files.expires, users.email AS user_email
     FROM files
     LEFT JOIN users ON users.id = files.user_id
     WHERE files.id = ?`,
    [id],
    (err, file) => {
      if (err) {
        console.error('Admin share file lookup error:', err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (file) return res.json({ type: 'file', share: file });

      db.get(
        `SELECT pastes.id, pastes.title, pastes.created, pastes.user_id,
                pastes.views, pastes.expires, users.email AS user_email
         FROM pastes
         LEFT JOIN users ON users.id = pastes.user_id
         WHERE pastes.id = ?`,
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
// SPA FALLBACK
// ---------------------------------------------------------------------------

app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// Heartbeat endpoint: called by clients to mark session as active
app.post('/api/ping', (req, res) => {
  const sid = req.cookies && req.cookies.session_id;
  if (!sid || !req.user) return res.json({ ok: false });
  try {
    const LAST_SEEN_THRESHOLD = 30 * 1000; // 30s
    db.get('SELECT last_seen FROM sessions WHERE id = ?', [sid], (err, row) => {
      if (err) {
        console.error('Ping select error:', err);
        return res.json({ ok: false });
      }
      const now = Date.now();
      const last = row && row.last_seen ? row.last_seen : null;
      if (!last || (now - last) > LAST_SEEN_THRESHOLD) {
        db.run('UPDATE sessions SET last_seen = ? WHERE id = ?', [now, sid], err2 => {
          if (err2) console.error('Ping update error:', err2);
          return res.json({ ok: true });
        });
      } else {
        return res.json({ ok: true });
      }
    });
  } catch (e) {
    console.error('Ping handler failed', e);
    res.json({ ok: false });
  }
});

// ---------------------------------------------------------------------------
// HTTPS SERVER
// ---------------------------------------------------------------------------

// Determine domain used for Let's Encrypt certs. Prefer env var, then SITE_URL, then fallback.
let domain = process.env.LETSENCRYPT_DOMAIN || null;
if (!domain && CONFIG.SITE_URL) {
  try {
    const u = new URL(CONFIG.SITE_URL);
    domain = u.hostname;
  } catch (e) {
    // ignore
  }
}
  if (!domain) domain = 'justpasted.com';

let httpsOptions = null;
try {
  httpsOptions = {
    key: fs.readFileSync(`/etc/letsencrypt/live/${domain}/privkey.pem`),
    cert: fs.readFileSync(`/etc/letsencrypt/live/${domain}/fullchain.pem`)
  };
} catch (err) {
  console.warn(`Could not load HTTPS certs for ${domain}, running HTTP-only:`, err.message);
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
