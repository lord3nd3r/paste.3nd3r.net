// ==============================
//  Pastebin – Full Server Code
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
      created INTEGER
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
      views INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS pastes (
      id TEXT PRIMARY KEY,
      content TEXT,
      title TEXT,
      created INTEGER,
      user_id INTEGER,
      views INTEGER DEFAULT 0
  )`);

  // Patch older DBs that don't have views columns yet
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
});

// ---------------------------------------------------------------------------
// MIDDLEWARE
// ---------------------------------------------------------------------------

const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => {
    const id = crypto.randomBytes(8).toString('hex');
    const ext = path.extname(file.originalname);
    cb(null, id + ext);
  }
});

const upload = multer({ storage });

app.use(cookieParser());
app.use(express.json());
app.use(express.static(PUBLIC_DIR));
app.use('/uploads', express.static(UPLOAD_DIR));

// Load logged-in user via session cookie
app.use((req, res, next) => {
  const sid = req.cookies.session_id;
  if (!sid) {
    req.user = null;
    return next();
  }

  db.get(
    `SELECT users.* FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.id = ?`,
    [sid],
    (err, user) => {
      if (err) {
        console.error('Session lookup error:', err);
        req.user = null;
        return next();
      }
      req.user = user || null;
      next();
    }
  );
});

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Not authenticated" });
  next();
}

// ---------------------------------------------------------------------------
// AUTH HELPERS
// ---------------------------------------------------------------------------

function createSession(userId, res, email) {
  const sid = crypto.randomBytes(30).toString("hex");
  const now = Date.now();
  const expires = now + 90 * 86400 * 1000;

  db.run(
    "INSERT INTO sessions (id, user_id, created, expires) VALUES (?, ?, ?, ?)",
    [sid, userId, now, expires],
    err => {
      if (err) {
        console.error('Session insert error:', err);
        return res.status(500).json({ error: "Session error" });
      }

      res.cookie("session_id", sid, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: 90 * 86400 * 1000
      });

      res.json({ ok: true, email });
    }
  );
}

// ---------------------------------------------------------------------------
// AUTH ROUTES
// ---------------------------------------------------------------------------

app.post('/api/register', (req, res) => {
  const { email, password } = req.body || {};
  const e = String(email || "").trim().toLowerCase();
  const p = String(password || "");

  if (!e || !p) return res.status(400).json({ error: "Email and password required" });
  if (p.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

  bcrypt.hash(p, 10, (err, hash) => {
    if (err) {
      console.error('Hash error:', err);
      return res.status(500).json({ error: "Hash error" });
    }

    db.run(
      "INSERT INTO users (email, password_hash, created) VALUES (?, ?, ?)",
      [e, hash, Date.now()],
      function (err2) {
        if (err2) {
          if (err2.message && err2.message.includes("UNIQUE")) {
            return res.status(400).json({ error: "Email already registered" });
          }
          console.error('User insert error:', err2);
          return res.status(500).json({ error: "DB error" });
        }

        createSession(this.lastID, res, e);
      }
    );
  });
});

app.post('/api/login', (req, res) => {
  const e = String(req.body.email || '').trim().toLowerCase();
  const p = String(req.body.password || '');

  if (!e || !p) return res.status(400).json({ error: "Email and password required" });

  db.get("SELECT * FROM users WHERE email = ?", [e], (err, user) => {
    if (err) {
      console.error('User lookup error:', err);
      return res.status(500).json({ error: "DB error" });
    }
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    bcrypt.compare(p, user.password_hash, (err2, ok) => {
      if (err2) {
        console.error('Compare error:', err2);
        return res.status(500).json({ error: "Auth error" });
      }
      if (!ok) return res.status(400).json({ error: "Invalid credentials" });

      createSession(user.id, res, user.email);
    });
  });
});

app.post('/api/logout', (req, res) => {
  const sid = req.cookies.session_id;
  if (sid) {
    db.run("DELETE FROM sessions WHERE id = ?", [sid], err => {
      if (err) console.error('Session delete error:', err);
    });
  }
  res.clearCookie("session_id");
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, email: req.user.email });
});

// ---------------------------------------------------------------------------
// UPLOAD FILE (with quota check)
// ---------------------------------------------------------------------------

app.post('/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file" });

  const newFileSize = req.file.size;

  db.get(
    "SELECT IFNULL(SUM(size),0) AS used FROM files WHERE user_id = ?",
    [req.user.id],
    (err, row) => {
      if (err) {
        console.error('Usage query error:', err);
        // Clean up file
        fs.unlink(req.file.path, () => {});
        return res.status(500).json({ error: "Server error" });
      }

      const currentlyUsed = row ? row.used : 0;
      const projected = currentlyUsed + newFileSize;

      if (projected > QUOTA_BYTES) {
        // Over quota — delete the uploaded file
        fs.unlink(req.file.path, () => {});
        return res.status(400).json({ error: "Storage quota exceeded (1 GB limit)" });
      }

      const id = path.basename(req.file.filename, path.extname(req.file.filename));

      db.run(
        `INSERT INTO files (id, filename, original_name, size, mime, created, user_id, views)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
        [
          id,
          req.file.filename,
          req.file.originalname,
          req.file.size,
          req.file.mimetype,
          Date.now(),
          req.user.id
        ],
        err2 => {
          if (err2) {
            console.error('File DB error:', err2);
            fs.unlink(req.file.path, () => {});
            return res.status(500).json({ error: "DB save error" });
          }
          res.json({ url: `${req.protocol}://${req.get('host')}/f/${id}` });
        }
      );
    }
  );
});

// ---------------------------------------------------------------------------
// CREATE PASTE (clean title, not based on content)
// ---------------------------------------------------------------------------

app.post(
  '/paste',
  requireAuth,
  express.text({ type: '*/*', limit: '10mb' }),
  (req, res) => {
    const content = (req.body || "").toString().trim();
    if (!content) return res.status(400).json({ error: "Empty paste" });

    const id = crypto.randomBytes(6).toString("hex");
    const createdAt = Date.now();

    const ts = new Date(createdAt)
      .toISOString()
      .slice(0, 16)
      .replace("T", " ");

    const title = `Paste ${ts}`;

    db.run(
      `INSERT INTO pastes (id, content, title, created, user_id, views)
       VALUES (?, ?, ?, ?, ?, 0)`,
      [id, content, title, createdAt, req.user.id],
      err => {
        if (err) {
          console.error('Paste DB error:', err);
          return res.status(500).json({ error: "DB error" });
        }
        res.json({ url: `${req.protocol}://${req.get('host')}/p/${id}` });
      }
    );
  }
);

// ---------------------------------------------------------------------------
// VIEW FILE (increments views)
// ---------------------------------------------------------------------------

app.get('/f/:id', (req, res) => {
  const id = req.params.id;
  db.get("SELECT * FROM files WHERE id = ?", [id], (err, file) => {
    if (err) {
      console.error('File query error:', err);
      return res.status(500).send("Server error");
    }
    if (!file) return res.status(404).send("Not found");

    // Increment views (fire-and-forget)
    db.run("UPDATE files SET views = views + 1 WHERE id = ?", [id], err2 => {
      if (err2) console.error('Update views error (file):', err2);
    });

    const fp = path.join(UPLOAD_DIR, file.filename);
    const ext = path.extname(fp).toLowerCase();
    const imgs = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg', '.avif'];

    if (imgs.includes(ext)) res.sendFile(fp);
    else res.download(fp, file.original_name);
  });
});

// ---------------------------------------------------------------------------
// VIEW PASTE (with Highlight.js & views increment)
// ---------------------------------------------------------------------------

app.get('/p/:id', (req, res) => {
  const id = req.params.id;
  db.get("SELECT * FROM pastes WHERE id = ?", [id], (err, paste) => {
    if (err) {
      console.error('Paste query error:', err);
      return res.status(500).send("Server error");
    }
    if (!paste) return res.status(404).send("Not found");

    // Increment views
    db.run("UPDATE pastes SET views = views + 1 WHERE id = ?", [id], err2 => {
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
  });
});

// ---------------------------------------------------------------------------
// USER DASHBOARD LISTING (includes views & size)
// ---------------------------------------------------------------------------

app.get('/api/shares', requireAuth, (req, res) => {
  const all = [];

  db.all(
    "SELECT id, original_name AS title, 'file' AS type, created, size, views FROM files WHERE user_id = ?",
    [req.user.id],
    (err, files) => {
      if (err) {
        console.error('Files list error:', err);
        return res.status(500).json({ error: "DB error" });
      }
      if (files) all.push(...files);

      db.all(
        "SELECT id, title, 'paste' AS type, created, NULL AS size, views FROM pastes WHERE user_id = ?",
        [req.user.id],
        (err2, pastes) => {
          if (err2) {
            console.error('Pastes list error:', err2);
            return res.status(500).json({ error: "DB error" });
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
// USAGE STATS (quota, used, remaining, file count)
// ---------------------------------------------------------------------------

app.get('/api/usage', requireAuth, (req, res) => {
  db.get(
    "SELECT COUNT(*) AS fileCount, IFNULL(SUM(size),0) AS totalSize FROM files WHERE user_id = ?",
    [req.user.id],
    (err, row) => {
      if (err) {
        console.error('Usage stats error:', err);
        return res.status(500).json({ error: "DB error" });
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
// DELETE SHARE
// ---------------------------------------------------------------------------

app.delete('/api/share/:type/:id', requireAuth, (req, res) => {
  const { type, id } = req.params;

  if (type === "file") {
    db.get("SELECT * FROM files WHERE id = ? AND user_id = ?", [id, req.user.id], (err, f) => {
      if (err) {
        console.error('File lookup error:', err);
        return res.status(500).json({ error: "Server error" });
      }
      if (!f) return res.status(404).json({ error: "Not found" });

      fs.unlink(path.join(UPLOAD_DIR, f.filename), () => {
        db.run("DELETE FROM files WHERE id = ?", [id], err2 => {
          if (err2) {
            console.error('File delete DB error:', err2);
            return res.status(500).json({ error: "Server error" });
          }
          res.json({ ok: true });
        });
      });
    });
  } else if (type === "paste") {
    db.get("SELECT * FROM pastes WHERE id = ? AND user_id = ?", [id, req.user.id], (err, p) => {
      if (err) {
        console.error('Paste lookup error:', err);
        return res.status(500).json({ error: "Server error" });
      }
      if (!p) return res.status(404).json({ error: "Not found" });

      db.run("DELETE FROM pastes WHERE id = ?", [id], err2 => {
        if (err2) {
          console.error('Paste delete DB error:', err2);
          return res.status(500).json({ error: "Server error" });
        }
        res.json({ ok: true });
      });
    });
  } else {
    res.status(400).json({ error: "Invalid type" });
  }
});

// ---------------------------------------------------------------------------
// SPA FALLBACK
// ---------------------------------------------------------------------------

app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// ---------------------------------------------------------------------------
// UTILITIES
// ---------------------------------------------------------------------------

function e(str) {
  return String(str).replace(/[&<>"']/g, c => ({
    "&":"&amp;",
    "<":"&lt;",
    ">":"&gt;",
    "\"":"&quot;",
    "'":"&#39;"
  }[c]));
}

// ---------------------------------------------------------------------------
// HTTPS SERVER (Let’s Encrypt)
// ---------------------------------------------------------------------------

// CHANGE THIS 
const domain = "paste.3nd3r.net";

const httpsOptions = {
  key: fs.readFileSync(`/etc/letsencrypt/live/${domain}/privkey.pem`),
  cert: fs.readFileSync(`/etc/letsencrypt/live/${domain}/fullchain.pem`)
};

// Redirect HTTP → HTTPS
http.createServer((req, res) => {
  const host = (req.headers.host || '').replace(/:\d+$/, "");
  res.writeHead(301, { Location: `https://${host}${req.url}` });
  res.end();
}).listen(HTTP_PORT, () => {
  console.log(`HTTP redirect server on :${HTTP_PORT}`);
});

// HTTPS app server
https.createServer(httpsOptions, app).listen(HTTPS_PORT, () => {
  console.log(`Pastebin LIVE over HTTPS on :${HTTPS_PORT}`);
});
