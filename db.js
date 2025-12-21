const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const { encrypt, decrypt } = require('./security');

const DB_PATH = path.join(__dirname, 'pastebin.db');
const db = new sqlite3.Database(DB_PATH);

function initDb() {
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
        target_type TEXT,
        target_id TEXT,
        reason TEXT,
        status TEXT DEFAULT 'open',
        created INTEGER,
        reporter_user_id INTEGER,
        reporter_ip TEXT
    )`);

    // Legacy/optional migrations (ignore duplicate column errors)
    db.run(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'`, err => {});
    db.run(`ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0`, err => {});
    db.run(`ALTER TABLE users ADD COLUMN created_ip TEXT`, err => {});
    db.run(`ALTER TABLE files ADD COLUMN views INTEGER DEFAULT 0`, err => {});
    db.run(`ALTER TABLE pastes ADD COLUMN views INTEGER DEFAULT 0`, err => {});
    db.run(`ALTER TABLE files ADD COLUMN expires INTEGER`, err => {});
    db.run(`ALTER TABLE pastes ADD COLUMN expires INTEGER`, err => {});
    // optional columns for resized/thumbnail image variants
    db.run(`ALTER TABLE files ADD COLUMN resized_filename TEXT`, err => {});
    db.run(`ALTER TABLE files ADD COLUMN thumb_filename TEXT`, err => {});

    // add last_seen to sessions for presence tracking
    db.run(`ALTER TABLE sessions ADD COLUMN last_seen INTEGER`, err => {});

    db.run(`ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0`, err => {});
    db.run(`ALTER TABLE users ADD COLUMN email_verification_code TEXT`, err => {});
    db.run(`ALTER TABLE users ADD COLUMN email_verification_expires INTEGER`, err => {});

    db.run(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )`);
  });
}

function getSetting(key, cb) {
  db.get('SELECT value FROM settings WHERE key = ?', [key], (err, row) => {
    if (err) return cb(err);
    if (!row) return cb(null, null);
    cb(null, row.value);
  });
}

function setSetting(key, value, cb) {
  let v = value === null || value === undefined ? null : String(value);
  try {
    if (key === 'MAIL') {
      const obj = typeof v === 'string' ? JSON.parse(v || '{}') : v;
      if (obj && obj.AUTH_PASS) {
        const enc = encrypt(obj.AUTH_PASS);
        if (enc) obj.AUTH_PASS = `ENC:${enc}`;
      }
      v = JSON.stringify(obj);
    }
  } catch (e) {
    console.error('Error preparing setting for storage:', e);
  }
  db.run('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', [key, v], err => {
    if (cb) cb(err);
  });
}

function loadAllSettings(callback) {
  db.all('SELECT key, value FROM settings', [], (err, rows) => {
    if (err) {
      console.error('Error loading settings from DB:', err);
      if (callback) callback(err);
      return;
    }
    const applied = {};
    rows.forEach(r => {
      try {
        if (r.key === 'MAIL') {
          const parsed = JSON.parse(r.value || '{}');
          if (parsed && parsed.AUTH_PASS && typeof parsed.AUTH_PASS === 'string' && parsed.AUTH_PASS.startsWith('ENC:')) {
            const cipher = parsed.AUTH_PASS.slice(4);
            const dec = decrypt(cipher);
            if (dec !== null) parsed.AUTH_PASS = dec;
            else delete parsed.AUTH_PASS;
          }
          applied.MAIL = parsed;
        } else if (r.key === 'EMAIL_VERIFICATION_ENABLED') {
          applied.EMAIL_VERIFICATION_ENABLED = r.value === '1' || r.value === 'true';
        } else if (r.key === 'ENABLE_ADMIN_REGISTRATION') {
          applied.ENABLE_ADMIN_REGISTRATION = r.value === '1' || r.value === 'true';
        } else if (r.key === 'QUOTA_BYTES') {
          applied.QUOTA_BYTES = Number(r.value);
        } else if (r.key === 'SITE_URL') {
          applied.SITE_URL = r.value;
        }
      } catch (e) {
        console.error('Error applying setting', r.key, e);
      }
    });
    if (callback) callback(null, applied);
  });
}

module.exports = { db, initDb, getSetting, setSetting, loadAllSettings };
