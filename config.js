// Centralized configuration file
// All deployment- and runtime-config should be set here or via environment variables.

const path = require('path');

const CONFIG = {
  HTTP_PORT: process.env.HTTP_PORT || 80,
  HTTPS_PORT: process.env.HTTPS_PORT || 443,

  // Uploads / public directories
  UPLOAD_DIR: path.join(__dirname, process.env.UPLOAD_DIR || 'uploads'),
  PUBLIC_DIR: path.join(__dirname, process.env.PUBLIC_DIR || 'public'),

  // Per-user quota (bytes)
  QUOTA_BYTES: Number(process.env.QUOTA_BYTES) || 1024 * 1024 * 1024,

  // Admin / owner settings
  OWNER_EMAIL: process.env.OWNER_EMAIL || 'lord3nd3r@gmail.com',
  ENABLE_ADMIN_REGISTRATION: process.env.ENABLE_ADMIN_REGISTRATION === '1' || false,

  // Email verification toggle
  EMAIL_VERIFICATION_ENABLED: process.env.EMAIL_VERIFICATION_ENABLED === '1' || false,

  // Mail server settings (for nodemailer). Fill these in or set env vars.
  MAIL: {
    HOST: process.env.MAIL_HOST || 'smtp.gmail.com',
    PORT: Number(process.env.MAIL_PORT) || 587,
    SECURE: process.env.MAIL_SECURE === '1' || false,
    AUTH_USER: process.env.MAIL_USER || '',
    AUTH_PASS: process.env.MAIL_PASS || null,
    FROM: process.env.MAIL_FROM || ''
  },

  // Site / domain
  // Letsencrypt domain override (useful when certs live under /etc/letsencrypt/live/<domain>)
  LETSENCRYPT_DOMAIN: process.env.LETSENCRYPT_DOMAIN || null,

  // Public site URL. If not set, will derive from LETSENCRYPT_DOMAIN when available.
  SITE_URL: process.env.SITE_URL || (process.env.LETSENCRYPT_DOMAIN ? `https://${process.env.LETSENCRYPT_DOMAIN}` : null),

  // Public site display name (brand)
  SITE_NAME: process.env.SITE_NAME || 'JustPasted',

  // Letsencrypt paths (optional)
  LETSENCRYPT: {
    LIVE_PATH: process.env.LETSENCRYPT_LIVE_PATH || `/etc/letsencrypt/live`
  }
};

module.exports = { CONFIG };
