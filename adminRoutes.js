// Admin routes registrar
module.exports = function registerAdminRoutes(app, deps) {
  const { requireAdmin, CONFIG, setSetting } = deps;

  app.get('/api/admin/config', requireAdmin, (req, res) => {
    const payload = {
      EMAIL_VERIFICATION_ENABLED: !!CONFIG.EMAIL_VERIFICATION_ENABLED,
      ENABLE_ADMIN_REGISTRATION: !!CONFIG.ENABLE_ADMIN_REGISTRATION,
      QUOTA_BYTES: CONFIG.QUOTA_BYTES,
      SITE_URL: CONFIG.SITE_URL,
      MAIL: {
        HOST: CONFIG.MAIL.HOST || '',
        PORT: CONFIG.MAIL.PORT || 587,
        SECURE: !!CONFIG.MAIL.SECURE,
        AUTH_USER: CONFIG.MAIL.AUTH_USER || '',
        FROM: CONFIG.MAIL.FROM || ''
      }
    };
    res.json(payload);
  });

  app.post('/api/admin/config', requireAdmin, (req, res) => {
    const body = req.body || {};
    if (typeof body.EMAIL_VERIFICATION_ENABLED === 'boolean') CONFIG.EMAIL_VERIFICATION_ENABLED = body.EMAIL_VERIFICATION_ENABLED;
    if (typeof body.ENABLE_ADMIN_REGISTRATION === 'boolean') CONFIG.ENABLE_ADMIN_REGISTRATION = body.ENABLE_ADMIN_REGISTRATION;
    if (body.QUOTA_BYTES) CONFIG.QUOTA_BYTES = Number(body.QUOTA_BYTES) || CONFIG.QUOTA_BYTES;
    if (body.SITE_URL) CONFIG.SITE_URL = String(body.SITE_URL);

    if (body.MAIL && typeof body.MAIL === 'object') {
      const m = body.MAIL;
      if (typeof m.HOST === 'string') CONFIG.MAIL.HOST = m.HOST;
      if (m.PORT) CONFIG.MAIL.PORT = Number(m.PORT) || CONFIG.MAIL.PORT;
      if (typeof m.SECURE === 'boolean') CONFIG.MAIL.SECURE = m.SECURE;
      if (typeof m.AUTH_USER === 'string') CONFIG.MAIL.AUTH_USER = m.AUTH_USER;
      if (typeof m.AUTH_PASS === 'string') CONFIG.MAIL.AUTH_PASS = m.AUTH_PASS;
      if (typeof m.FROM === 'string') CONFIG.MAIL.FROM = m.FROM;
    }

    // Persist non-mail settings immediately. MAIL settings are optional and
    // should be managed on the separate SMTP admin page. Only persist MAIL
    // when it's explicitly provided in the request body.
    try {
      setSetting('EMAIL_VERIFICATION_ENABLED', CONFIG.EMAIL_VERIFICATION_ENABLED ? '1' : '0');
      setSetting('ENABLE_ADMIN_REGISTRATION', CONFIG.ENABLE_ADMIN_REGISTRATION ? '1' : '0');
      setSetting('QUOTA_BYTES', String(CONFIG.QUOTA_BYTES));
      setSetting('SITE_URL', CONFIG.SITE_URL);
      if (body.MAIL && typeof body.MAIL === 'object') {
        setSetting('MAIL', JSON.stringify(CONFIG.MAIL));
      }
      res.json({ ok: true });
    } catch (e) {
      console.error('Error saving settings:', e && e.message ? e.message : e);
      res.status(500).json({ ok: false, error: 'save_failed' });
    }
  });

  app.post('/api/admin/test-smtp', requireAdmin, async (req, res) => {
    const mail = (req.body && req.body.MAIL) || CONFIG.MAIL;
    const to = (req.body && req.body.to) || CONFIG.OWNER_EMAIL || CONFIG.MAIL.FROM;
    // dynamic test using local mailer creation
    const nodemailer = require('nodemailer');
    try {
      const transporter = nodemailer.createTransport({
        host: mail.HOST,
        port: mail.PORT,
        secure: !!mail.SECURE,
        auth: mail.AUTH_USER ? { user: mail.AUTH_USER, pass: mail.AUTH_PASS } : undefined
      });
      // verify connection
      await transporter.verify();
      // send a test message
      await transporter.sendMail({ from: mail.FROM || CONFIG.MAIL.FROM, to, subject: 'SMTP test', text: 'This is a test message from justpasted.com' });
      res.json({ ok: true });
    } catch (e) {
      console.error('SMTP test error:', e && e.message ? e.message : e);
      res.status(500).json({ ok: false, error: (e && e.message) || 'smtp_error' });
    }
  });
};
