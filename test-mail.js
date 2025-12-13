// test-mail.js
// Simple SMTP probe using nodemailer. Reads SMTP settings from environment.

const nodemailer = require('nodemailer');

(async () => {
  const host = process.env.MAIL_HOST || 'smtp.gmail.com';
  const port = Number(process.env.MAIL_PORT || 587);
  const secure = process.env.MAIL_SECURE === '1' || false;
  const user = process.env.MAIL_USER;
  const pass = process.env.MAIL_PASS;
  const from = process.env.MAIL_FROM || user;

  if (!user || !pass) {
    console.error('Missing MAIL_USER or MAIL_PASS environment variables.');
    process.exit(2);
  }

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
    tls: { rejectUnauthorized: false }
  });

  try {
    const info = await transporter.sendMail({
      from,
      to: user,
      subject: 'justpasted SMTP test',
      text: 'If you received this, SMTP is working for justpasted.'
    });
    console.log('Test email queued/sent:', info && (info.response || info.messageId || info));
    process.exit(0);
  } catch (err) {
    console.error('SMTP test failed:', err && err.message ? err.message : err);
    process.exit(3);
  } finally {
    transporter.close();
  }
})();
