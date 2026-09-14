// server.js — Kim's Coffee License Server
// -----------------------------------------------------------------------
// Minimal backend that lets you sell yearly subscriptions to the POS app.
// Each cafe gets a license key. The app calls /api/license/verify every
// time it's opened (when online) to confirm the key is still valid.
// You create/renew/revoke keys through the small admin page at /admin.
// -----------------------------------------------------------------------

const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.use('/admin', express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
// IMPORTANT: set this to a real secret via environment variable in production.
// This password protects the /admin page and the admin API endpoints below.
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'change-this-password';

// مسار قاعدة البيانات: إذا ضفت قرص دائم (Persistent Disk) بـ Render، خله يشاور نفس مجلد القرص
// (مثلاً DB_PATH=/var/data/licenses.db) حتى لا تنمسح البيانات عند إعادة التشغيل أو النشر.
// بدون هذا المتغير، يستخدم ملف محلي بمجلد المشروع (يصلح للتجربة فقط، مو للاستخدام الحقيقي على Render).
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'licenses.db');
const db = new Database(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    key TEXT PRIMARY KEY,
    customer_name TEXT NOT NULL,
    device_id TEXT,
    expires_at INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_verified_at INTEGER
  )
`);

// Generates keys like KIMS-7F3K-9QRT-2XWM (easy to read/type over the phone).
// Excludes visually confusing characters (0/O, 1/I).
function generateKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const group = () => Array.from({ length: 4 }, () => chars[crypto.randomInt(chars.length)]).join('');
  return `KIMS-${group()}-${group()}-${group()}`;
}

function requireAdmin(req, res, next) {
  if (req.headers['x-admin-secret'] !== ADMIN_SECRET) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// ------------------------------------------------------------------
// PUBLIC: called by the app itself. No password — anyone could call
// this, but all they can do is check whether a key they already have
// is valid, which is fine.
// ------------------------------------------------------------------
app.post('/api/license/verify', (req, res) => {
  const { key, deviceId } = req.body || {};
  if (!key || !deviceId) {
    return res.status(400).json({ valid: false, reason: 'missing_fields' });
  }

  const license = db.prepare('SELECT * FROM licenses WHERE key = ?').get(String(key).trim().toUpperCase());

  if (!license) return res.json({ valid: false, reason: 'not_found' });
  if (!license.active) return res.json({ valid: false, reason: 'revoked' });
  if (Date.now() > license.expires_at) {
    return res.json({ valid: false, reason: 'expired', expiresAt: license.expires_at });
  }

  // Bind the key to the first device that verifies successfully. This stops
  // one paid key from being copy-pasted into many different cafes at once.
  // If a customer switches tablets, unbind the key for them from /admin.
  if (!license.device_id) {
    db.prepare('UPDATE licenses SET device_id = ?, last_verified_at = ? WHERE key = ?')
      .run(deviceId, Date.now(), license.key);
  } else if (license.device_id !== deviceId) {
    return res.json({ valid: false, reason: 'device_mismatch' });
  } else {
    db.prepare('UPDATE licenses SET last_verified_at = ? WHERE key = ?').run(Date.now(), license.key);
  }

  return res.json({ valid: true, expiresAt: license.expires_at, customerName: license.customer_name });
});

// ------------------------------------------------------------------
// ADMIN (password-protected): used from the /admin page to manage keys.
// ------------------------------------------------------------------
app.post('/api/admin/licenses', requireAdmin, (req, res) => {
  const { customerName, months } = req.body || {};
  if (!customerName || !months) {
    return res.status(400).json({ error: 'customerName and months are required' });
  }
  const key = generateKey();
  const now = Date.now();
  const expiresAt = now + Math.round(Number(months) * 30 * 24 * 60 * 60 * 1000);
  db.prepare(`INSERT INTO licenses (key, customer_name, expires_at, active, created_at) VALUES (?, ?, ?, 1, ?)`)
    .run(key, customerName, expiresAt, now);
  res.json({ key, customerName, expiresAt });
});

app.get('/api/admin/licenses', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all());
});

app.post('/api/admin/licenses/:key/renew', requireAdmin, (req, res) => {
  const { months } = req.body || {};
  const license = db.prepare('SELECT * FROM licenses WHERE key = ?').get(req.params.key);
  if (!license) return res.status(404).json({ error: 'not_found' });
  const base = Math.max(license.expires_at, Date.now());
  const newExpiry = base + Math.round(Number(months) * 30 * 24 * 60 * 60 * 1000);
  db.prepare('UPDATE licenses SET expires_at = ?, active = 1 WHERE key = ?').run(newExpiry, license.key);
  res.json({ key: license.key, expiresAt: newExpiry });
});

app.post('/api/admin/licenses/:key/revoke', requireAdmin, (req, res) => {
  db.prepare('UPDATE licenses SET active = 0 WHERE key = ?').run(req.params.key);
  res.json({ ok: true });
});

app.post('/api/admin/licenses/:key/unbind', requireAdmin, (req, res) => {
  db.prepare('UPDATE licenses SET device_id = NULL WHERE key = ?').run(req.params.key);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`License server running on port ${PORT}`);
});
