// server.js — Kim's Coffee License Server
// -----------------------------------------------------------------------
// Minimal backend that lets you sell yearly subscriptions to the POS app.
// Each cafe gets a license key. The app calls /api/license/verify every
// time it's opened (when online) to confirm the key is still valid.
// You create/renew/revoke keys through the small admin page at /admin.
//
// قاعدة البيانات: يستخدم @libsql/client، يشتغل بشكل ممتاز مع Turso
// (خدمة مجانية للأبد، بياناتها ما تنمسح أبداً حتى لو Render نام أو
// أعاد النشر) - شوف README.md لخطوات ربطها. بدون Turso، يرجع لملف
// محلي مؤقت (يصلح للتجربة بس).
// -----------------------------------------------------------------------

const express = require('express');
const { createClient } = require('@libsql/client');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
// يسمح لتطبيق الكاشير (اللي يشتغل على دومين مختلف تماماً، مثل GitHub Pages) يتواصل مع هذا السيرفر.
// بدون هذا، المتصفح يحجب أي طلب بين دومينين مختلفين تلقائياً (CORS) ويطلع خطأ "تعذر الاتصال".
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-admin-secret');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use('/admin', express.static(path.join(__dirname, 'public')));
// يخلي /admin و /admin/ يفتحون صفحة الإدارة مباشرة بدون الحاجة تكتب admin.html بآخر الرابط
app.get(['/admin', '/admin/'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

const PORT = process.env.PORT || 3000;
// IMPORTANT: set this to a real secret via environment variable in production.
// This password protects the /admin page and the admin API endpoints below.
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'change-this-password';

// قاعدة البيانات: إذا حطيت TURSO_DATABASE_URL و TURSO_AUTH_TOKEN (من حسابك المجاني
// بـ turso.tech)، البيانات تنحفظ دائماً بالسحابة ومتنمسح أبداً. بدونهم، يستخدم ملف
// محلي مؤقت (يصلح للتجربة فقط - ينمسح على Render المجاني كل ما يرتاح أو يعاد نشره).
const db = createClient(
  process.env.TURSO_DATABASE_URL
    ? { url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN }
    : { url: `file:${process.env.DB_PATH || path.join(__dirname, 'licenses.db')}` }
);

async function initDb() {
  await db.execute(`
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
  await db.execute(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);
}
initDb().catch(err => console.error('فشل تجهيز قاعدة البيانات:', err));

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
app.post('/api/license/verify', async (req, res) => {
  const { key, deviceId } = req.body || {};
  if (!key || !deviceId) {
    return res.status(400).json({ valid: false, reason: 'missing_fields' });
  }
  try {
    const result = await db.execute({
      sql: 'SELECT * FROM licenses WHERE key = ?',
      args: [String(key).trim().toUpperCase()]
    });
    const license = result.rows[0];

    if (!license) return res.json({ valid: false, reason: 'not_found' });
    if (!license.active) return res.json({ valid: false, reason: 'revoked' });
    if (Date.now() > license.expires_at) {
      return res.json({ valid: false, reason: 'expired', expiresAt: license.expires_at });
    }

    // Bind the key to the first device that verifies successfully. This stops
    // one paid key from being copy-pasted into many different cafes at once.
    // If a customer switches tablets, unbind the key for them from /admin.
    if (!license.device_id) {
      await db.execute({
        sql: 'UPDATE licenses SET device_id = ?, last_verified_at = ? WHERE key = ?',
        args: [deviceId, Date.now(), license.key]
      });
    } else if (license.device_id !== deviceId) {
      return res.json({ valid: false, reason: 'device_mismatch' });
    } else {
      await db.execute({
        sql: 'UPDATE licenses SET last_verified_at = ? WHERE key = ?',
        args: [Date.now(), license.key]
      });
    }

    return res.json({ valid: true, expiresAt: license.expires_at, customerName: license.customer_name });
  } catch (err) {
    console.error('license/verify error:', err);
    res.status(500).json({ valid: false, reason: 'server_error' });
  }
});

// ------------------------------------------------------------------
// PUBLIC: معلومات التواصل بتاعتك (واتساب/انستغرام/رابط إضافي) يقرأها التطبيق
// نفسه ليعرضها للزبون - ما فيها شي حساس، فما تحتاج كلمة سر.
// ------------------------------------------------------------------
app.get('/api/contact-info', async (req, res) => {
  try {
    const result = await db.execute('SELECT key, value FROM settings');
    const info = { whatsapp: '', instagram: '', website: '' };
    result.rows.forEach(r => { info[r.key] = r.value; });
    res.json(info);
  } catch (err) {
    console.error('contact-info error:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

// يستخدمها زر "دخول" بصفحة الإدارة بس للتأكد إن كلمة السر صحيحة قبل ما يفتح الصفحة كاملة
app.post('/api/admin/check', requireAdmin, (req, res) => {
  res.json({ ok: true });
});

// ------------------------------------------------------------------
// ADMIN (password-protected): used from the /admin page to manage keys.
// ------------------------------------------------------------------
app.post('/api/admin/licenses', requireAdmin, async (req, res) => {
  const { customerName, months, days } = req.body || {};
  if (!customerName || (!months && !days)) {
    return res.status(400).json({ error: 'customerName and months or days are required' });
  }
  const key = generateKey();
  const now = Date.now();
  const durationMs = days
    ? Math.round(Number(days) * 24 * 60 * 60 * 1000)
    : Math.round(Number(months) * 30 * 24 * 60 * 60 * 1000);
  const expiresAt = now + durationMs;
  try {
    await db.execute({
      sql: 'INSERT INTO licenses (key, customer_name, expires_at, active, created_at) VALUES (?, ?, ?, 1, ?)',
      args: [key, customerName, expiresAt, now]
    });
    res.json({ key, customerName, expiresAt });
  } catch (err) {
    console.error('create license error:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/admin/licenses', requireAdmin, async (req, res) => {
  try {
    const result = await db.execute('SELECT * FROM licenses ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('list licenses error:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/licenses/:key/renew', requireAdmin, async (req, res) => {
  const { months, days } = req.body || {};
  try {
    const result = await db.execute({ sql: 'SELECT * FROM licenses WHERE key = ?', args: [req.params.key] });
    const license = result.rows[0];
    if (!license) return res.status(404).json({ error: 'not_found' });
    const base = Math.max(license.expires_at, Date.now());
    const durationMs = days
      ? Math.round(Number(days) * 24 * 60 * 60 * 1000)
      : Math.round(Number(months) * 30 * 24 * 60 * 60 * 1000);
    const newExpiry = base + durationMs;
    await db.execute({ sql: 'UPDATE licenses SET expires_at = ?, active = 1 WHERE key = ?', args: [newExpiry, license.key] });
    res.json({ key: license.key, expiresAt: newExpiry });
  } catch (err) {
    console.error('renew error:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/licenses/:key/revoke', requireAdmin, async (req, res) => {
  try {
    await db.execute({ sql: 'UPDATE licenses SET active = 0 WHERE key = ?', args: [req.params.key] });
    res.json({ ok: true });
  } catch (err) {
    console.error('revoke error:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/licenses/:key/unbind', requireAdmin, async (req, res) => {
  try {
    await db.execute({ sql: 'UPDATE licenses SET device_id = NULL WHERE key = ?', args: [req.params.key] });
    res.json({ ok: true });
  } catch (err) {
    console.error('unbind error:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

// حفظ/تحديث معلومات التواصل (واتساب/انستغرام/رابط إضافي) - يظهرون بعدها تلقائياً بتطبيق الكاشير
app.post('/api/admin/contact-info', requireAdmin, async (req, res) => {
  const { whatsapp, instagram, website } = req.body || {};
  try {
    const upsert = (k, v) => db.execute({
      sql: 'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
      args: [k, v]
    });
    if (whatsapp !== undefined) await upsert('whatsapp', String(whatsapp || ''));
    if (instagram !== undefined) await upsert('instagram', String(instagram || ''));
    if (website !== undefined) await upsert('website', String(website || ''));
    res.json({ ok: true });
  } catch (err) {
    console.error('contact-info save error:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.listen(PORT, () => {
  console.log(`License server running on port ${PORT}`);
});
