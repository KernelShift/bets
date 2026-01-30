'use strict';

const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const expressLayouts = require('express-ejs-layouts');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const bcrypt = require('bcryptjs');
const validator = require('validator');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const crypto = require('crypto');

const db = require('./db');
const { securityStack } = require('./security');
const { requireAuth, require2faIfEnabled, noCache } = require('./middleware');

const app = express();

// ---------------- BTC wallet generation (CommonJS) ----------------
const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
const { ECPairFactory } = require('ecpair');
const ECPair = ECPairFactory(ecc);

// Choose mainnet vs testnet
const BTC_NETWORK = bitcoin.networks.bitcoin;
// const BTC_NETWORK = bitcoin.networks.testnet;

function requireMasterKey() {
  const hex = process.env.WALLET_MASTER_KEY_HEX;
  if (!hex || typeof hex !== 'string' || hex.length < 64) {
    throw new Error('Missing/weak WALLET_MASTER_KEY_HEX (need 32 bytes hex / 64 chars).');
  }
  const buf = Buffer.from(hex, 'hex');
  if (buf.length !== 32) {
    throw new Error('WALLET_MASTER_KEY_HEX must decode to exactly 32 bytes.');
  }
  return buf;
}

function encryptWithMasterKey(plaintextUtf8) {
  const key = requireMasterKey();         // 32 bytes
  const iv = crypto.randomBytes(12);      // 96-bit IV for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(plaintextUtf8, 'utf8')),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return {
    enc_b64: ciphertext.toString('base64'),
    iv_b64: iv.toString('base64'),
    tag_b64: tag.toString('base64'),
  };
}

function decryptWithMasterKey(enc_b64, iv_b64, tag_b64) {
  const key = requireMasterKey();
  const iv = Buffer.from(iv_b64, 'base64');
  const tag = Buffer.from(tag_b64, 'base64');
  const ciphertext = Buffer.from(enc_b64, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}

// Generate a real BTC private key + address
// - Private key stored as WIF (encrypted at rest)
// - Address is bech32 P2WPKH (bc1...)
function generateUserWallet() {
  const keyPair = ECPair.makeRandom({ network: BTC_NETWORK });

  const payment = bitcoin.payments.p2wpkh({
    pubkey: keyPair.publicKey,
    network: BTC_NETWORK
  });

  const address = payment.address;
  if (!address) throw new Error('Failed to derive BTC address.');

  const wif = keyPair.toWIF();
  const enc = encryptWithMasterKey(wif);

  return {
    address,
    wif_enc: enc.enc_b64,
    wif_iv: enc.iv_b64,
    wif_tag: enc.tag_b64,
    wallet_type: 'p2wpkh',
  };
}

// Optional internal-only helper (DO NOT expose in API responses)
function getUserWifFromDbRow(userRow) {
  return decryptWithMasterKey(
    userRow.wallet_privkey_enc,
    userRow.wallet_privkey_iv,
    userRow.wallet_privkey_tag
  );
}

// ---------------- Views / static ----------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

app.use('/public', express.static(path.join(__dirname, 'public')));

// ---------------- Body parsing + cookies ----------------
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

// ---------------- Security middleware ----------------
securityStack(app);

// ---------------- Sessions ----------------
const sessionSecret = process.env.SESSION_SECRET || 'dev-insecure-secret-change-me';
app.use(session({
  name: 'pp.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: 'sessions.db' }),
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// ---------------- CSRF (must be after cookie/session) ----------------
app.use(csurf());

// ---------------- Locals for templates ----------------
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  res.locals.user = null;
  res.locals.title = 'Poker Pool';

  if (req.session?.userId) {
    const u = db.prepare('SELECT id, username, display_name, twofa_enabled, wallet_address FROM users WHERE id = ?')
      .get(req.session.userId);
    res.locals.user = u || null;
  }
  next();
});

// ---------------- No-store for authenticated pages ----------------
app.use((req, res, next) => {
  if (req.session?.userId) return noCache(req, res, next);
  next();
});

// -------------- Helpers --------------

function nowIso() {
  return new Date().toISOString();
}

function satsToUsdCents(sats, satsPerUsd) {
  if (!satsPerUsd || satsPerUsd <= 0) return 0;
  return Math.round((sats * 100) / satsPerUsd);
}

// ---------- Live BTC rate (cached) ----------
let _rateCache = { ts: 0, btcUsd: null };

async function getBtcUsdRate() {
  const now = Date.now();
  if (_rateCache.btcUsd && (now - _rateCache.ts) < 60_000) return _rateCache.btcUsd; // 60s cache

  // CoinGecko simple price (no API key)
  const url = 'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd';
  const r = await fetch(url, { headers: { 'accept': 'application/json' } });
  if (!r.ok) throw new Error(`Rate fetch failed: ${r.status}`);
  const j = await r.json();

  const btcUsd = Number(j?.bitcoin?.usd);
  if (!Number.isFinite(btcUsd) || btcUsd <= 0) throw new Error('Invalid BTC/USD from rate API');

  _rateCache = { ts: now, btcUsd };
  return btcUsd;
}

async function getSatsPerUsdLive() {
  // sats per USD = 100,000,000 sats / (USD per BTC)
  const btcUsd = await getBtcUsdRate();
  return Math.max(1, Math.floor(100_000_000 / btcUsd));
}

// Public endpoint for UI
app.get('/api/rate', requireAuth, require2faIfEnabled, async (req, res) => {
  try {
    const btcUsd = await getBtcUsdRate();
    const satsPerUsd = Math.max(1, Math.floor(100_000_000 / btcUsd));
    return res.json({ ok: true, btcUsd, satsPerUsd, fetchedAt: nowIso() });
  } catch (e) {
    // fallback to your static env conversion if API fails
    const satsPerUsdFallback = satsPerUsd();
    return res.json({ ok: true, btcUsd: null, satsPerUsd: satsPerUsdFallback, fetchedAt: nowIso(), fallback: true });
  }
});

app.get('/api/deposits/latest-pending', requireAuth, require2faIfEnabled, (req, res) => {
  const uid = req.session.userId;

  const row = db.prepare(`
    SELECT id, usd_cents, status, created_at
    FROM deposits
    WHERE user_id = ? AND status = 'pending'
    ORDER BY id DESC
    LIMIT 1
  `).get(uid);

  return res.json({ ok: true, deposit: row || null });
});

function satsPerUsd() {
  // Configurable conversion; avoids live price feeds.
  // Example: SATS_PER_USD=2500 means $1 => 2500 sats.
  const raw = process.env.SATS_PER_USD || '2500';
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return 2500;
  return Math.floor(n);
}

function usdToSats(usdCents) {
  // sats = (usd * satsPerUsd)
  // usdCents -> usd = usdCents/100
  const spu = satsPerUsd();
  return Math.max(1, Math.floor((usdCents * spu) / 100));
}

function getUserBetSats(userId) {
  const row = db.prepare('SELECT amount_sats FROM bets WHERE user_id = ?').get(userId);
  return row ? row.amount_sats : 0;
}

function getTotalCreditedSats(userId) {
  const row = db.prepare(`
    SELECT COALESCE(SUM(sats), 0) AS total
    FROM deposits
    WHERE user_id = ? AND status = 'credited'
  `).get(userId);
  return row ? row.total : 0;
}

function syncBetFromDeposits(userId) {
  // Bet is ALWAYS 2x total credited sats
  const totalCredited = getTotalCreditedSats(userId);
  const bet = totalCredited * 2;

  db.prepare(`
    INSERT INTO bets (user_id, amount_sats, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET amount_sats=excluded.amount_sats, updated_at=excluded.updated_at
  `).run(userId, bet, nowIso());

  return bet;
}

function userHasBet(userId) {
  // Gate based on total credited sats (since bet is derived)
  return getTotalCreditedSats(userId) > 0;
}

function safeUsername(s) {
  return typeof s === 'string' && /^[a-zA-Z0-9_.-]{3,24}$/.test(s);
}

// -------------- Routes: Auth --------------

app.get('/', (req, res) => {
  if (req.session?.userId) return res.redirect('/main');
  return res.redirect('/login');
});

app.get('/register', (req, res) => {
  res.locals.title = 'Register';
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const displayName = (req.body.display_name || '').trim();
    const password = req.body.password || '';

    if (!safeUsername(username)) {
      res.locals.title = 'Register';
      return res.status(400).render('register', { error: 'Username must be 3–24 chars (letters/numbers/._- only).' });
    }
    if (!displayName || displayName.length > 32) {
      res.locals.title = 'Register';
      return res.status(400).render('register', { error: 'Display name is required (max 32).' });
    }
    if (typeof password !== 'string' || password.length < 10) {
      res.locals.title = 'Register';
      return res.status(400).render('register', { error: 'Password must be at least 10 characters.' });
    }

    const pwHash = await bcrypt.hash(password, 12);

    const team = (req.body.team || '').toString().trim().toLowerCase();
    if (!['patriots', 'seahawks'].includes(team)) {
    res.locals.title = 'Register';
    return res.status(400).render('register', { error: 'Please pick Patriots or Seahawks.' });
    }

    // REAL wallet
    const wallet = generateUserWallet();

    db.prepare(`
    INSERT INTO users (
        username, display_name, password_hash,
        wallet_address, wallet_privkey_enc, wallet_privkey_iv, wallet_privkey_tag, wallet_type,
        team,
        created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
    username,
    displayName,
    pwHash,
    wallet.address,
    wallet.wif_enc,
    wallet.wif_iv,
    wallet.wif_tag,
    wallet.wallet_type,
    team,
    nowIso()
    );

    return res.redirect('/login');
  } catch (e) {
    res.locals.title = 'Register';
    if (String(e).includes('UNIQUE')) {
      return res.status(400).render('register', { error: 'That username is taken.' });
    }
    if (String(e).includes('WALLET_MASTER_KEY_HEX')) {
      return res.status(500).render('register', { error: 'Server wallet key misconfigured (WALLET_MASTER_KEY_HEX).' });
    }
    return res.status(500).render('register', { error: 'Server error. Try again.' });
  }
});

app.get('/login', (req, res) => {
  res.locals.title = 'Login';
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    res.locals.title = 'Login';
    return res.status(400).render('login', { error: 'Invalid username or password.' });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    res.locals.title = 'Login';
    return res.status(400).render('login', { error: 'Invalid username or password.' });
  }

  req.session.userId = user.id;
  req.session.twofaEnabled = !!user.twofa_enabled;
  req.session.twofaVerified = !user.twofa_enabled;

  if (user.twofa_enabled) return res.redirect('/login-2fa');
  return res.redirect('/main');
});

app.get('/login-2fa', requireAuth, (req, res) => {
  if (!req.session.twofaEnabled) return res.redirect('/main');
  if (req.session.twofaVerified) return res.redirect('/main');
  res.locals.title = '2FA Verify';
  res.render('twofa_setup', { mode: 'verify', qrDataUrl: null, secret: null, error: null });
});

app.post('/login-2fa', requireAuth, (req, res) => {
  const token = (req.body.token || '').trim().replace(/\s+/g, '');
  const user = db.prepare('SELECT id, totp_secret_base32, twofa_enabled FROM users WHERE id = ?')
    .get(req.session.userId);

  if (!user || !user.twofa_enabled || !user.totp_secret_base32) {
    res.locals.title = '2FA Verify';
    return res.status(400).render('twofa_setup', { mode: 'verify', qrDataUrl: null, secret: null, error: '2FA not enabled.' });
  }

  const verified = speakeasy.totp.verify({
    secret: user.totp_secret_base32,
    encoding: 'base32',
    token,
    window: 1
  });

  if (!verified) {
    res.locals.title = '2FA Verify';
    return res.status(400).render('twofa_setup', { mode: 'verify', qrDataUrl: null, secret: null, error: 'Invalid code. Try again.' });
  }

  req.session.twofaVerified = true;
  return res.redirect('/main');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// -------------- Routes: Main & Betting --------------

app.get('/main', requireAuth, require2faIfEnabled, async (req, res) => {
  res.locals.title = 'Main';
  const uid = req.session.userId;

  const myBetSats = syncBetFromDeposits(uid);
  const creditedSats = getTotalCreditedSats(uid);
  const hasBet = creditedSats > 0;

  let spu;
  try {
    spu = await getSatsPerUsdLive();
  } catch {
    spu = satsPerUsd();
  }

  const myCreditedUsdCents = satsToUsdCents(creditedSats, spu);
  const myBetUsdCents = satsToUsdCents(myBetSats, spu);

  if (!hasBet) {
    return res.render('main', {
      hasBet: false,
      myBetUsdCents,
      myCreditedUsdCents,
      top3: [],
      others: [],
      message: 'To unlock the leaderboard, start a deposit in Settings.'
    });
  }

  const rows = db.prepare(`
    SELECT u.display_name, u.username, u.team, b.amount_sats
    FROM bets b
    JOIN users u ON u.id = b.user_id
    WHERE b.amount_sats > 0
    ORDER BY b.amount_sats DESC, u.username ASC
  `).all();

  const withUsd = rows.map(r => ({
    ...r,
    usd_cents: satsToUsdCents(r.amount_sats, spu)
  }));

  const top3 = withUsd.slice(0, 3);
  const others = withUsd.slice(3);

  return res.render('main', {
    hasBet: true,
    myBetUsdCents,
    myCreditedUsdCents,
    top3,
    others,
    message: null
  });
});

/**
 * Start a deposit from Main:
 * User enters USD -> create pending deposit -> redirect them to Settings deposit screen.
 */
app.post('/bet/start', requireAuth, require2faIfEnabled, async (req, res) => {
  const uid = req.session.userId;
  const usdRaw = (req.body.usd || '').toString().trim();

  if (!validator.isFloat(usdRaw, { min: 0.01, max: 100000 })) {
    return res.status(400).json({ ok: false, error: 'Invalid USD amount.' });
  }

  const usd = Number(usdRaw);
  const usdCents = Math.round(usd * 100);

  // LOCK conversion at time of deposit creation
  let satsPerUsdNow;
  try {
    satsPerUsdNow = await getSatsPerUsdLive();
  } catch {
    satsPerUsdNow = satsPerUsd(); // fallback if rate API down
  }

  const sats = Math.max(1, Math.floor((usdCents * satsPerUsdNow) / 100));

  const dep = db.prepare(`
    INSERT INTO deposits (user_id, sats, usd_cents, status, created_at)
    VALUES (?, ?, ?, 'pending', ?)
  `).run(uid, sats, usdCents, nowIso());

  return res.json({ ok: true, redirect: `/settings?deposit=${dep.lastInsertRowid}` });
});

/**
 * Get deposit details for Settings UI (includes QR code for the address).
 */
app.get('/api/deposit/:id', requireAuth, require2faIfEnabled, async (req, res) => {
  const uid = req.session.userId;
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ ok: false, error: 'Bad id.' });

  const dep = db.prepare('SELECT id, status, usd_cents, created_at FROM deposits WHERE id = ? AND user_id = ?')
    .get(id, uid);
  if (!dep) return res.status(404).json({ ok: false, error: 'Not found.' });

  const user = db.prepare('SELECT wallet_address FROM users WHERE id = ?').get(uid);
  const qrDataUrl = await qrcode.toDataURL(user.wallet_address);

  return res.json({
    ok: true,
    deposit: dep,
    address: user.wallet_address,
    qrDataUrl
  });
});

async function getAddressTotalReceivedSatsConfirmed(address) {
  // Blockstream public API (mainnet)
  const base = 'https://blockstream.info/api';
  const url = `${base}/address/${encodeURIComponent(address)}/txs`;

  const r = await fetch(url, { headers: { accept: 'application/json' } });
  if (!r.ok) throw new Error(`Blockstream error ${r.status}`);

  const txs = await r.json();
  let total = 0;

  for (const tx of txs) {
    const confirmed = !!tx?.status?.confirmed;
    if (!confirmed) continue;

    for (const vout of (tx.vout || [])) {
      // Blockstream returns address at vout.scriptpubkey_address and value in sats
      if (vout?.scriptpubkey_address === address) {
        total += Number(vout.value || 0);
      }
    }
  }

  return total;
}

app.post('/api/deposit/:id/check', requireAuth, require2faIfEnabled, async (req, res) => {
  try {
    const uid = req.session.userId;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) return res.status(400).json({ ok: false, error: 'Bad id.' });

    const dep = db.prepare('SELECT * FROM deposits WHERE id = ? AND user_id = ?').get(id, uid);
    if (!dep) return res.status(404).json({ ok: false, error: 'Not found.' });

    if (dep.status === 'credited') {
      return res.json({ ok: true, credited: true, note: 'Already credited.' });
    }

    const user = db.prepare('SELECT wallet_address FROM users WHERE id = ?').get(uid);
    const address = user.wallet_address;

    // how much has been credited already (so we don't double-count)
    const alreadyCredited = getTotalCreditedSats(uid);

    const receivedConfirmed = await getAddressTotalReceivedSatsConfirmed(address);

    const availableToCredit = Math.max(0, receivedConfirmed - alreadyCredited);

    if (availableToCredit >= dep.sats) {
      db.prepare(`UPDATE deposits SET status='credited', credited_at=? WHERE id=?`).run(nowIso(), id);
      const betSats = syncBetFromDeposits(uid);
      const totalCreditedSats = getTotalCreditedSats(uid);

      return res.json({
        ok: true,
        credited: true,
        receivedConfirmed,
        alreadyCredited,
        availableToCredit,
        betSats,
        totalCreditedSats
      });
    }

    return res.json({
      ok: true,
      credited: false,
      receivedConfirmed,
      alreadyCredited,
      availableToCredit,
      needed: dep.sats
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'Chain check failed.' });
  }
});

// -------------- Routes: Settings (2FA + Deposit UI) --------------
app.get('/settings', requireAuth, require2faIfEnabled, async (req, res) => {
  res.locals.title = 'Settings';
  const user = db.prepare('SELECT username, display_name, wallet_address, twofa_enabled, team FROM users WHERE id = ?')
    .get(req.session.userId);

  let spu;
  try {
    spu = await getSatsPerUsdLive();
  } catch {
    spu = satsPerUsd();
  }

  const totalCreditedSats = getTotalCreditedSats(req.session.userId);
  const betSats = syncBetFromDeposits(req.session.userId);

  const totalCreditedUsdCents = satsToUsdCents(totalCreditedSats, spu);
  const betUsdCents = satsToUsdCents(betSats, spu);

  const depositId = req.query.deposit ? String(req.query.deposit) : null;
  const qrDataUrl = await qrcode.toDataURL(user.wallet_address);

  res.render('settings', {
    user,
    error: null,
    message: null,
    depositId,
    qrDataUrl,
    totalCreditedUsdCents,
    betUsdCents
  });
});

// Update display name
app.post('/settings/profile', requireAuth, require2faIfEnabled, (req, res) => {
  const displayName = (req.body.display_name || '').trim();
  const user = db.prepare('SELECT username, display_name, wallet_address, twofa_enabled, team FROM users WHERE id = ?')
    .get(req.session.userId);

  if (!displayName || displayName.length > 32) {
    res.locals.title = 'Settings';
    return res.status(400).render('settings', {
      user,
      error: 'Display name required (max 32).',
      message: null,
      depositId: null,
      satsPerUsd: satsPerUsd(),
      totalCreditedSats: getTotalCreditedSats(req.session.userId),
      betSats: syncBetFromDeposits(req.session.userId)
    });
  }

  db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(displayName, req.session.userId);

  res.locals.title = 'Settings';
  const updated = db.prepare('SELECT username, display_name, wallet_address, twofa_enabled FROM users WHERE id = ?')
    .get(req.session.userId);

  return res.render('settings', {
    user: updated,
    error: null,
    message: 'Profile updated.',
    depositId: null,
    satsPerUsd: satsPerUsd(),
    totalCreditedSats: getTotalCreditedSats(req.session.userId),
    betSats: syncBetFromDeposits(req.session.userId)
  });
});

// Reset password (requires current password)
app.post('/settings/password', requireAuth, require2faIfEnabled, async (req, res) => {
  const current = req.body.current_password || '';
  const nextPw = req.body.new_password || '';

  const u = db.prepare('SELECT password_hash, username, display_name, wallet_address, twofa_enabled, team FROM users WHERE id = ?')
  .get(req.session.userId);

  const ok = await bcrypt.compare(current, u.password_hash);
  if (!ok) {
    res.locals.title = 'Settings';
    return res.status(400).render('settings', {
      user: u,
      error: 'Current password is wrong.',
      message: null,
      depositId: null,
      satsPerUsd: satsPerUsd(),
      totalCreditedSats: getTotalCreditedSats(req.session.userId),
      betSats: syncBetFromDeposits(req.session.userId)
    });
  }

  if (typeof nextPw !== 'string' || nextPw.length < 10) {
    res.locals.title = 'Settings';
    return res.status(400).render('settings', {
      user: u,
      error: 'New password must be at least 10 characters.',
      message: null,
      depositId: null,
      satsPerUsd: satsPerUsd(),
      totalCreditedSats: getTotalCreditedSats(req.session.userId),
      betSats: syncBetFromDeposits(req.session.userId)
    });
  }

  const pwHash = await bcrypt.hash(nextPw, 12);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(pwHash, req.session.userId);

  res.locals.title = 'Settings';
  return res.render('settings', {
    user: u,
    error: null,
    message: 'Password updated.',
    depositId: null,
    satsPerUsd: satsPerUsd(),
    totalCreditedSats: getTotalCreditedSats(req.session.userId),
    betSats: syncBetFromDeposits(req.session.userId)
  });
});

// 2FA: start setup
app.get('/settings/2fa/setup', requireAuth, require2faIfEnabled, async (req, res) => {
  const u = db.prepare('SELECT username, twofa_enabled FROM users WHERE id = ?').get(req.session.userId);
  if (u.twofa_enabled) return res.redirect('/settings');

  const secret = speakeasy.generateSecret({ name: `PokerPool (${u.username})` });
  const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);

  req.session.pendingTotpSecret = secret.base32;

  res.locals.title = '2FA Setup';
  return res.render('twofa_setup', { mode: 'setup', qrDataUrl, secret: secret.base32, error: null });
});

// 2FA: confirm setup
app.post('/settings/2fa/confirm', requireAuth, require2faIfEnabled, (req, res) => {
  const token = (req.body.token || '').trim().replace(/\s+/g, '');
  const secret = req.session.pendingTotpSecret;

  if (!secret) return res.status(400).send('No pending 2FA setup. Start again.');

  const verified = speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (!verified) {
    res.locals.title = '2FA Setup';
    return res.status(400).render('twofa_setup', { mode: 'setup', qrDataUrl: null, secret, error: 'Invalid code. Try again.' });
  }

  db.prepare('UPDATE users SET twofa_enabled = 1, totp_secret_base32 = ? WHERE id = ?')
    .run(secret, req.session.userId);

  req.session.pendingTotpSecret = null;

  req.session.twofaEnabled = true;
  req.session.twofaVerified = true;

  return res.redirect('/settings');
});

// 2FA: disable (requires code)
app.post('/settings/2fa/disable', requireAuth, require2faIfEnabled, (req, res) => {
  const token = (req.body.token || '').trim().replace(/\s+/g, '');
  const u = db.prepare('SELECT username, display_name, wallet_address, twofa_enabled, totp_secret_base32, team FROM users WHERE id = ?')
    .get(req.session.userId);

  if (!u.twofa_enabled || !u.totp_secret_base32) {
    res.locals.title = 'Settings';
    return res.render('settings', {
      user: u,
      error: '2FA not enabled.',
      message: null,
      depositId: null,
      satsPerUsd: satsPerUsd(),
      totalCreditedSats: getTotalCreditedSats(req.session.userId),
      betSats: syncBetFromDeposits(req.session.userId)
    });
  }

  const verified = speakeasy.totp.verify({
    secret: u.totp_secret_base32,
    encoding: 'base32',
    token,
    window: 1
  });

  if (!verified) {
    res.locals.title = 'Settings';
    return res.render('settings', {
      user: u,
      error: 'Invalid 2FA code.',
      message: null,
      depositId: null,
      satsPerUsd: satsPerUsd(),
      totalCreditedSats: getTotalCreditedSats(req.session.userId),
      betSats: syncBetFromDeposits(req.session.userId)
    });
  }

  db.prepare('UPDATE users SET twofa_enabled = 0, totp_secret_base32 = NULL WHERE id = ?')
    .run(req.session.userId);

  req.session.twofaEnabled = false;
  req.session.twofaVerified = true;

  const user = db.prepare('SELECT username, display_name, wallet_address, twofa_enabled, team FROM users WHERE id = ?')
  .get(req.session.userId);

  res.locals.title = 'Settings';
  return res.render('settings', {
    user,
    error: null,
    message: '2FA disabled.',
    depositId: null,
    satsPerUsd: satsPerUsd(),
    totalCreditedSats: getTotalCreditedSats(req.session.userId),
    betSats: syncBetFromDeposits(req.session.userId)
  });
});

// CSRF error handler
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).send('Invalid CSRF token. Refresh and try again.');
  }
  return next(err);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`PokerPool running on http://localhost:${port}`));