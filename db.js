'use strict';

const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'app.db');
// open DB using DB_PATH

const db = new Database('app.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = OFF');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,

  twofa_enabled INTEGER NOT NULL DEFAULT 0,
  totp_secret_base32 TEXT,

  wallet_address TEXT NOT NULL,

  wallet_privkey_enc TEXT NOT NULL,
  wallet_privkey_iv  TEXT NOT NULL,
  wallet_privkey_tag TEXT NOT NULL,
  wallet_type        TEXT NOT NULL DEFAULT 'p2wpkh',

  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bets (
  user_id INTEGER PRIMARY KEY,
  amount_sats INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS deposits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  sats INTEGER NOT NULL,
  usd_cents INTEGER NOT NULL,
  status TEXT NOT NULL,            -- 'pending' | 'credited'
  created_at TEXT NOT NULL,
  credited_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

module.exports = db;