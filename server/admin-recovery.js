#!/usr/bin/env node
'use strict';
const path = require('node:path');
const readline = require('node:readline');
const { DatabaseSync } = require('node:sqlite');
const security = require('./account-security');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
let db;

function usage() {
  console.error('Usage: node admin-recovery.js <init|reset-email>');
  process.exit(1);
}

function requireTty() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.error('TTY diperlukan. Jalankan interaktif di server.');
    process.exit(2);
  }
}

function promptHidden(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl.question(query, (value) => {
      rl.close();
      resolve(value.trim());
    });
    rl._writeToOutput = () => {};
  });
}

function prompt(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl.question(query, (value) => {
      rl.close();
      resolve(value.trim());
    });
  });
}

(async () => {
  const cmd = process.argv[2];
  if (!cmd) usage();
  requireTty();
  db = new DatabaseSync(path.join(DATA_DIR, 'tiassh.db'));
  security.migrate(db);
  try {
    if (cmd === 'init') {
      const existing = db.prepare('SELECT 1 FROM recovery_keys WHERE id=1').get();
      if (existing) throw new Error('Recovery key sudah ada');
      const key = require('node:crypto').randomBytes(48).toString('base64url');
      security.initializeRecoveryKey(db, key);
      console.log('\nSIMPAN KUNCI INI SEKALI SAJA. TIDAK DITAMPILKAN LAGI:\n');
      console.log(key);
      console.log('\nSelesai.');
    } else if (cmd === 'reset-email') {
      const recoveryKey = await promptHidden('Recovery key: ');
      const email = await prompt('Email akun: ');
      const newPassword = await promptHidden('Sandi baru (12-72 byte): ');
      security.adminResetByEmail(db, { recoveryKey, email, newPassword });
      console.log('Reset selesai. Semua sesi dicabut dan TOTP dihapus.');
    } else {
      usage();
    }
  } catch (e) {
    console.error(String(e.message || e));
    process.exit(1);
  } finally {
    if (db) db.close();
  }
})();
