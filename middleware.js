'use strict';

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) return res.redirect('/login');
  next();
}

function require2faIfEnabled(req, res, next) {
  // If user has 2FA enabled but session not verified, block
  if (req.session?.userId && req.session?.twofaEnabled && !req.session?.twofaVerified) {
    return res.redirect('/login-2fa');
  }
  next();
}

function noCache(req, res, next) {
  res.setHeader('Cache-Control', 'no-store');
  next();
}

module.exports = { requireAuth, require2faIfEnabled, noCache };