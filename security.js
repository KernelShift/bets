'use strict';

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

function securityStack(app) {
  app.set('trust proxy', 1);

  app.use(helmet({
    contentSecurityPolicy: false // simplest for EJS + inline; tighten later if you want
  }));

  // Basic rate limiting for auth endpoints
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 25,
    standardHeaders: true,
    legacyHeaders: false
  });

  app.use('/login', authLimiter);
  app.use('/register', authLimiter);
  app.use('/settings', authLimiter);
}

module.exports = { securityStack };