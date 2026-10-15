// Authentication (bcrypt + short-lived JWT in an HttpOnly, SameSite=Strict cookie),
// account lockout, and role-based authorization middleware.
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cfg = require('./config');
const { users, failed } = require('./store');
const audit = require('./audit');

const COOKIE = 'cs_session';
const DUMMY_HASH = bcrypt.hashSync('timing-equaliser', 10);

async function login(username, password) {
  const f = failed[username];
  if (f && f.lockedUntil > Date.now()) return { error: 'locked' };
  const u = users[username];
  // Always run bcrypt so response time does not reveal whether a user exists
  const ok = await bcrypt.compare(password, u ? u.hash : DUMMY_HASH);
  if (!u || !ok) {
    if (u) {
      const rec = failed[username] || { count: 0, lockedUntil: 0 };
      rec.count += 1;
      if (rec.count >= cfg.maxFailedLogins) { rec.lockedUntil = Date.now() + cfg.lockoutMinutes * 60000; rec.count = 0; }
      failed[username] = rec;
    }
    return { error: 'invalid' };
  }
  delete failed[username];
  const token = jwt.sign({ sub: u.username, role: u.role, name: u.name }, cfg.jwtSecret, {
    algorithm: 'HS256', expiresIn: `${cfg.sessionMinutes}m`, issuer: 'curasecure',
  });
  return { token, user: { username: u.username, name: u.name, role: u.role } };
}

function cookieOptions() {
  return { httpOnly: true, sameSite: 'strict', secure: cfg.cookieSecure, maxAge: cfg.sessionMinutes * 60000, path: '/' };
}

function authenticate(req, res, next) {
  const token = req.cookies && req.cookies[COOKIE];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.user = jwt.verify(token, cfg.jwtSecret, { algorithms: ['HS256'], issuer: 'curasecure' });
    return next();
  } catch {
    res.clearCookie(COOKIE, { path: '/' });
    return res.status(401).json({ error: 'Session expired' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      audit.record(req, 'access.denied', { target: req.originalUrl, outcome: 'denied' });
      return res.status(403).json({ error: 'Your role is not permitted to perform this action' });
    }
    return next();
  };
}

module.exports = { COOKIE, login, cookieOptions, authenticate, requireRole };
