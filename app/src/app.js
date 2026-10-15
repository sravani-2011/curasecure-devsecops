const express = require('express');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const cfg = require('./config');
const store = require('./store');
const audit = require('./audit');
const validate = require('./validate');
const { COOKIE, login, cookieOptions, authenticate, requireRole } = require('./auth');

const app = express();
app.disable('x-powered-by');

// ---- Security headers (OWASP Secure Headers) ----
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'"], connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"],
      formAction: ["'self'"], frameAncestors: ["'none'"],
    },
  },
  hsts: cfg.cookieSecure, // only meaningful behind TLS
  crossOriginEmbedderPolicy: true,
  referrerPolicy: { policy: 'no-referrer' },
}));
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  next();
});

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// ---- CSRF defence: state-changing requests must be same-origin JSON ----
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const origin = req.get('origin');
    if (origin && new URL(origin).host !== req.get('host')) {
      audit.record(req, 'csrf.blocked', { target: req.originalUrl, outcome: 'denied' });
      return res.status(403).json({ error: 'Cross-origin request blocked' });
    }
    if (!req.is('application/json')) return res.status(415).json({ error: 'Content-Type must be application/json' });
  }
  return next();
});

// ---- Rate limiting (brute-force protection) ----
const loginLimiter = rateLimit({ windowMs: 15 * 60000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Too many login attempts, try again later' } });
const apiLimiter = rateLimit({ windowMs: 60000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false });
app.use('/api', apiLimiter);

app.use(express.static(path.join(__dirname, '..', 'public'), { extensions: ['html'], index: 'index.html' }));

// ---- Health probes ----
app.get('/healthz', (req, res) => res.json({ status: 'ok' }));
app.get('/readyz', (req, res) => res.json({ status: 'ready' }));
app.get('/api/build', (req, res) => res.json(cfg.build));

// ---- Auth ----
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const c = validate.credentials(req.body);
  if (!c) return res.status(400).json({ error: 'Invalid username or password format' });
  const r = await login(c.username, c.password);
  if (r.error === 'locked') {
    audit.record(req, 'login.locked', { user: c.username, outcome: 'denied' });
    return res.status(423).json({ error: `Account locked after ${cfg.maxFailedLogins} failed attempts. Try again in ${cfg.lockoutMinutes} minutes.` });
  }
  if (r.error) {
    audit.record(req, 'login.failed', { user: c.username, outcome: 'failure' });
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  res.cookie(COOKIE, r.token, cookieOptions());
  audit.record({ ...req, ip: req.ip, user: { sub: r.user.username, role: r.user.role } }, 'login.success');
  return res.json({ user: r.user });
});

app.post('/api/auth/logout', authenticate, (req, res) => {
  audit.record(req, 'logout');
  res.clearCookie(COOKIE, { path: '/' });
  res.json({ ok: true });
});

app.get('/api/auth/me', authenticate, (req, res) => res.json({ user: { username: req.user.sub, name: req.user.name, role: req.user.role } }));

// ---- Patients (RBAC + audit on every PHI access) ----
app.get('/api/patients', authenticate, requireRole('doctor', 'nurse', 'admin'), (req, res) => {
  audit.record(req, 'patient.list');
  res.json({ patients: store.listPatients(req.user.role) });
});

app.get('/api/patients/:mrn', authenticate, requireRole('doctor', 'nurse', 'admin'), (req, res) => {
  if (!validate.isMrn(req.params.mrn)) return res.status(400).json({ error: 'Invalid MRN' });
  const p = store.getPatient(req.params.mrn, req.user.role);
  if (!p) return res.status(404).json({ error: 'Patient not found' });
  audit.record(req, 'patient.view', { target: req.params.mrn });
  return res.json({ patient: p });
});

app.post('/api/patients/:mrn/notes', authenticate, requireRole('doctor'), (req, res) => {
  if (!validate.isMrn(req.params.mrn)) return res.status(400).json({ error: 'Invalid MRN' });
  const v = validate.note(req.body);
  if (v.error) return res.status(400).json({ error: v.error });
  if (!store.addNote(req.params.mrn, req.user.sub, v.value)) return res.status(404).json({ error: 'Patient not found' });
  audit.record(req, 'note.create', { target: req.params.mrn });
  return res.status(201).json({ ok: true });
});

app.post('/api/patients/:mrn/vitals', authenticate, requireRole('doctor', 'nurse'), (req, res) => {
  if (!validate.isMrn(req.params.mrn)) return res.status(400).json({ error: 'Invalid MRN' });
  const v = validate.vitals(req.body);
  if (v.error) return res.status(400).json({ error: v.error });
  if (!store.addVitals(req.params.mrn, req.user.sub, v.value)) return res.status(404).json({ error: 'Patient not found' });
  audit.record(req, 'vitals.record', { target: req.params.mrn });
  return res.status(201).json({ ok: true });
});

// ---- Admin: audit trail + proof of encryption at rest ----
app.get('/api/audit', authenticate, requireRole('admin'), (req, res) => {
  audit.record(req, 'audit.view');
  res.json({ chainValid: audit.verifyChain(), entries: audit.list(300) });
});

app.get('/api/admin/encrypted/:mrn', authenticate, requireRole('admin'), (req, res) => {
  if (!validate.isMrn(req.params.mrn)) return res.status(400).json({ error: 'Invalid MRN' });
  const r = store.rawRecord(req.params.mrn);
  if (!r) return res.status(404).json({ error: 'Patient not found' });
  audit.record(req, 'record.raw_view', { target: req.params.mrn });
  return res.json(r);
});

// ---- Security Center: results of the DevSecOps pipeline (written by Jenkins) ----
app.get('/api/security', authenticate, (req, res) => {
  try {
    res.json(JSON.parse(fs.readFileSync(cfg.securityReportFile, 'utf8')));
  } catch {
    res.json({ available: false });
  }
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, '..', 'public', '404.html')));

// Generic error handler: never leak stack traces
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large' });
  console.error(JSON.stringify({ level: 'error', msg: err.message }));
  return res.status(500).json({ error: 'Internal error' });
});

module.exports = app;
