// Tamper-evident audit trail: every PHI access and security event is recorded.
// Each entry includes a SHA-256 hash chained to the previous entry, so editing
// or deleting a past entry breaks the chain (verifiable via verifyChain()).
// Log lines never contain PHI, only identifiers (user, role, MRN, action).
const crypto = require('crypto');

const MAX = 1000;
const entries = [];
let lastHash = 'GENESIS';

function record(req, action, details = {}) {
  const e = {
    id: entries.length ? entries[entries.length - 1].id + 1 : 1,
    at: new Date().toISOString(),
    user: req.user ? req.user.sub : (details.user || 'anonymous'),
    role: req.user ? req.user.role : null,
    action,
    target: details.target || null,
    outcome: details.outcome || 'success',
    ip: req.ip,
  };
  e.prevHash = lastHash;
  e.hash = crypto.createHash('sha256').update(JSON.stringify({ ...e, hash: undefined })).digest('hex');
  lastHash = e.hash;
  entries.push(e);
  if (entries.length > MAX) entries.shift();
  console.log(JSON.stringify({ level: 'audit', ...e }));
  return e;
}

function list(limit = 200) {
  return entries.slice(-limit).reverse();
}

function verifyChain() {
  for (let i = 1; i < entries.length; i++) {
    if (entries[i].prevHash !== entries[i - 1].hash) return false;
  }
  return entries.every(e => e.hash === crypto.createHash('sha256').update(JSON.stringify({ ...e, hash: undefined })).digest('hex'));
}

module.exports = { record, list, verifyChain, _entries: entries };
