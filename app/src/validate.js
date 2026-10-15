// Strict allow-list input validation. Anything unexpected is rejected.
const MRN_RE = /^MRN-\d{6}$/;
const USERNAME_RE = /^[a-z][a-z.]{2,31}$/;

function isMrn(v) { return typeof v === 'string' && MRN_RE.test(v); }

function credentials(body) {
  if (!body || typeof body !== 'object') return null;
  const { username, password } = body;
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) return null;
  if (typeof password !== 'string' || password.length < 1 || password.length > 128) return null;
  return { username, password };
}

function note(body) {
  if (!body || typeof body.text !== 'string') return { error: 'text is required' };
  const text = body.text.trim();
  if (text.length < 3 || text.length > 2000) return { error: 'Note must be 3-2000 characters' };
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(text)) return { error: 'Invalid characters' };
  return { value: text };
}

const VITAL_RANGES = {
  heartRate: [20, 250], systolic: [50, 260], diastolic: [30, 160], temperature: [30, 45], spo2: [50, 100],
};

function vitals(body) {
  if (!body || typeof body !== 'object') return { error: 'Invalid body' };
  const out = {};
  for (const [k, [min, max]] of Object.entries(VITAL_RANGES)) {
    const n = Number(body[k]);
    if (!Number.isFinite(n) || n < min || n > max) return { error: `${k} must be between ${min} and ${max}` };
    out[k] = Math.round(n * 10) / 10;
  }
  if (out.diastolic >= out.systolic) return { error: 'diastolic must be lower than systolic' };
  return { value: out };
}

module.exports = { isMrn, credentials, note, vitals };
