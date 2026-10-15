// Functional + security tests. Run in CI before any image is built.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

process.env.NODE_ENV = 'test';
process.env.DEMO_PASSWORD = 'Test-Only-Pass-123';
process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.DATA_KEY = crypto.randomBytes(32).toString('hex');
process.env.SECURITY_REPORT_FILE = '/nonexistent/summary.json';

const app = require('../src/app');
const { encrypt, decrypt, mask } = require('../src/crypto');
const audit = require('../src/audit');
const store = require('../src/store');

let server, base;
before(() => new Promise(r => { server = app.listen(0, () => { base = `http://127.0.0.1:${server.address().port}`; r(); }); }));
after(() => server.close());

const PW = process.env.DEMO_PASSWORD;
async function loginAs(username, password = PW) {
  const res = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username, password }) });
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  return { res, cookie };
}
const get = (path, cookie) => fetch(base + path, { headers: cookie ? { cookie } : {} });
const post = (path, cookie, body, extra = {}) => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', cookie, ...extra }, body: JSON.stringify(body) });

test('security headers are set (CSP, frame, nosniff, no x-powered-by)', async () => {
  const r = await get('/');
  assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
  assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.strictEqual(r.headers.get('x-content-type-options'), 'nosniff');
  assert.strictEqual(r.headers.get('x-powered-by'), null);
});

test('patient API requires authentication', async () => {
  assert.strictEqual((await get('/api/patients')).status, 401);
});

test('wrong password is rejected with a generic message', async () => {
  const { res } = await loginAs('dr.fernandes', 'wrong-password');
  assert.strictEqual(res.status, 401);
  assert.deepStrictEqual(await res.json(), { error: 'Invalid username or password' });
});

test('session cookie is HttpOnly and SameSite=Strict', async () => {
  const { res } = await loginAs('dr.mehta');
  assert.strictEqual(res.status, 200);
  const sc = res.headers.get('set-cookie');
  assert.match(sc, /HttpOnly/i);
  assert.match(sc, /SameSite=Strict/i);
});

test('account locks after 5 failed attempts', async () => {
  for (let i = 0; i < 5; i++) await loginAs('dr.fernandes', 'bad-' + i);
  const { res } = await loginAs('dr.fernandes');
  assert.strictEqual(res.status, 423);
});

test('doctor sees full identifiers; nurse sees masked; admin sees no clinical data', async () => {
  const d = (await loginAs('dr.mehta')).cookie;
  const n = (await loginAs('nurse.priya')).cookie;
  const a = (await loginAs('admin.rao')).cookie;
  const pd = (await (await get('/api/patients/MRN-100231', d)).json()).patient;
  const pn = (await (await get('/api/patients/MRN-100231', n)).json()).patient;
  const pa = (await (await get('/api/patients/MRN-100231', a)).json()).patient;
  assert.strictEqual(pd.nationalId, '900-12-4471');
  assert.match(pn.nationalId, /^•••-••-4471$/);
  assert.strictEqual(pn.notes, undefined);
  assert.strictEqual(pa.diagnosis, undefined);
  assert.strictEqual(pa.nationalId, undefined);
});

test('nurse cannot write physician notes (403) and denial is audited', async () => {
  const n = (await loginAs('nurse.priya')).cookie;
  const r = await post('/api/patients/MRN-100231/notes', n, { text: 'attempted note' });
  assert.strictEqual(r.status, 403);
  assert.ok(audit.list(5).some(e => e.action === 'access.denied' && e.user === 'nurse.priya'));
});

test('doctor note is stored encrypted, never as plaintext', async () => {
  const d = (await loginAs('dr.mehta')).cookie;
  const r = await post('/api/patients/MRN-100232/notes', d, { text: 'BP improving on current dose' });
  assert.strictEqual(r.status, 201);
  const raw = JSON.stringify(store.rawRecord('MRN-100232'));
  assert.ok(!raw.includes('BP improving'), 'plaintext leaked into storage');
  const p = (await (await get('/api/patients/MRN-100232', d)).json()).patient;
  assert.strictEqual(p.notes[0].text, 'BP improving on current dose');
});

test('input validation rejects out-of-range vitals and bad MRNs', async () => {
  const n = (await loginAs('nurse.priya')).cookie;
  const bad = await post('/api/patients/MRN-100233/vitals', n, { heartRate: 999, systolic: 120, diastolic: 80, temperature: 37, spo2: 98 });
  assert.strictEqual(bad.status, 400);
  const inj = await get("/api/patients/MRN-1'%20OR%201=1", n);
  assert.strictEqual(inj.status, 400);
  const ok = await post('/api/patients/MRN-100233/vitals', n, { heartRate: 80, systolic: 120, diastolic: 80, temperature: 37, spo2: 98 });
  assert.strictEqual(ok.status, 201);
});

test('cross-origin POST is blocked (CSRF protection)', async () => {
  const d = (await loginAs('dr.mehta')).cookie;
  const r = await post('/api/patients/MRN-100231/notes', d, { text: 'csrf attempt' }, { origin: 'https://evil.example' });
  assert.strictEqual(r.status, 403);
});

test('forged / tampered JWT is rejected', async () => {
  const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const forged = `${b64({ alg: 'none' })}.${b64({ sub: 'admin.rao', role: 'admin' })}.`; // "alg:none" attack
  const r = await get('/api/patients', `cs_session=${forged}`);
  assert.strictEqual(r.status, 401);
});

test('only admin can read the audit trail; chain verifies', async () => {
  const d = (await loginAs('dr.mehta')).cookie;
  assert.strictEqual((await get('/api/audit', d)).status, 403);
  const a = (await loginAs('admin.rao')).cookie;
  const body = await (await get('/api/audit', a)).json();
  assert.strictEqual(body.chainValid, true);
  assert.ok(body.entries.length > 0);
});

test('AES-256-GCM: random IV per value and tamper detection', () => {
  const a = encrypt('secret'), b = encrypt('secret');
  assert.notStrictEqual(a.ct + a.iv, b.ct + b.iv);
  assert.strictEqual(decrypt(a), 'secret');
  const t = { ...a, ct: Buffer.from('tampered!').toString('base64') };
  assert.throws(() => decrypt(t));
  assert.strictEqual(mask('900-12-4471'), '•••-••-4471');
});

test('malformed JSON and oversized bodies are rejected safely', async () => {
  const r1 = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad' });
  assert.strictEqual(r1.status, 400);
  const r2 = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'a', password: 'x'.repeat(20000) }) });
  assert.strictEqual(r2.status, 413);
});

test('pages load and unknown routes return 404', async () => {
  for (const p of ['/', '/login', '/dashboard', '/patient', '/audit', '/security']) assert.strictEqual((await get(p)).status, 200, p);
  assert.strictEqual((await get('/nope')).status, 404);
});
