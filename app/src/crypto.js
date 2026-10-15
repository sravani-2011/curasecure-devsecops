// Field-level encryption for PHI (Protected Health Information) at rest.
// AES-256-GCM: confidentiality + integrity (tampered ciphertext fails to decrypt).
const crypto = require('crypto');
const { dataKey } = require('./config');

function encrypt(plaintext) {
  const iv = crypto.randomBytes(12); // unique nonce per value
  const cipher = crypto.createCipheriv('aes-256-gcm', dataKey, iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  return { alg: 'AES-256-GCM', iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ct: ct.toString('base64') };
}

function decrypt(box) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, Buffer.from(box.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(box.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(box.ct, 'base64')), decipher.final()]).toString('utf8');
}

// Show only the last 4 characters (minimum-necessary principle)
function mask(value) {
  const s = String(value);
  return s.replace(/[A-Za-z0-9]/g, (c, i) => (i >= s.length - 4 ? c : '•'));
}

module.exports = { encrypt, decrypt, mask };
