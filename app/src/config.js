// Central configuration. Secrets come ONLY from environment variables
// (in Kubernetes: the "curasecure-secrets" Secret). Nothing sensitive is hard-coded.
const crypto = require('crypto');

const isProd = process.env.NODE_ENV === 'production';

function secret(name, bytes) {
  const v = process.env[name];
  if (v) return v;
  if (isProd) {
    // Fail closed: never run production without real secrets
    throw new Error(`Missing required secret ${name}`);
  }
  const generated = crypto.randomBytes(bytes).toString('hex');
  console.warn(JSON.stringify({ level: 'warn', msg: `${name} not set, generated an ephemeral value (dev only)` }));
  return generated;
}

const dataKeyHex = secret('DATA_KEY', 32);
if (!/^[0-9a-fA-F]{64}$/.test(dataKeyHex)) throw new Error('DATA_KEY must be 64 hex characters (256-bit key)');

module.exports = {
  isProd,
  port: Number(process.env.PORT) || 3000,
  jwtSecret: secret('JWT_SECRET', 48),
  dataKey: Buffer.from(dataKeyHex, 'hex'),
  demoPassword: secret('DEMO_PASSWORD', 9),
  cookieSecure: process.env.COOKIE_SECURE === 'true',
  sessionMinutes: 30,
  maxFailedLogins: 5,
  lockoutMinutes: 15,
  securityReportFile: process.env.SECURITY_REPORT_FILE || '/etc/curasecure/security-summary.json',
  build: {
    version: process.env.APP_VERSION || 'dev',
    buildNumber: process.env.BUILD_NUMBER || 'local',
    gitCommit: process.env.GIT_COMMIT || 'unknown',
  },
};
