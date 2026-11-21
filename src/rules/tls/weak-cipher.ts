import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const WEAK_CIPHER = /(RC4|3DES|_DES_|DES-CBC3|NULL|EXPORT|anon|MD5|CBC_SHA$)/i;

const rule: Rule = {
  id: 'tls-weak-cipher',
  severity: 'medium',
  title: 'TLS negotiated a weak cipher suite',
  what: 'The connection uses a cipher suite with known weaknesses (RC4, 3DES, DES, NULL, export-grade, anonymous or MD5-based).',
  why: 'Weak ciphers undermine the encryption that TLS promises. Some leak plaintext, some allow forgery, and export ciphers are breakable in seconds with modern hardware.',
  attack:
    'An attacker records an encrypted session and breaks the weak cipher offline, or manipulates a NULL/anonymous cipher to strip authentication and read credentials.',
  tags: ['tls', 'transport'],
  appliesTo: 'response',
  remediation: remediation(
    `// Node: prefer AEAD suites only
const server = https.createServer({
  key, cert,
  minVersion: 'TLSv1.2',
  ciphers: 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:TLS_AES_128_GCM_SHA256',
}, app);`,
    `// Next.js: configure TLS at the hosting layer (Vercel/Cloudflare handle this).
// For a custom Node server, pass the same ciphers option as the Express example.`,
    `# nginx: modern cipher list, server preference off for TLS 1.3
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers off;`,
  ),
  evaluate(ctx) {
    const cipher = ctx.event.tls?.cipher;
    if (!cipher || !WEAK_CIPHER.test(cipher)) return [];
    return [
      {
        key: cipher,
        message: `Cipher suite ${cipher} is considered weak.`,
        detail: 'Prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305.',
        evidence: cipher,
      },
    ];
  },
};

export default rule;
