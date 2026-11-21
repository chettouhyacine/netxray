import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const OUTDATED = /(TLSv?1\.0|TLSv?1\.1|TLS 1\.0|TLS 1\.1|SSLv?2|SSLv?3|SSL 3)/i;

const rule: Rule = {
  id: 'tls-outdated-protocol',
  severity: 'high',
  title: 'Connection uses an outdated TLS version',
  what: 'The TLS handshake negotiated TLS 1.0/1.1 or an SSL version, all of which are deprecated and disallowed by modern browsers and PCI DSS.',
  why: 'These protocols have known cryptographic weaknesses and missing modern primitives. Attackers can downgrade or break the connection, then read or alter traffic that users believe is secure.',
  attack:
    'A network attacker forces a downgrade to TLS 1.0 and exploits known weaknesses (BEAST-style attacks, weak cipher suites) to recover session cookies or inject content.',
  tags: ['tls', 'transport'],
  appliesTo: 'response',
  remediation: remediation(
    `// Node/Express: restrict TLS versions and ciphers on the HTTPS server
import https from 'node:https';

https.createServer({
  key, cert,
  minVersion: 'TLSv1.2',
  ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256',
}, app);`,
    `// Next.js custom server (or your hosting provider's TLS settings)
import { createServer } from 'https';
import next from 'next';

const app = next({ dev: process.env.NODE_ENV !== 'production' });
const server = createServer({ key, cert, minVersion: 'TLSv1.2' }, app.getRequestHandler());`,
    `# nginx: TLS 1.2+ only
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;`,
  ),
  evaluate(ctx) {
    const protocol = ctx.event.tls?.protocol ?? ctx.event.protocol ?? '';
    if (!protocol || !OUTDATED.test(protocol)) return [];
    return [
      {
        key: protocol,
        message: `Negotiated protocol is ${protocol}.`,
        detail: 'TLS 1.2 or 1.3 is required for modern security baselines.',
        evidence: protocol,
      },
    ];
  },
};

export default rule;
