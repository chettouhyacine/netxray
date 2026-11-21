import { hostOf } from '../../core/url';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

/** RFC 6125-style single-label wildcard matching. */
export function matchesHostname(pattern: string, host: string): boolean {
  const normalizedPattern = pattern.toLowerCase().replace(/\.$/, '');
  const normalizedHost = host.toLowerCase().replace(/\.$/, '');
  if (!normalizedPattern || !normalizedHost) return false;
  if (!normalizedPattern.includes('*')) return normalizedPattern === normalizedHost;
  if (!normalizedPattern.startsWith('*.')) return false;
  const suffix = normalizedPattern.slice(1); // ".example.com"
  if (!normalizedHost.endsWith(suffix)) return false;
  const label = normalizedHost.slice(0, -suffix.length);
  return label.length > 0 && !label.includes('.');
}

const rule: Rule = {
  id: 'tls-hostname-mismatch',
  severity: 'high',
  title: 'Certificate does not match the hostname',
  what: 'The certificate presented by the server is valid for a different hostname, or the captured TLS data cannot be matched to this host.',
  why: 'The hostname is the part of the certificate that ties the encrypted channel to the site you think you are visiting. A mismatch means you may be talking to a different server, and a man-in-the-middle can read and modify everything.',
  attack:
    'An attacker with a valid certificate for attacker.example intercepts traffic to your domain and presents that certificate. Without a hostname check the encrypted tunnel terminates at the attacker, who relays the content and records credentials.',
  tags: ['tls', 'certificate', 'mitm'],
  appliesTo: 'response',
  remediation: remediation(
    `// Ensure the certificate's SAN list contains the exact host you serve.
// On Node, terminate TLS with the right certificate per hostname:
const options = { key: keyFor(host), cert: certFor(host), minVersion: 'TLSv1.2' };`,
    `// With a custom Next.js server, use SNI to choose the certificate:
const tls = require('node:tls');
tls.createServer({ SNICallback: (servername, cb) => cb(null, contextFor(servername)) });`,
    `# nginx: one server block per hostname, each with its own certificate
server {
  listen 443 ssl;
  server_name example.com;
  ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
}`,
  ),
  evaluate(ctx) {
    const certificate = ctx.event.tls?.certificate;
    if (!certificate) return [];
    const host = hostOf(ctx.event.url);
    if (!host) return [];
    const names = [certificate.subjectName, ...(certificate.sanList ?? [])].filter(
      (name): name is string => typeof name === 'string' && name.length > 0,
    );
    if (names.length === 0) return [];
    if (names.some((name) => matchesHostname(name, host))) return [];
    return [
      {
        key: `mismatch:${host}`,
        message: `Certificate names (${names.slice(0, 3).join(', ')}) do not match ${host}.`,
        detail: 'This can indicate a misconfigured virtual host or an interception proxy.',
        evidence: names.slice(0, 5).join(', '),
      },
    ];
  },
};

export default rule;
