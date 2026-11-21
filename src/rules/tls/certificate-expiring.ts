import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const WARN_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;

const rule: Rule = {
  id: 'tls-certificate-expiring',
  severity: 'medium',
  title: 'TLS certificate is expiring or expired',
  what: 'The server certificate expires within 14 days, or has already expired.',
  why: 'An expired certificate makes every browser show a full-page security warning. Users are trained to click through those warnings, which is exactly the moment a phishing page becomes indistinguishable from a broken real site.',
  attack:
    'An attacker waits for the certificate to lapse, then serves a look-alike site over HTTP or with a self-signed certificate. Users who are used to ignoring warnings continue and enter credentials.',
  tags: ['tls', 'certificate'],
  appliesTo: 'response',
  remediation: remediation(
    `// Automate renewal (Let's Encrypt + certbot) and reload Node on success
// crontab:
// 0 3 * * * certbot renew --quiet --deploy-hook "systemctl reload my-app"`,
    `// Vercel/Cloudflare manage certificates automatically.
// On a self-hosted Next.js server, renew with certbot and restart:
// certbot renew --deploy-hook "pm2 reload next-app"`,
    `# Let certbot manage nginx and reload automatically
certbot --nginx -d example.com -d www.example.com
# certbot installs a systemd timer that reloads nginx after renewal`,
  ),
  evaluate(ctx) {
    const validTo = ctx.event.tls?.certificate?.validTo;
    if (!validTo) return [];
    const remaining = validTo - Date.now();
    if (remaining > WARN_WINDOW_MS) return [];
    const days = Math.floor(remaining / (24 * 60 * 60 * 1000));
    return [
      {
        key: `expiry:${validTo}`,
        message:
          remaining <= 0
            ? `The certificate expired ${Math.abs(days)} day(s) ago.`
            : `The certificate expires in ${days} day(s).`,
        detail: 'Renew before expiry; browsers will block the site once it lapses.',
        evidence: new Date(validTo).toISOString(),
      },
    ];
  },
};

export default rule;
