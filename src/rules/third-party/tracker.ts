import { hostOf } from '../../core/url';
import { trackerForHost } from '../lib/trackers';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'third-party-tracker',
  severity: 'low',
  title: 'Known tracker or analytics domain contacted',
  what: 'The page talks to a domain on the well-known analytics/advertising/session-replay list.',
  why: 'Trackers receive URLs, referrers, user identifiers and sometimes form data. They widen your attack surface, add third-party code you do not control, and create GDPR/consent obligations.',
  attack:
    'A compromised tag on the tracker’s CDN runs arbitrary JavaScript in your page with access to the DOM and any token in localStorage, exactly like a supply-chain XSS.',
  tags: ['third-party', 'privacy'],
  appliesTo: 'request',
  remediation: remediation(
    `// Express: add a Consent Management Platform gate and a strict CSP allow-list
// Only load analytics after the user opts in.
app.get('/', (req, res) => {
  res.setHeader(
    'Content-Security-Policy',
    "script-src 'self' https://consented-analytics.example.com",
  );
  res.render('index', { analyticsConsent: req.cookies.analytics_consent === 'true' });
});`,
    `// Next.js: load analytics only after consent, via next/script
import Script from 'next/script';

export default function Layout({ consent }: { consent: boolean }) {
  return consent ? <Script src="/vendor/analytics.js" strategy="afterInteractive" /> : null;
}`,
    `# nginx: allow-list third-party calls at the CSP layer
add_header Content-Security-Policy "connect-src 'self' https://api.example.com" always;`,
  ),
  evaluate(ctx) {
    const host = hostOf(ctx.event.url);
    if (!host) return [];
    const tracker = trackerForHost(host);
    if (!tracker) return [];
    return [
      {
        key: `tracker:${tracker}`,
        message: `${host} is a known tracking/analytics domain.`,
        detail: 'Review whether this data collection is necessary, consented and covered by your privacy policy.',
      },
    ];
  },
};

export default rule;
