import { headerRemediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'header-referrer-policy-missing',
  severity: 'low',
  title: 'Referrer-Policy leaks URLs to other sites',
  what: 'The response does not set a Referrer-Policy, or sets one that leaks full URLs (unsafe-url, no-referrer-when-downgrade).',
  why: 'The Referer header sends the current URL to every third party. URLs often contain account ids, search terms, password-reset tokens and internal paths, and the browser default varies across clients.',
  attack:
    'A password-reset link such as /reset?token=… loads a support-chat widget. The full URL, including the reset token, arrives in that third party’s Referer header and logs.',
  tags: ['headers', 'privacy'],
  appliesTo: 'document',
  remediation: headerRemediation({
    header: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  }),
  evaluate(ctx) {
    const value = (ctx.event.responseHeaders['referrer-policy'] ?? '').toLowerCase();
    if (!value) {
      return [
        {
          key: 'missing',
          message: 'No Referrer-Policy header.',
          detail: 'The browser default differs between clients; set it explicitly.',
        },
      ];
    }
    if (value.includes('unsafe-url') || value.includes('no-referrer-when-downgrade')) {
      return [
        {
          key: `weak:${value}`,
          message: `Referrer-Policy is "${value}", which leaks full cross-site URLs.`,
          detail: 'Prefer strict-origin-when-cross-origin.',
          evidence: value,
        },
      ];
    }
    return [];
  },
};

export default rule;
