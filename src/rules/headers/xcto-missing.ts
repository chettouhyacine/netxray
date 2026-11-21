import { headerRemediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'header-xcto-missing',
  severity: 'low',
  title: 'Missing X-Content-Type-Options: nosniff',
  what: 'The response does not set X-Content-Type-Options: nosniff, so the browser may guess a file’s type instead of trusting the declared Content-Type.',
  why: 'MIME sniffing lets an uploaded file that is served as text/plain be interpreted as HTML or JavaScript. nosniff is one line of defence with essentially no downside.',
  attack:
    'A user uploads an "image" containing HTML/JS. It is served without nosniff, the browser sniffs it as HTML, and the payload runs on your origin with the victim’s cookies.',
  tags: ['headers', 'content'],
  appliesTo: 'document',
  remediation: headerRemediation({
    header: 'X-Content-Type-Options',
    value: 'nosniff',
    expressCode: `app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});`,
  }),
  evaluate(ctx) {
    const value = ctx.event.responseHeaders['x-content-type-options'];
    if (value && value.toLowerCase().includes('nosniff')) return [];
    return [
      {
        key: 'nosniff',
        message: value ? `X-Content-Type-Options is "${value}", not "nosniff".` : 'X-Content-Type-Options is missing.',
        detail: 'The browser may sniff uploads as HTML or JavaScript.',
      },
    ];
  },
};

export default rule;
