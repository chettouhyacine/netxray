import { headerRemediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'header-permissions-policy-missing',
  severity: 'info',
  title: 'Missing Permissions-Policy',
  what: 'The page does not restrict powerful browser features (camera, microphone, geolocation, payment, clipboard) with a Permissions-Policy header.',
  why: 'Restricting features means an injected or third-party iframe cannot silently ask for the camera or location. It also documents which capabilities your app actually uses.',
  attack:
    'A malicious embedded iframe or a compromised script calls getUserMedia or geolocation. Without a policy, the browser shows a permission prompt that a rushed user may accept.',
  tags: ['headers', 'privacy'],
  appliesTo: 'document',
  remediation: headerRemediation({
    header: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), payment=()',
    expressCode: `app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  );
  next();
});`,
    nginxCode: `add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()" always;`,
  }),
  evaluate(ctx) {
    if (ctx.event.responseHeaders['permissions-policy']) return [];
    return [
      {
        key: 'permissions-policy',
        message: 'No Permissions-Policy header.',
        detail: 'Powerful features stay available to any embedded origin.',
      },
    ];
  },
};

export default rule;
