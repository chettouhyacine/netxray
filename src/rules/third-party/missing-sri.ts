import { extractExternalTags } from '../lib/html';
import { remediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'missing-sri',
  severity: 'medium',
  title: 'External script or stylesheet without Subresource Integrity',
  what: 'The HTML loads a script or stylesheet from another origin without an `integrity` attribute.',
  why: 'SRI pins the exact bytes of a third-party file. Without it, whoever controls that CDN or file can silently change the code that runs on your page, and the browser has no way to detect it.',
  attack:
    'The attacker gains write access to a third-party CDN (or hijacks its DNS) and replaces a library file with a keylogger. Every visitor’s browser loads the modified file and runs it with full page access.',
  tags: ['third-party', 'supply-chain'],
  appliesTo: 'document',
  remediation: remediation(
    `<!-- Express (EJS/Pug): add integrity + crossorigin to every external asset -->
<script
  src="https://cdn.jsdelivr.net/npm/htmx.org@1.9.12/dist/htmx.min.js"
  integrity="sha384-<hash>"
  crossorigin="anonymous"></script>`,
    `// Next.js: use next/script with integrity where the CDN provides a stable hash
import Script from 'next/script';

<Script
  src="https://cdn.jsdelivr.net/npm/htmx.org@1.9.12/dist/htmx.min.js"
  integrity="sha384-<hash>"
  crossOrigin="anonymous"
  strategy="afterInteractive"
/>;`,
    `# nginx: self-host third-party assets (best option) or proxy them with a pinned version
location /vendor/ {
  proxy_pass https://cdn.jsdelivr.net/npm/htmx.org@1.9.12/dist/;
}`,
  ),
  evaluate(ctx) {
    if (ctx.event.resourceType !== 'document') return [];
    if (!ctx.event.responseBodyText) return [];
    if (!/html/i.test(ctx.event.mimeType)) return [];
    return extractExternalTags(ctx.event.responseBodyText, ctx.event.url)
      .filter((tag) => !tag.hasIntegrity)
      .map((tag) => ({
        key: `${tag.tag}:${tag.url}`,
        message: `External ${tag.tag} from ${new URL(tag.url).hostname} has no integrity attribute.`,
        detail: 'Pin the file with SRI and crossorigin="anonymous", or self-host it.',
        evidence: tag.url,
      }));
  },
};

export default rule;
