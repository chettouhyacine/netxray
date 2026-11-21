# Writing a NetXRay rule

A rule is a pure function with teaching text attached. Adding one should take a single file and a single test file; the engine, scoring, de-duplication, UI and report all pick it up automatically.

## The contract

```ts
// src/rules/types.ts
export interface Rule {
  id: string;                       // stable, kebab-case, unique
  severity: 'info' | 'low' | 'medium' | 'high';
  title: string;                    // short, specific
  what: string;                     // plain-language definition
  why: string;                      // why the developer should care
  attack: string;                   // one concrete attacker story
  remediation: Remediation[];       // express / nextjs / nginx snippets
  tags: string[];                   // used for filtering and grouping
  appliesTo: 'request' | 'response' | 'document';
  evaluate(ctx: RuleContext): RuleHit[];
}
```

`appliesTo`:
- `document`: only the main HTML document response. Use this for header, cookie and SRI rules.
- `response`: every response, including XHR/fetch/images. Use this for CORS, caching, secrets and errors.
- `request`: every outbound request. Use this for mixed content, third parties and secrets in URLs.

## The context

```ts
interface RuleContext {
  event: NetworkEvent;              // fully normalized request/response
  page: PageContext;                // pageUrl, pageOrigin, isHttps
  cookies: CookieObservation[];     // chrome.cookies for the page (may be empty)
  jwts: DecodedJwt[];               // decoded locally from URL/headers/cookies/bodies
}
```

Useful fields on `NetworkEvent`:

| Field | Notes |
| --- | --- |
| `url`, `method`, `status`, `statusText` | Always present after normalization |
| `pageOrigin`, `resourceType`, `mimeType` | Use `isThirdParty(url, pageOrigin)` from `core/url` |
| `requestHeaders`, `responseHeaders` | Lower-cased keys; duplicate headers are comma-joined |
| `setCookie` | Raw `Set-Cookie` strings, in order |
| `query` | Parsed multi-value query map |
| `timings` | `blocked, dns, tcp, tls, request, wait, download, total` (ms) |
| `sizes` | Request/response headers and body bytes, plus `total` |
| `tls` | Only present when Deep TLS inspection is enabled |
| `responseBodyText` | Only when body capture is on and the type is textual |
| `cookiesObserved` | Cookie attributes from `chrome.cookies` for this page |

## A complete example

```ts
// src/rules/headers/my-header.ts
import { headerRemediation } from '../lib/remediation';
import type { Rule } from '../types';

const rule: Rule = {
  id: 'header-my-header',
  severity: 'low',
  title: 'Missing X-My-Header',
  what: 'The document does not set X-My-Header, which enables ...',
  why: 'Without it, the browser will ...',
  attack:
    'An attacker who can ... uses the missing header to ...',
  tags: ['headers', 'privacy'],
  appliesTo: 'document',
  remediation: headerRemediation({
    header: 'X-My-Header',
    value: 'strict',
  }),
  evaluate(ctx) {
    if (ctx.event.responseHeaders['x-my-header'] === 'strict') return [];
    return [
      {
        key: 'x-my-header',
        message: 'X-My-Header is missing or not "strict".',
        detail: 'Explain here exactly what the browser will do differently.',
        evidence: 'X-My-Header: <absent>',
      },
    ];
  },
};

export default rule;
```

Register it in `src/rules/index.ts`:

```ts
import myHeader from './headers/my-header';

export const rules: Rule[] = [
  // ...
  myHeader,
];
```

Then add its metadata to `src/rules/catalog.ts`:

```ts
'header-my-header': { confidence: 'medium' },
```

Only rules mapped to one of the four v1 attack classes **and** marked `high`
confidence appear in the default view. Everything else runs in extended mode.
A test (`catalog.test.ts`) fails if a registered rule has no metadata, so the
catalog and registry cannot drift.

## Hits and identity

```ts
interface RuleHit {
  key: string;        // what is affected (cookie name, header, host, param…)
  message: string;    // one specific sentence for the UI
  detail?: string;    // extra context, shown under the message
  evidence?: string;  // masked value, never a raw secret
}
```

The engine turns each hit into a `Finding` with `id = ruleId + ':' + key`. Findings are de-duplicated by that id across the whole session, so a rule that fires on every asset appears once. Include the specific object in `key` (`cookie:sid@example.com`, `origin:cdn.example.com`) so genuinely different problems stay separate.

Severity is per rule, not per hit. If two outcomes deserve different severities, write two rules (for example `header-hsts-missing` and `header-hsts-weak`).

## Remediation snippets

Use `remediation(express, nextjs, nginx, notes?)` or `headerRemediation({...})` from `src/rules/lib/remediation.ts`. Every rule should give the three stacks when the fix is realistic; use a short note when a stack cannot implement it (for example, nginx cannot set `HttpOnly` on an upstream cookie). Snippets must be copy-pasteable and safe defaults, not pseudo-code.

## Testing

Use the factories in `src/test-utils.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { cookie, makeContext } from '../../test-utils';
import rule from './my-header';

describe('header-my-header', () => {
  it('flags the missing header', () => {
    expect(rule.evaluate(makeContext())).toHaveLength(1);
  });

  it('accepts the safe value and ignores unrelated cases', () => {
    expect(
      rule.evaluate(makeContext({ responseHeaders: { 'x-my-header': 'strict' } })),
    ).toEqual([]);
  });
});
```

`makeContext({...})` accepts any `Partial<NetworkEvent>` plus an optional cookie array. `makeEvent`/`makeContext` derive the query map from the URL. For JWT tests, use `makeJwt(header, payload)`.

A rule PR needs at least:
1. a positive case,
2. a negative case,
3. one boundary case (missing data, malformed value, wrong resource type, HTTP vs HTTPS).

Run `npm run test`, `npm run coverage`, `npm run typecheck`.

## Correctness rules of thumb

- **Never guess from missing data.** No TLS details → return `[]`. No body → return `[]`. A rule that fires because capture was incomplete erodes trust.
- **Avoid double-reporting.** Header rules usually belong on `document`; cookie rules should read `cookieFacts(ctx)` so they work with either `chrome.cookies` or `Set-Cookie`.
- **Mask evidence.** Use `maskSecret` from `core/redact`.
- **Stay local.** Rules must not fetch, log to remote services, or read extension state.
- **Keep the attacker story concrete.** "An attacker on public Wi-Fi intercepts..." is useful; "attackers can exploit this" is not.
- **Target 60fps.** A rule runs on every event in a worker; keep regexes bounded and avoid quadratic scans of large bodies.

## Review checklist

- [ ] Rule id, title and severity are accurate and unique.
- [ ] `what`/`why`/`attack` explain the issue without jargon.
- [ ] Remediation snippets are valid for the current major versions of Express, Next.js and Nginx.
- [ ] `appliesTo` matches the resource type being examined.
- [ ] `key` distinguishes different affected objects.
- [ ] Evidence is masked; no secrets in tests or fixtures.
- [ ] Positive, negative and edge-case tests exist.
- [ ] Registry and README catalogue updated.
- [ ] Typecheck, lint, tests and coverage pass.
