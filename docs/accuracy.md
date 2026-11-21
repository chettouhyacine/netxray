# Accuracy in v1

V1 makes four attack claims. Anything outside those four is an **extended
check**, available on request but hidden by default. That boundary is the main
accuracy decision: a short list of direct, explainable findings is more useful
than a long list that mixes confirmed issues with review prompts.

## The four claims and the evidence behind them

| Attack class | A finding requires | Rules |
| --- | --- | --- |
| Session hijacking | A session-like cookie is readable by scripts (`HttpOnly` absent), or the page is HTTPS and a session-like cookie lacks `Secure` | `cookie-session-js-readable`, `cookie-missing-secure` |
| Cross-origin data theft | The response echoes the caller's `Origin` (not the page's own), or sends `Access-Control-Allow-Origin: *` with `Allow-Credentials: true` | `cors-reflected-origin`, `cors-wildcard-credentials` |
| Clickjacking | An HTML document has neither `X-Frame-Options: DENY/SAMEORIGIN` nor an effective `frame-ancestors` directive | `header-frame-options-missing` |
| Credential leakage | A credential-shaped value is in a URL, a known key/private-key/database-URL shape is in a body, or a JWT is unsigned (`alg=none`) or carries sensitive claims | `secret-in-url`, `secret-in-response`, `jwt-alg-none`, `jwt-sensitive-payload` |

Each mapped rule is `high` confidence. Rules that are useful but easier to
misread are `medium`/`low` and stay in extended mode: generic cookie flags,
`SameSite` defaults, missing CSP/HSTS, TLS details, third-party inventory,
server banners and cache policy.

## Precision: how false positives are controlled

- **Direct evidence only.** A rule returns `[]` when the data it needs was not
  captured (no body, no TLS details, no cookie attributes). Missing evidence is
  never treated as a finding.
- **No duplicate claims.** A signed JWT in a token response is not reported as
  a leaked secret; the JWT rules inspect its algorithm, lifetime and claims
  instead. Preference cookies missing `Secure` are not reported as session
  hijacking.
- **Framing is parsed, not keyword-matched.** `frame-ancestors *`,
  `frame-ancestors https:` and the obsolete `X-Frame-Options: ALLOW-FROM` are
  treated as ineffective, not as protection.
- **Same-origin CORS is normal.** Reflecting the page's own origin is not
  reported; only a different origin is.
- **Repeats do not amplify.** A finding has one entry per affected object and
  an occurrence count. Raw URLs are never copied into the detail text, so a
  token in a URL cannot leak through de-duplication.
- **No machine learning in v1.** There is no labelled traffic corpus to train
  on, and a model would make a finding harder to explain and easier to tune
  into false confidence. The `src/rules/catalog.ts` confidence layer is the
  seam where a local model can be evaluated later, against the same benchmark.

## Recall: how false negatives are controlled

- Every v1 attack class has a labelled positive in the benchmark.
- Cookie features fall back from `chrome.cookies` to `Set-Cookie` headers when
  cookie access is unavailable, so the check still runs.
- The benchmark includes the evasions that a keyword check would miss:
  `frame-ancestors *`, scheme-only sources and `ALLOW-FROM`.
- Reachability limits are stated instead of hidden: response bodies are needed
  for secret/JWT body checks, and imports include bodies when the HAR contains
  them.

## The labelled benchmark

`src/core/accuracy.test.ts` defines two profiles of the same app:

- **vulnerable**: one deliberate example of each v1 attack;
- **hardened**: the same traffic after the documented fixes.

The test asserts:

- **recall 100%**: all 9 labelled rule hits are found;
- **precision 100%**: no finding outside the labels;
- **zero findings** and a score of 100 on the hardened profile;
- no claim for preference cookies, same-origin CORS echoes or correctly signed
  short-lived tokens.

A new noisy rule, or a regression that silently stops detecting one of the four
attacks, fails `npm test`. That is the precision/recall guarantee v1 ships
with, and the number to improve in v2.

## Residual limits

- **Business intent is invisible.** A page may intentionally be frameable (an
  embeddable widget). v1 reports the technical condition and explains the risk;
  it cannot know the product decision.
- **Only what the browser received.** Server-side configuration that never
  reaches the wire cannot be judged.
- **Bodies are best-effort.** Cached, streaming, binary and opaque responses may
  have no body; body-based checks then stay quiet rather than guess.
- **Cookie attributes depend on access.** Without cookie permissions the panel
  falls back to `Set-Cookie`, which does not show attributes inherited from an
  earlier response.

If a finding is wrong, include the HAR (redacted) and the rule id in an issue.
If an attack is missed, include the HAR and the expected attack class. That
case becomes a benchmark fixture before any rule change.
