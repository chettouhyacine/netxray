# Contributing to NetXRay

Thanks for helping make network behaviour easier to understand. This project values small, well-tested changes and plain-language explanations over clever abstractions.

## Getting started

```bash
git clone <your-fork>
cd netxray
npm install
npm run build
```

Load `dist/` as an unpacked extension in `chrome://extensions` (Developer mode on). Open DevTools → ⋮ → More tools → NetXRay.

Useful commands:

| Command | What it does |
| --- | --- |
| `npm run dev` | Vite dev server for fast panel UI iteration |
| `npm run build` | Production build of panel pages + service worker into `dist/` |
| `npm run test` | Vitest unit tests |
| `npm run coverage` | Coverage with enforced thresholds on `src/rules` and `src/core` |
| `npm run typecheck` | Strict TypeScript, no emit |
| `npm run lint` | ESLint 9 flat config |
| `npm run e2e` | Playwright tests (demo server starts automatically) |
| `npm run demo` | Vulnerable demo app on <http://localhost:4000> |

## Project conventions

- **One rule, one file, one test.** A rule lives in `src/rules/<group>/<name>.ts` with a matching `<name>.test.ts`; register it in `src/rules/index.ts`. Adding a rule should not require touching the UI.
- **Plain data only.** The analysis layer works on `NetworkEvent` and returns `Finding` objects. No DOM, no `chrome.*`, no I/O inside rules.
- **Strict TypeScript.** No `any`. Prefer narrow types and early returns.
- **Untrusted input is data.** Never render captured strings with `dangerouslySetInnerHTML`, never `eval`, and mask secrets with the helpers in `src/core/redact.ts`.
- **No new dependencies without a reason.** The bundle is deliberately small; explain the trade-off in the PR.
- **Explain, don't lecture.** Every rule needs a concrete attacker story and a copy-ready fix.

## Adding a security rule

1. Read [`docs/rule-authoring.md`](docs/rule-authoring.md).
2. Implement `evaluate(ctx)` so it returns `[]` when the rule does not apply.
3. Choose a stable `key` inside each hit (cookie name, header name, host, rule-specific identity). Duplicate keys are de-duplicated session-wide.
4. Cover at least: one positive, one negative, and one boundary case.
5. Add the rule to the registry and to the README catalogue table.
6. Run `npm run test && npm run typecheck && npm run lint`.

Rules must avoid false confidence: if data is unavailable (for example no TLS details because the debugger is off), return no hits instead of guessing.

## Pull requests

- Keep the diff focused; unrelated refactors belong in a separate PR.
- Describe the user-visible change and how you verified it. For UI changes, include a screenshot or a short recording.
- Add tests for behaviour changes. A bug fix should include a regression test.
- Update the README or docs when you add a rule, permission or command.
- CI must pass: typecheck, lint, unit tests with coverage, build, and Playwright E2E.

## Reporting bugs and security issues

For ordinary bugs, open an issue with Chrome version, extension version, reproduction steps, and (if possible) a minimal demo page. Redact any tokens or personal data before pasting a HAR or screenshot.

For a vulnerability **in NetXRay itself**, do not open a public issue. Email the maintainers with a description and reproduction, or use GitHub's private vulnerability reporting if enabled. Please give us a reasonable window to fix it before disclosure.

## Code of conduct

Be kind and assume good intent. This is a teaching tool; questions about why a finding matters are always welcome.
