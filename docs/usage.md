# NetXRay User Guide

NetXRay is a browser extension for developers. It adds a panel to Chrome DevTools that shows, request by request, what your web application sends over the network, where the time goes, and which parts of that traffic are insecure. Every finding says what triggered it, why it matters and how to fix it.

It runs entirely on your machine. There is no account, no telemetry, and the extension makes no network calls of its own.

**Built for developers only.** NetXRay is a debugging and review tool for people who build and ship web applications. It is not end-user software, and it must only be used on sites you own or have explicit permission to test.

---

## 1. What NetXRay is, and what it is not

| It is | It is not |
| --- | --- |
| A DevTools panel that reads the traffic the current browser tab already made | A scanner that crawls the internet or tests sites in the background |
| A plain-language explanation of each request: phases, headers, cookies, bodies | A replacement for a professional penetration test |
| A checklist of four real attack classes with direct evidence behind each one | A compliance certificate or a security guarantee |
| A local analyzer with exportable reports for PRs and tickets | A proxy that intercepts other apps or other machines |
| A learning tool for developers who have never had to reason about the wire | An analytics, monitoring or ad-blocking product |

If a page loads in the tab you are inspecting, NetXRay can explain it. If it does not, NetXRay never sees it.

---

## 2. When you need it

Use NetXRay when you are working on a web app and any of these are true:

1. **You are shipping a login or session feature.** It confirms your session cookie is `HttpOnly` and `Secure`, and that it is not readable by page scripts.
2. **Your frontend calls an API on another origin.** It shows exactly what `Access-Control-Allow-Origin` your server returns, and whether an arbitrary site could read authenticated responses.
3. **You added a header, cookie or CORS rule and want proof it works.** Capture before and after, and attach both HTML reports to the pull request.
4. **You suspect a page can be framed by another site.** It checks `X-Frame-Options` and `frame-ancestors` on the actual document response.
5. **You are auditing what third parties your page loads.** The Map view lists every domain, its traffic share and its worst finding.
6. **You need to explain a performance problem.** The Timeline splits each request into DNS, connect, TLS, waiting and download, so you can say whether the time is your server or the plumbing.
7. **You joined an unfamiliar codebase.** Open the app, walk one flow, and you have a map of its services, cookies and API surfaces.
8. **You want to teach someone what "insecure cookie" or "open CORS" actually means.** Every finding has a plain-English explanation and a fix snippet.

Typical moment: a feature is about to merge, and someone asks "is this safe?". NetXRay gives you a concrete answer with evidence you can paste into the review.

---

## 3. When you should not use it

- On a site you do not own and have no written permission to test. Inspecting your own browser traffic is legal in most places, but acting on another company's site is not your call.
- As your only security review. It sees what reaches the browser, so server-side issues that never appear on the wire are invisible.
- On native mobile or desktop apps. This is a browser extension for web pages.
- To capture real customer data. Bodies and headers can contain personal data; keep captures local and do not attach raw HAR files to public tickets.

---

## 4. What you need

- A Chromium browser: Chrome 116+, Microsoft Edge, Brave, Opera or Vivaldi. Firefox and Safari work through HAR import (section 15).
- The application you want to inspect, open in that browser.
- Two minutes for the first run.
- Node 20+ only if you build the extension from source.

---

## 5. Install

### From the zip (what testers get)

1. Unzip `netxray-0.2.0.zip` to a permanent folder, for example `Documents\netxray`. Do not run it from inside the zip or from a temporary Downloads folder.
2. Open `chrome://extensions`, `edge://extensions`, `brave://extensions`, `opera://extensions` or `vivaldi://extensions`.
3. Turn on **Developer mode** in the top-right corner.
4. Click **Load unpacked** and select the unzipped folder (the one that contains `manifest.json`).
5. The card appears with the version number. If it does not, the folder you picked is one level too deep.
6. Open DevTools on any page (**F12** or **Ctrl+Shift+I**), then click **⋮ → More tools → NetXRay**.

Unsigned extensions always need Developer mode. That is expected, not a warning about the tool.

### From source

```bash
npm install
npm run build
```

Then load the generated `dist/` folder with **Load unpacked**, exactly as above.

### Updating

Build or unzip the new version, then click the reload icon on the extension card in `chrome://extensions` and reopen DevTools. A stale `dist/` is the most common reason the panel looks unchanged after an update.

### Removing

Click **Remove** on the extension card. Nothing is left behind except the folder you unzipped.

---

## 6. The 60-second version

1. Open your app in Chrome or Edge.
2. Open DevTools, then **More tools → NetXRay**.
3. **Reload the page** with the panel open. This step is required: the panel only sees requests made after it starts.
4. Read the score in the top bar. Anything below 100 has findings listed in **Security**.
5. Open the slowest request in **Timeline** to see where its time went.
6. Click **Export ▾ → Shareable HTML report** when you want to share the result.

---

## 7. Five minutes with the demo: a real problem and its fix

The repo ships a deliberately insecure demo so you can see the difference a fix makes.

1. Start it: `npm run demo`, then open <http://localhost:4000/vulnerable/>.
2. Open DevTools → **More tools → NetXRay**.
3. Reload the page with the panel open.
4. **Timeline**: requests stream in with real phase timings.
5. **Security**: the score is well below 100. You should see findings from the four v1 attack classes: session hijacking, cross-origin data theft, clickjacking and credential leakage.
6. Open one finding and read the four sections: what it is, why it matters, how an attacker uses it, how to fix it.
7. Now open <http://localhost:4000/fixed/> (or run `npm run demo:fixed`) and repeat. Same app, same traffic shape, findings gone and the score back at 100.

That before and after is the product in one gesture: the difference between the two pages is the exact change you are being asked to make.

---

## 8. Using it on your own app, step by step

This is the routine to follow every time.

**Step 1. Open the page and the panel.** NetXRay starts capturing when the panel opens.

**Step 2. Reload the page, then walk the flow you care about.** Log in, load the dashboard, save a record, upload a file. Each thing you do is captured as it happens. A full page navigation starts a new session; a single-page app keeps one session as you navigate.

**Step 3. Read Security first.** Fix high-severity findings before anything else. Start with session cookies and CORS: those are the ones with real attacker stories. Click each finding, read the fix, and keep the report for the PR.

**Step 4. Read Timeline second.** Find the slowest request and look at its bars. A long **Waiting** bar is your server. A long DNS, connect or TLS bar before a small response is connection overhead, often a missing keep-alive or too many third-party origins. A long **Download** bar with few bytes means a slow or streamed connection.

**Step 5. Read Map third.** Confirm that every third-party origin is one you intend to trust. Anything unexpected is either a dependency you forgot or a script you did not add.

**Step 6. Read Storage fourth.** Check cookie flags on the origin you are actually reviewing, including subdomains. Read `localStorage` and `sessionStorage` only if you need to see what the app keeps client-side.

**Step 7. Capture before and after.** Make your fix, rebuild your backend, reload, and export the HTML report again. Attaching both reports to a pull request is the most persuasive evidence you can give a reviewer.

### What good looks like

- Score 100 with no v1 findings in the Security view.
- Session cookies show `HttpOnly`, `Secure` and an appropriate `SameSite`.
- No reflected `Origin` in CORS responses, and no wildcard origin combined with credentials.
- The document response carries either an effective `X-Frame-Options` or a `frame-ancestors` directive.
- No tokens, API keys or passwords in URLs or response bodies.
- Every domain in the Map view is one you can name and justify.

---

## 9. The top bar

| Element | What it does |
| --- | --- |
| **score NN/100** | Live score for the captured page. Red, amber or green. |
| **N high** | Count of high-severity findings. |
| **v1 · 4 attacks** / **all checks** | Which detection mode is active. Change it in Security or Settings. |
| **Timeline / Map / Security / Storage** | The four views, each with a live count badge. |
| **Filter requests** | Filters the timeline by URL, method, status or type. Shortcut: `/`. |
| **Teach me** | Adds a plain-English line under every network phase. Shortcut: `t`. |
| **Export ▾** | HTML report, JSON report, HAR export and HAR import. |
| **☀ / ☾** | Light or dark theme. |
| **⚙** | Settings: detection, TLS, capture, privacy, replay tour. |
| **⨯** | Clears the current session (it asks first). Nothing is sent anywhere. |

---

## 10. Timeline: where the time actually goes

Each row is one request. The bar on the right is not a single duration: it is split into the phases the browser actually measured.

| Phase | What it means |
| --- | --- |
| **Queued / blocked** | The browser held the request: connection limit, priority or cache check. |
| **DNS** | Turning the hostname into an IP address. |
| **TCP** | Opening the connection to the server. |
| **TLS** | The encrypted handshake. Absent on plain HTTP. |
| **Request** | Uploading headers and body. |
| **Waiting (TTFB)** | The server thinking. Usually the biggest bar on a slow page. |
| **Download** | Receiving the response. |

Click any row to open the drawer:

- **Overview**: URL, method, status, protocol, IP, size, cache status and total time.
- **Timing**: every phase with its duration, plus the Teach me explanation when it is on.
- **Headers**: request and response headers. `Authorization` and `Cookie` stay masked until you click to reveal.
- **Body**: the response body as text, truncated at 256 KB. Recognized secrets are masked.

The strip above the list summarizes the session: total requests, bytes, domain count and how many are third-party, slowest request and finding count.

---

## 11. Security: the four claims v1 makes

The score starts at 100 and loses points for each distinct rule that fires; repeats of the same finding count for less. It is a teaching aid that reflects this page's network behavior. It is not a penetration test and not a compliance result.

In v1 mode NetXRay reports only four attack classes, and only at high confidence. Each one requires direct evidence on the wire.

| Attack class | What the panel must see | Why it matters | First fix to try |
| --- | --- | --- | --- |
| **Session hijacking** | A session-like cookie readable by page scripts, or a session cookie without `Secure` on an HTTPS page | Any XSS becomes full account takeover; an insecure cookie can travel over plain HTTP | Set `HttpOnly` and `Secure` on session cookies, and use `SameSite=Lax` or `Strict` |
| **Cross-origin data theft** | A reflected `Origin` in `Access-Control-Allow-Origin`, or `*` combined with credentials | A reflected origin lets any site read authenticated responses from your API | Allowlist known origins instead of reflecting the request origin |
| **Clickjacking** | A document with no effective `X-Frame-Options` and no restricting `frame-ancestors` | An attacker frames your page invisibly and tricks a logged-in user into clicking | Send `X-Frame-Options: DENY` or a `frame-ancestors` CSP directive |
| **Credential leakage** | A secret in a URL or response body, an unsigned JWT (`alg: none`), or sensitive claims in a JWT payload | URLs end up in logs, Referer headers, history and screenshots; unsigned tokens can be forged | Move secrets to headers or a backend, and reject unsigned tokens |

### How to act on a finding

1. Read **what it is** and **why it matters** so you can explain it to your team.
2. Check the evidence. NetXRay names the request, header or cookie that triggered it, so you can confirm it yourself.
3. Apply the fix from the drawer. Snippets are provided for Express, Next.js and Nginx.
4. Reload and re-check. The finding should disappear from the list and the score should move.
5. Export the HTML report and attach it to the pull request or ticket.

### Working the list

- Filter by **severity** or by **attack class**. The chips carry live counts.
- Each finding shows its rule id and confidence, so you can look up exactly what fired.
- Findings are deduplicated by occurrence, not silently repeated dozens of times.

### Extended checks

Tick **Extended checks** in the Security view (or Settings → Detection) to run all 34 rules: full cookie flags, CSP, HSTS, `nosniff`, Referrer-Policy, Permissions-Policy, mixed content, TLS details, cache policy, third-party inventory and SRI.

Treat those as review prompts, not attack claims. That is exactly why they are off by default.

---

## 12. Map: who your page talks to

A force-directed graph: your page in the middle, every domain it contacted around it. Node size tracks traffic, node colour tracks the worst finding on that domain, and edge width tracks bytes.

Use it to answer "what did we just load?" and to spot third-party origins you forgot about. Click a domain to jump to a matching request.

---

## 13. Storage: cookies and web storage

**Cookies** are read from the browser for the inspected origin, on demand with **Refresh cookies**. Each row shows the name, the value (masked), domain and path scope, flags, and a risk badge: missing `HttpOnly`, missing `Secure`, weak `SameSite`, overly wide domain scope, or **hardened** when nothing is wrong.

**localStorage / sessionStorage** are read only when you press **Read page storage**. Nothing is scraped automatically, no page script is evaluated, values are truncated to 500 characters and masked until you reveal them.

---

## 14. Exporting and sharing

The **Export ▾** menu has four entries:

| Option | Use it for |
| --- | --- |
| **Shareable HTML report** | One self-contained file with inline CSS and JS and zero external requests. Attach it to a ticket or PR. Give this to a teammate who does not have the extension. |
| **JSON report** | Score, findings and normalized events with secrets masked, for scripting or diffing. |
| **HAR (full capture)** | The standard format for other tools. It contains raw data, so treat it as sensitive. |
| **Import HAR from any browser…** | Analyze someone else's capture, or your own from Firefox or Safari. |

Reports mask recognized secrets, but they still describe your infrastructure. Do not post them publicly by default.

---

## 15. Firefox and Safari

Those browsers cannot run a Chrome DevTools extension, so there is nothing to install. The analyzer takes data in and produces findings out, so you feed it a HAR file:

1. Firefox: DevTools → **Network** → **Export HAR**. Safari: **Develop → Show Web Inspector → Network → Export**.
2. Open NetXRay in Chrome or Edge (the demo page works too) → **Export ▾ → Import HAR from any browser…**
3. Pick the file. The timeline, all four v1 attack checks, the extended rules and every export format run on that capture, with the same redaction.

A notice confirms how many requests were imported and how many entries were skipped as unusable.

---

## 16. Settings

- **Deep TLS inspection**: off by default. Turning it on requests the powerful `debugger` permission, and Chrome shows its "started debugging" infobar. It adds protocol version, cipher suite and certificate validity. Without it, TLS rules stay quiet. You can disable it at any time; denying the permission leaves everything else working.
- **Detection**: the extended-checks toggle, plus why v1 is deterministic. There is no machine learning in v1: there is no labelled corpus to train on, and a developer needs a defensible reason for every finding more than extra coverage. The confidence catalog is the seam where ML can be added later.
- **Capture**: capture response bodies, text and JSON only, capped at 256 KB. Body checks need this. Bodies are never written to session storage.
- **Theme**: light or dark.
- **Replay the tour**: reruns the first-run walkthrough.

---

## 17. Keyboard shortcuts

| Key | Action |
| --- | --- |
| `1` `2` `3` `4` | Timeline · Map · Security · Storage |
| `j` / `k` | Next / previous request |
| `/` | Focus the request filter |
| `t` | Toggle Teach me |
| `Esc` | Close the drawer, then settings, then blur the filter |

---

## 18. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Panel is empty | Requests must happen after the panel opens. Reload the page with the panel visible. |
| Panel does not appear in More tools | The extension is not loaded, or `dist/` is stale. Run `npm run build`, reload the extension card, reopen DevTools. |
| No findings at all | The page may genuinely be clean for the four v1 classes, or the document response was not captured. Enable **Extended checks** and reload. |
| Cookie rules never fire | Cookies are read per origin. The site may set none, or host access may be missing. Check Storage → Refresh cookies. |
| TLS findings absent | Deep TLS inspection is off. Settings → Deep TLS inspection → Enable. |
| Body checks absent | Capture bodies is off, or the response had no readable body. |
| Storage read fails | It cannot run on `chrome://` pages or some protected pages, and needs the DevTools panel context. |
| The panel looks the same after an update | Reload the extension in `chrome://extensions`, then reopen DevTools. |

---

## 19. Privacy, permissions and safe use

- All analysis runs in a Web Worker inside the panel. There is no telemetry and the extension makes no outbound requests of its own.
- Captured data lives in DevTools memory, plus a crash-recovery snapshot in `chrome.storage.session` that Chrome clears when the browser closes. Bodies are never persisted.
- Permissions are narrow and each one is justified in the README: `cookies` (attributes only, never written), `storage`, `scripting` (only on the explicit storage-read click) and optional `debugger`.
- Use it only on applications you own or are explicitly authorized to test.

The honest scope of v1: four attack classes, reported only on direct evidence, with a labelled precision and recall test behind each claim. Everything else is available as an extended check instead of being silently dropped. That is a deliberate trade, fewer findings but each one defensible, not a claim that the extended checks are harmless.

---

## 20. Glossary

| Term | Meaning |
| --- | --- |
| **HAR** | HTTP Archive, a JSON file that records requests and responses. Every major browser can export one. |
| **Origin** | Scheme, host and port: `https://app.example.com:443`. Two pages with different origins are different sites to the browser. |
| **CORS** | Cross-Origin Resource Sharing. Response headers that decide whether another origin may read the response. |
| **`Access-Control-Allow-Origin`** | The CORS header naming which origin may read the response. A reflected value trusts whoever asked. |
| **TTFB** | Time To First Byte, the wait between sending the request and the first byte coming back. |
| **`HttpOnly`** | A cookie flag that hides the cookie from `document.cookie`, so XSS cannot read it. |
| **`Secure`** | A cookie flag that restricts the cookie to HTTPS. |
| **`SameSite`** | A cookie flag controlling whether the cookie is sent on cross-site requests. `Lax` or `Strict` limit CSRF. |
| **`X-Frame-Options`** | A response header that stops a page from being framed by another site. |
| **`frame-ancestors`** | The CSP directive that replaces `X-Frame-Options` and lists which origins may frame the page. |
| **CSP** | Content Security Policy, a header that limits which scripts and resources a page may load. |
| **HSTS** | Strict-Transport-Security, a header that forces HTTPS for future visits. |
| **JWT** | JSON Web Token, a signed token often used for sessions. `alg: none` means it is not signed at all. |
| **SRI** | Subresource Integrity, a hash on a third-party script so a changed file is refused. |
| **Third-party origin** | Any domain other than the one you are inspecting. |
