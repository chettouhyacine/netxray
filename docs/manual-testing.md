# Manual verification checklist

Playwright cannot attach to Chrome's DevTools frontend, so this checklist covers the one part automation cannot: capturing a live page through the actual panel. Run it before a release, against the demo app.

## Setup

```bash
npm install
npm run build
npm run demo
```

1. `chrome://extensions` → Developer mode → **Load unpacked** → `dist/`.
2. Open <http://localhost:4000/vulnerable/> and open DevTools → ⋮ → More tools → NetXRay.
3. Reload the page with the panel open.

## Capture and timeline

- [ ] Requests appear within a second of reload; document, script, fetch and image types are all present.
- [ ] The waterfall bars show distinct DNS/TCP/TLS/WAIT/RECEIVE phases and look proportional to the durations.
- [ ] Filtering by URL, method, status and type works; the list scrolls smoothly with a large page.
- [ ] Clicking a row opens the detail drawer; the packet animates and the phase highlight follows it.
- [ ] **Teach me** shows one explanation per phase in both the drawer and the timing tab.
- [ ] Overview shows protocol, IP, size, cache status and TTFB-derived total.
- [ ] Headers tab masks `Authorization` and `Cookie` until clicked; reveal/hide works.
- [ ] Body tab renders JSON/HTML as text, masks test secrets, and notes truncation.

## Security

- [ ] The score starts below 100 and the high-severity count matches the findings list.
- [ ] Every finding states what, why, attacker use and a framework fix; the copy button works.
- [ ] Cookie findings match the Storage view (missing HttpOnly/Secure/SameSite).
- [ ] The demo's `alg=none` JWT is flagged; the fixed token is not.
- [ ] Secret-in-URL fires for `?access_token=…` and not for innocuous query params.
- [ ] Verbose error, server banner and secret-in-response fire on `/vulnerable/`, not on `/fixed/`.
- [ ] Switching the demo to `/fixed/` removes the corresponding findings after navigation.

## Map and storage

- [ ] The map draws the page node and every domain; edge width tracks bytes; node colour shows risk.
- [ ] Clicking a domain selects a matching request.
- [ ] Storage → Refresh cookies shows the demo `sid`; risk badges match the server behaviour.
- [ ] “Read page storage” asks for nothing extra, returns key/value entries and masks values.
- [ ] On a `chrome://` page, the storage read fails with a readable error rather than a crash.

## Optional deep TLS

- [ ] Enabling Deep TLS in Settings shows Chrome's debugging infobar and requests the permission once.
- [ ] TLS rows then show protocol, cipher, issuer and certificate validity.
- [ ] Disabling detaches the debugger and stops further TLS lookups.
- [ ] Denying the permission leaves the rest of the tool functional and shows an inline explanation.

## Export and privacy

- [ ] HAR exports and opens in a HAR viewer; bodies match what the panel showed.
- [ ] JSON report masks secrets and contains score, findings and event timings.
- [ ] The HTML report opens from the filesystem with no network tab activity, and filtering works.
- [ ] Reloading the extension recovers the session from `chrome.storage.session` (bodies may be absent).
- [ ] No request in Chrome's own Network panel originates from the extension itself.

## Known gaps to verify manually

- Live capture across a full navigation clears the previous session by design.
- WebSocket frames are not decoded (only the handshake request is listed).
- HTTP/3 timings can be coarser; check that phases still add up to the total.
