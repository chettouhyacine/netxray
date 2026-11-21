# Browser support

NetXRay is a DevTools panel extension, so what it can do depends on what a
browser exposes to extensions. This page states exactly what is supported in
v1, without claiming a port that does not exist.

## Fully supported: Chromium browsers

The same `dist/` build loads unpacked in any Chromium-based browser that
supports Manifest V3 and the DevTools extensions API:

| Browser | Extensions page | Status |
| --- | --- | --- |
| Google Chrome 116+ | `chrome://extensions` | Primary target |
| Microsoft Edge | `edge://extensions` | Supported, same build |
| Brave | `brave://extensions` | Supported, same build |
| Opera | `opera://extensions` | Supported, same build |
| Vivaldi | `vivaldi://extensions` | Supported, same build |
| Chromium itself | `chrome://extensions` | Supported, same build |

Install: build with `npm run build`, enable **Developer mode**, choose
**Load unpacked**, and select `dist/`. Open DevTools → **⋮ → More tools →
NetXRay**.

Chromium-only features:

- **Live capture** uses `chrome.devtools.network`, which is the API that gives
  the panel request timings, headers and response bodies.
- **Deep TLS inspection** uses the optional `chrome.debugger` permission. It is
  off by default and only available in Chromium.
- **Reading page storage** uses `chrome.scripting` on an explicit click.

## Firefox and Safari: analyze an exported HAR

Firefox and Safari do not run a Chrome DevTools extension. Shipping a single
extension package for all three is not possible: Firefox needs its own
WebExtension port and DevTools panel, and Safari extensions must be built and
signed with Xcode.

What works today is the part that matters for review: **the analyzer is plain
data in, findings out.** Export a HAR from any browser, then import it:

1. In Firefox: DevTools → **Network** → **Export HAR**.
   In Safari: **Develop → Show Web Inspector → Network → Export**.
2. Open the NetXRay panel in Chrome/Edge (or the demo page) and choose
   **Export ▾ → Import HAR from any browser…**.
3. The timeline, the four v1 attack checks, the extended rules and all export
   formats run on that capture, with the same redaction.

HAR files can contain credentials and personal data. They never leave the
machine, and NetXRay redacts known secret shapes on export.

## What a native port would need (next version)

- **Firefox:** a `browser.*` promise shim, a Firefox manifest
  (`background.scripts` instead of a service worker, no `debugger` permission),
  and a DevTools panel built on Firefox's `devtools.network`. The rule engine,
  scoring and report code are already browser-agnostic.
- **Safari:** a Safari Web Extension target in Xcode, a container app, and
  App Store signing. Safari's extension networking APIs do not expose the same
  DevTools request stream, so capture would likely need a different transport.
