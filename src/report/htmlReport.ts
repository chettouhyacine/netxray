import type { Finding, NetworkEvent, ScoreResult } from '../core/types';
import { formatBytes, formatDuration } from '../core/timings';
import { maskSecret, redactUrl } from '../core/redact';
import { SEVERITY_ORDER } from '../panel/lib/severity';

export interface ReportInput {
  pageUrl: string;
  generatedAt: number;
  score: ScoreResult;
  findings: Finding[];
  events: NetworkEvent[];
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * JSON embedded in a <script> tag must not be able to close it. `<` is escaped
 * as a unicode sequence, which is valid JSON and inert HTML.
 */
function embedJson(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
}

interface ReportFinding {
  id: string;
  severity: string;
  title: string;
  message: string;
  what: string;
  why: string;
  attack: string;
  attackClass?: string;
  confidence: string;
  domain: string;
  remediation: { framework: string; code: string }[];
}

interface ReportRow {
  method: string;
  status: number;
  url: string;
  domain: string;
  type: string;
  size: number;
  duration: number;
}

/**
 * Builds the shareable single-file report. It contains only escaped text, no
 * third-party assets, no fonts, no images and no outbound requests.
 */
export function buildHtmlReport(input: ReportInput): string {
  const findings: ReportFinding[] = [...input.findings]
    .sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    )
    .map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      message: finding.message,
      what: finding.what,
      why: finding.why,
      attack: finding.attack,
      attackClass: finding.attackClass,
      confidence: finding.confidence,
      domain: finding.domain ?? '',
      remediation: finding.remediation.map((item) => ({ framework: item.framework, code: item.code })),
    }));

  const rows: ReportRow[] = input.events.map((event) => ({
    method: event.method,
    status: event.status,
    url: redactUrl(event.url),
    domain: (() => {
      try {
        return new URL(event.url).hostname;
      } catch {
        return event.url;
      }
    })(),
    type: event.resourceType,
    size: event.sizes.total,
    duration: event.timings.total,
  }));

  const data = embedJson({
    page: redactUrl(input.pageUrl),
    generatedAt: new Date(input.generatedAt).toISOString(),
    score: input.score,
    findings,
    rows,
  });

  const reportHost = (() => {
    try {
      return new URL(input.pageUrl).hostname || 'session';
    } catch {
      return 'session';
    }
  })();
  const title = `NetXRay report for ${escapeHtml(reportHost)}`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>${title}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0b0f17; color: #e2e8f0; font: 14px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
  header { padding: 28px 32px 20px; border-bottom: 1px solid #1f2939; background: linear-gradient(180deg, #111725, #0b0f17); }
  h1 { margin: 0 0 4px; font-size: 22px; letter-spacing: -0.01em; }
  .muted { color: #94a3b8; }
  .mono { font-family: ui-monospace, Consolas, monospace; }
  main { padding: 24px 32px 60px; max-width: 1180px; margin: 0 auto; }
  .scoreboard { display: flex; gap: 28px; flex-wrap: wrap; align-items: center; margin-top: 16px; }
  .score { font-size: 42px; font-weight: 700; line-height: 1; }
  .pill { display: inline-flex; gap: 6px; align-items: center; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; }
  .high { background: rgba(244,63,94,.15); color: #fda4af; border: 1px solid rgba(244,63,94,.4); }
  .medium { background: rgba(245,158,11,.15); color: #fcd34d; border: 1px solid rgba(245,158,11,.4); }
  .low { background: rgba(14,165,233,.15); color: #7dd3fc; border: 1px solid rgba(14,165,233,.4); }
  .info { background: rgba(148,163,184,.15); color: #cbd5e1; border: 1px solid rgba(148,163,184,.4); }
  h2 { font-size: 15px; text-transform: uppercase; letter-spacing: .08em; color: #94a3b8; margin: 34px 0 12px; }
  .finding { border: 1px solid #1f2939; border-radius: 10px; background: #111725; margin-bottom: 10px; overflow: hidden; }
  .finding summary { cursor: pointer; padding: 12px 14px; display: flex; gap: 10px; align-items: center; list-style: none; }
  .finding summary::-webkit-details-marker { display: none; }
  .finding .body { padding: 4px 16px 16px; border-top: 1px solid #1f2939; }
  .finding h3 { margin: 0; font-size: 14px; font-weight: 600; }
  .finding p { margin: 8px 0; color: #cbd5e1; }
  .label { color: #7df0dd; font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
  pre { background: #080b12; border: 1px solid #1f2939; border-radius: 8px; padding: 10px 12px; overflow: auto; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid #1f2939; vertical-align: top; }
  th { color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 10px; letter-spacing: .06em; }
  td.num { text-align: right; white-space: nowrap; }
  .filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
  button { background: #161d2d; color: #e2e8f0; border: 1px solid #2c384d; border-radius: 999px; padding: 4px 12px; font-size: 12px; cursor: pointer; }
  button[aria-pressed="true"] { border-color: #38e1c6; color: #7df0dd; }
  .empty { color: #94a3b8; font-style: italic; }
  footer { margin-top: 40px; color: #64748b; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>NetXRay security report</h1>
  <div class="muted mono" id="page"></div>
  <div class="scoreboard">
    <div><div class="score" id="score"></div><div class="muted">security score</div></div>
    <div id="counts" class="filters"></div>
    <div class="muted">generated <span id="generated" class="mono"></span></div>
  </div>
</header>
<main>
  <h2>Findings</h2>
  <div class="filters" id="filters"></div>
  <div id="findings"></div>
  <h2>Request timeline</h2>
  <table>
    <thead><tr><th>Method</th><th>Status</th><th>Request</th><th>Type</th><th class="num">Size</th><th class="num">Time</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <footer>Generated locally by NetXRay. URLs and evidence are redacted; no data was uploaded.</footer>
</main>
<script type="application/json" id="nx-data">${data}</script>
<script>
(function () {
  var data = JSON.parse(document.getElementById('nx-data').textContent);
  var severityOrder = ['high', 'medium', 'low', 'info'];
  var active = null;
  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function fmtBytes(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(2) + ' MB';
  }
  function fmtMs(ms) {
    if (!ms) return '0 ms';
    return ms < 1000 ? Math.round(ms) + ' ms' : (ms / 1000).toFixed(2) + ' s';
  }
  document.getElementById('page').textContent = data.page || '(unknown page)';
  document.getElementById('generated').textContent = data.generatedAt;
  var scoreEl = document.getElementById('score');
  scoreEl.textContent = data.score.score;
  scoreEl.style.color = data.score.score >= 90 ? '#22c55e' : data.score.score >= 75 ? '#84cc16' : data.score.score >= 60 ? '#f59e0b' : '#f43f5e';
  var counts = document.getElementById('counts');
  counts.innerHTML = severityOrder.map(function (severity) {
    return '<span class="pill ' + severity + '">' + severity + ' ' + (data.score.counts[severity] || 0) + '</span>';
  }).join('');

  var filters = document.getElementById('filters');
  var options = [{ key: null, label: 'All' }].concat(severityOrder.map(function (severity) {
    return { key: severity, label: severity };
  }));
  options.forEach(function (option) {
    var button = document.createElement('button');
    button.textContent = option.label;
    button.setAttribute('aria-pressed', String(active === option.key));
    button.addEventListener('click', function () {
      active = option.key;
      render();
      Array.prototype.forEach.call(filters.children, function (child) {
        child.setAttribute('aria-pressed', String(child === button));
      });
    });
    filters.appendChild(button);
  });

  function render() {
    var container = document.getElementById('findings');
    var list = data.findings.filter(function (finding) {
      return active === null || finding.severity === active;
    });
    if (list.length === 0) {
      container.innerHTML = '<p class="empty">No findings for this filter. Nice work.</p>';
      return;
    }
    container.innerHTML = list.map(function (finding, index) {
      var fixes = finding.remediation.map(function (item) {
        return '<p class="label">' + esc(item.framework) + '</p><pre>' + esc(item.code) + '</pre>';
      }).join('');
      return '<details class="finding"' + (index === 0 ? ' open' : '') + '>' +
        '<summary><span class="pill ' + esc(finding.severity) + '">' + esc(finding.severity) + '</span>' +
        '<h3>' + esc(finding.title) + '</h3>' +
        '<span class="mono muted" style="margin-left:auto;font-size:11px">' +
        esc(finding.attackClass || 'extended') + ' · ' + esc(finding.confidence) + ' confidence</span></summary>' +
        '<div class="body"><p class="mono muted">' + esc(finding.domain) + ': ' + esc(finding.message) + '</p>' +
        '<p class="label">What is it?</p><p>' + esc(finding.what) + '</p>' +
        '<p class="label">Why does it matter?</p><p>' + esc(finding.why) + '</p>' +
        '<p class="label">How could an attacker use it?</p><p>' + esc(finding.attack) + '</p>' +
        '<p class="label">How to fix it</p>' + fixes +
        '</div></details>';
    }).join('');
  }

  document.getElementById('rows').innerHTML = data.rows.map(function (row) {
    return '<tr><td class="mono">' + esc(row.method) + '</td><td class="mono">' + esc(row.status) +
      '</td><td class="mono">' + esc(row.url) + '</td><td>' + esc(row.type) +
      '</td><td class="num">' + fmtBytes(row.size) + '</td><td class="num">' + fmtMs(row.duration) + '</td></tr>';
  }).join('') || '<tr><td colspan="6" class="empty">No requests captured.</td></tr>';

  render();
})();
</script>
</body>
</html>`;
}

/** Human-readable JSON report used by "Export JSON". */
export function buildJsonReport(input: ReportInput): string {
  return JSON.stringify(
    {
      tool: 'NetXRay',
      version: '0.2.0',
      format: 'netxray-report@1',
      generatedAt: new Date(input.generatedAt).toISOString(),
      page: redactUrl(input.pageUrl),
      score: input.score,
      findings: input.findings.map((finding) => ({
        ...finding,
        evidence: finding.evidence ? maskSecret(finding.evidence) : undefined,
        url: finding.url ? redactUrl(finding.url) : undefined,
      })),
      events: input.events.map((event) => ({
        id: event.id,
        url: redactUrl(event.url),
        method: event.method,
        status: event.status,
        resourceType: event.resourceType,
        mimeType: event.mimeType,
        protocol: event.protocol,
        serverIpAddress: event.serverIpAddress,
        startedAt: event.startedAt,
        startOffset: event.startOffset,
        timings: event.timings,
        sizes: event.sizes,
        tls: event.tls,
        cacheControl: event.cacheControl,
      })),
    },
    null,
    2,
  );
}

export function reportFileName(kind: 'har' | 'html' | 'json', at: number): string {
  const stamp = new Date(at).toISOString().replace(/[:.]/g, '-').slice(0, 19);
  return `netxray-${stamp}.${kind}`;
}

/** Exposed for unit tests: formatting used inside the generated report. */
export const reportHelpers = { escapeHtml, formatBytes, formatDuration };
