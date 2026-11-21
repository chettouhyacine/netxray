import { useState } from 'react';
import { PHASES, PHASE_META } from '../../core/phases';
import { parseSetCookie } from '../../core/headers';
import { redactUrl } from '../../core/redact';
import { formatBytes, formatDuration } from '../../core/timings';
import type { NetworkEvent } from '../../core/types';
import { usePanelStore } from '../store';
import { displayHost, displayPath, statusColor } from '../lib/severity';
import { redactBody, bodyWasTruncated, cookieRisks, isSensitiveHeader } from '../lib/format';
import { LifecyclePipe } from './LifecyclePipe';
import { RevealValue } from './RevealValue';

const TABS = ['overview', 'headers', 'cookies', 'timing', 'body'] as const;
type Tab = (typeof TABS)[number];

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-slate-100 py-1.5 last:border-0 dark:border-ink-700">
      <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
        {label}
      </span>
      <span className="min-w-0 truncate text-right text-[11px] text-slate-700 dark:text-slate-200">{children}</span>
    </div>
  );
}

function HeaderTable({ headers }: { headers: Record<string, string> }) {
  const entries = Object.entries(headers).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) return <p className="py-2 text-[11px] italic text-slate-500">No headers captured.</p>;
  return (
    <table className="w-full table-fixed border-collapse text-[11px]">
      <tbody>
        {entries.map(([name, value]) => (
          <tr key={name} className="border-b border-slate-100 align-top dark:border-ink-700">
            <td className="w-2/5 break-words py-1.5 pr-2 font-mono text-[10px] text-slate-500 dark:text-slate-400">{name}</td>
            <td className="break-words py-1.5 font-mono text-[10px] text-slate-700 dark:text-slate-200">
              {isSensitiveHeader(name) ? <RevealValue value={value} label={name} /> : value}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function RequestDrawer({ event }: { event: NetworkEvent }) {
  const selectEvent = usePanelStore((state) => state.selectEvent);
  const teachMe = usePanelStore((state) => state.teachMe);
  const [tab, setTab] = useState<Tab>('overview');
  const cookies = event.cookiesObserved;
  const setCookies = event.setCookie.map(parseSetCookie);

  return (
    <aside
      className="absolute inset-y-0 right-0 z-40 flex w-[min(540px,100%)] flex-col border-l border-slate-200 bg-white shadow-2xl dark:border-ink-700 dark:bg-ink-900"
      aria-label="Request details"
    >
      <div className="flex items-start justify-between gap-2 border-b border-slate-200 px-3 py-2 dark:border-ink-700">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-bold text-slate-700 dark:bg-ink-700 dark:text-slate-200">
              {event.method}
            </span>
            <span className={`font-mono text-xs font-bold ${statusColor(event.status)}`}>
              {event.status} {event.statusText}
            </span>
            <span className="truncate text-[10px] text-slate-500 dark:text-slate-400">
              {event.resourceType} · {event.mimeType || 'unknown type'}
            </span>
          </div>
          <div className="mt-1 truncate font-mono text-[11px] text-slate-700 dark:text-slate-200" title={redactUrl(event.url)}>
            {displayHost(event.url)}
            <span className="text-slate-400">{displayPath(event.url)}</span>
          </div>
        </div>
        <button
          type="button"
          onClick={() => selectEvent(null)}
          aria-label="Close request details"
          className="rounded p-1 text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:hover:bg-ink-700 dark:hover:text-white"
        >
          ✕
        </button>
      </div>

      <div className="border-b border-slate-200 p-3 dark:border-ink-700">
        <LifecyclePipe timings={event.timings} teachMe={teachMe} />
      </div>

      <div className="flex shrink-0 gap-0.5 border-b border-slate-200 px-2 dark:border-ink-700" role="tablist">
        {TABS.map((item) => (
          <button
            key={item}
            role="tab"
            aria-selected={tab === item}
            onClick={() => setTab(item)}
            className={`px-2 py-1.5 text-[11px] font-medium capitalize transition ${
              tab === item
                ? 'border-b-2 border-accent text-slate-900 dark:text-white'
                : 'border-b-2 border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
            }`}
          >
            {item}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {tab === 'overview' ? (
          <div>
            <Row label="URL">
              <span className="font-mono" title={redactUrl(event.url)}>
                {redactUrl(event.url).slice(0, 120)}
              </span>
            </Row>
            <Row label="Protocol">{event.tls?.protocol ?? event.protocol ?? event.httpVersion ?? 'unknown'}</Row>
            <Row label="Server IP">{event.serverIpAddress || 'not exposed by DevTools'}</Row>
            <Row label="Size">
              {formatBytes(event.sizes.total)} <span className="text-slate-400">({formatBytes(event.sizes.responseBody)} body)</span>
            </Row>
            <Row label="Total time">{formatDuration(event.timings.total)}</Row>
            <Row label="Cached">{event.fromCache ? 'yes, served from cache' : 'no'}</Row>
            <Row label="Cache-Control">{event.cacheControl || 'not set'}</Row>
            <Row label="Initiator">{event.initiator ? displayHost(event.initiator) : 'unknown'}</Row>
            <Row label="TLS data">{event.tls ? 'via chrome.debugger' : 'enable Deep TLS inspection for certificate and cipher details'}</Row>

            {event.tls ? (
              <div className="mt-3 rounded-lg border border-slate-200 p-2.5 dark:border-ink-700">
                <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-accent-dim dark:text-accent-soft">
                  TLS details
                </h4>
                <Row label="Protocol">{event.tls.protocol ?? 'n/a'}</Row>
                <Row label="Cipher">{event.tls.cipher ?? 'n/a'}</Row>
                <Row label="Key exchange">{event.tls.keyExchange ?? 'n/a'}</Row>
                <Row label="Issuer">{event.tls.certificate?.issuer ?? 'n/a'}</Row>
                <Row label="Valid until">
                  {event.tls.certificate?.validTo ? new Date(event.tls.certificate.validTo).toLocaleString() : 'n/a'}
                </Row>
              </div>
            ) : null}
          </div>
        ) : null}

        {tab === 'headers' ? (
          <div className="space-y-4">
            <section>
              <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Request headers</h4>
              <HeaderTable headers={event.requestHeaders} />
            </section>
            <section>
              <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Response headers</h4>
              <HeaderTable headers={event.responseHeaders} />
            </section>
          </div>
        ) : null}

        {tab === 'cookies' ? (
          <div className="space-y-4">
            <section>
              <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Cookies on this origin ({cookies.length})
              </h4>
              {cookies.length === 0 ? (
                <p className="text-[11px] italic text-slate-500">
                  No cookie data yet. Open the Storage view and refresh cookies for this origin.
                </p>
              ) : (
                <ul className="space-y-1">
                  {cookies.map((cookie) => (
                    <li
                      key={`${cookie.name}@${cookie.domain}${cookie.path}`}
                      className="rounded border border-slate-200 px-2 py-1.5 text-[11px] dark:border-ink-700"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-1">
                        <span className="font-mono font-semibold text-slate-800 dark:text-slate-100">{cookie.name}</span>
                        <span className="flex gap-1">
                          {cookieRisks(cookie).map((risk) => (
                            <span
                              key={risk.label}
                              className={`rounded px-1 py-px text-[9px] font-medium ${
                                risk.tone === 'medium'
                                  ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300'
                                  : 'bg-sky-500/15 text-sky-700 dark:text-sky-300'
                              }`}
                            >
                              {risk.label}
                            </span>
                          ))}
                        </span>
                      </div>
                      <div className="mt-1 flex items-center justify-between gap-2 text-[10px] text-slate-500 dark:text-slate-400">
                        <span className="font-mono">
                          {cookie.domain}
                          {cookie.path}
                        </span>
                        <RevealValue value={cookie.value} label={cookie.name} />
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
            {setCookies.length > 0 ? (
              <section>
                <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Set-Cookie in this response</h4>
                <ul className="space-y-1">
                  {setCookies.map((cookie, index) => (
                    <li key={`${cookie.name}-${index}`} className="rounded border border-slate-200 px-2 py-1.5 text-[10px] dark:border-ink-700">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono font-semibold text-slate-800 dark:text-slate-100">{cookie.name}</span>
                        <RevealValue value={cookie.value} label={cookie.name} />
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1 text-[9px] text-slate-500 dark:text-slate-400">
                        {Object.keys(cookie.attributes).length === 0 ? (
                          <span className="text-amber-600 dark:text-amber-300">no attributes</span>
                        ) : (
                          Object.entries(cookie.attributes).map(([key, value]) => (
                            <span key={key} className="rounded bg-slate-100 px-1 dark:bg-ink-700">
                              {key}
                              {value === true ? '' : `=${value}`}
                            </span>
                          ))
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
          </div>
        ) : null}

        {tab === 'timing' ? (
          <table className="w-full text-[11px]">
            <thead>
              <tr className="text-left text-[9px] uppercase tracking-wider text-slate-500">
                <th className="py-1">Phase</th>
                <th className="py-1 text-right">Duration</th>
                <th className="py-1 text-right">Share</th>
              </tr>
            </thead>
            <tbody>
              {PHASES.filter((name) => event.timings[name] > 0).map((name) => (
                <tr key={name} className="border-b border-slate-100 dark:border-ink-700">
                  <td className="py-1.5">
                    <span className="flex items-center gap-1.5">
                      <span
                        aria-hidden="true"
                        className="h-2 w-2 rounded-full"
                        style={{ backgroundColor: PHASE_META[name].color }}
                      />
                      {PHASE_META[name].label}
                    </span>
                    {teachMe ? (
                      <span className="mt-0.5 block text-[10px] leading-snug text-slate-500 dark:text-slate-400">
                        {PHASE_META[name].teach.split(': ').slice(1).join(': ')}
                      </span>
                    ) : null}
                  </td>
                  <td className="py-1.5 text-right font-mono tabular-nums">{formatDuration(event.timings[name])}</td>
                  <td className="py-1.5 text-right font-mono tabular-nums text-slate-500">
                    {Math.round((event.timings[name] / Math.max(event.timings.total, 1)) * 100)}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}

        {tab === 'body' ? (
          <div className="space-y-4">
            {event.responseBodyText ? (
              <section>
                <h4 className="mb-1 flex items-center justify-between text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  <span>Response body</span>
                  {bodyWasTruncated(event.responseBodyText, event.responseBodyTruncated) ? (
                    <span className="text-amber-600 dark:text-amber-300">truncated for safety</span>
                  ) : null}
                </h4>
                <pre className="max-h-72 overflow-auto rounded border border-slate-200 bg-slate-50 p-2 text-[10px] leading-relaxed text-slate-700 dark:border-ink-700 dark:bg-ink-950 dark:text-slate-300">
                  <code>{redactBody(event.responseBodyText)}</code>
                </pre>
                <p className="mt-1 text-[10px] text-slate-500">Secrets are masked. Values never leave this browser.</p>
              </section>
            ) : (
              <p className="text-[11px] italic text-slate-500">
                No response body captured. Binary, cached or streamed bodies are skipped.
              </p>
            )}
            {event.requestBodyText ? (
              <section>
                <h4 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">Request body</h4>
                <pre className="max-h-56 overflow-auto rounded border border-slate-200 bg-slate-50 p-2 text-[10px] text-slate-700 dark:border-ink-700 dark:bg-ink-950 dark:text-slate-300">
                  <code>{redactBody(event.requestBodyText)}</code>
                </pre>
              </section>
            ) : null}
          </div>
        ) : null}
      </div>
    </aside>
  );
}
