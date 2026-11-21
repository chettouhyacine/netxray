import { useState } from 'react';
import { usePanelStore } from '../store';
import { sendMessage } from '../../shared/protocol';
import { inspectedTabId } from '../lib/capture';
import { cookieRisks } from '../lib/format';
import { RevealValue } from '../components/RevealValue';
import { EmptyState } from '../components/EmptyState';
import { displayHost } from '../lib/severity';

function RiskBadge({ label, tone }: { label: string; tone: 'high' | 'medium' | 'low' }) {
  const classes =
    tone === 'high'
      ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300'
      : tone === 'medium'
        ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300'
        : 'bg-sky-500/15 text-sky-700 dark:text-sky-300';
  return <span className={`rounded px-1 py-px text-[9px] font-medium ${classes}`}>{label}</span>;
}

export function StorageView() {
  const cookies = usePanelStore((state) => state.cookies);
  const setCookies = usePanelStore((state) => state.setCookies);
  const pageUrl = usePanelStore((state) => state.pageUrl);
  const events = usePanelStore((state) => state.events);
  const storageSnapshot = usePanelStore((state) => state.storageSnapshot);
  const setStorage = usePanelStore((state) => state.setStorage);
  const storageError = usePanelStore((state) => state.storageError);
  const storageLoading = usePanelStore((state) => state.storageLoading);
  const setStorageLoading = usePanelStore((state) => state.setStorageLoading);
  const setNotice = usePanelStore((state) => state.setNotice);
  const [refreshing, setRefreshing] = useState(false);

  const documentUrl = pageUrl || events.find((event) => event.resourceType === 'document')?.url || '';

  const refreshCookies = async () => {
    if (!documentUrl) {
      setNotice('No page URL yet. Reload the inspected page first.');
      return;
    }
    setRefreshing(true);
    try {
      const response = await sendMessage({ type: 'GET_COOKIES', url: documentUrl });
      setCookies(response.cookies);
    } catch {
      setNotice('Could not read cookies. Check the extension has host permission for this site.');
    } finally {
      setRefreshing(false);
    }
  };

  const readStorage = async () => {
    const tabId = inspectedTabId();
    if (tabId === null) {
      setNotice('Open NetXRay inside DevTools to read page storage.');
      return;
    }
    setStorageLoading(true);
    try {
      const response = await sendMessage({ type: 'READ_STORAGE', tabId });
      setStorage(response.snapshot, response.error ?? null);
      if (response.error) setNotice(response.error);
    } catch (error) {
      setStorage(null, error instanceof Error ? error.message : 'Storage read failed');
    } finally {
      setStorageLoading(false);
    }
  };

  return (
    <div className="h-full overflow-y-auto p-3">
      <section className="mb-5">
        <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-xs font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
              Cookies {documentUrl ? <span className="font-normal normal-case tracking-normal text-slate-400">· {displayHost(documentUrl)}</span> : null}
            </h2>
            <p className="text-[10px] text-slate-400">
              Attributes come from chrome.cookies for the inspected origin, refreshed on demand.
            </p>
          </div>
          <button
            type="button"
            onClick={refreshCookies}
            disabled={refreshing}
            className="rounded-md border border-slate-200 px-2 py-1 text-[11px] font-medium text-slate-600 hover:bg-slate-100 disabled:opacity-50 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800"
          >
            {refreshing ? 'Reading…' : 'Refresh cookies'}
          </button>
        </div>

        {cookies.length === 0 ? (
          <EmptyState title="No cookies visible for this origin">
            <p>
              Cookies are only read for the page you are inspecting. If the site sets none, or the extension
              lacks host access, this stays empty.
            </p>
          </EmptyState>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-ink-700">
            <table className="w-full text-[11px]">
              <thead className="bg-slate-50 text-left text-[9px] uppercase tracking-wider text-slate-500 dark:bg-ink-850 dark:text-slate-400">
                <tr>
                  <th className="px-2 py-1.5">Name</th>
                  <th className="px-2 py-1.5">Value</th>
                  <th className="px-2 py-1.5">Scope</th>
                  <th className="px-2 py-1.5">Flags</th>
                  <th className="px-2 py-1.5">Risk</th>
                </tr>
              </thead>
              <tbody>
                {cookies.map((cookie) => (
                  <tr key={`${cookie.name}@${cookie.domain}${cookie.path}`} className="border-t border-slate-100 dark:border-ink-700">
                    <td className="px-2 py-1.5 font-mono font-medium text-slate-800 dark:text-slate-100">{cookie.name}</td>
                    <td className="max-w-[180px] px-2 py-1.5">
                      <RevealValue value={cookie.value} label={cookie.name} />
                    </td>
                    <td className="px-2 py-1.5 font-mono text-[10px] text-slate-500 dark:text-slate-400">
                      {cookie.domain}
                      {cookie.path}
                    </td>
                    <td className="px-2 py-1.5 text-[10px] text-slate-500 dark:text-slate-400">
                      {[
                        cookie.httpOnly ? 'HttpOnly' : null,
                        cookie.secure ? 'Secure' : null,
                        `SameSite=${cookie.sameSite}`,
                        cookie.session ? 'session' : 'persistent',
                      ]
                        .filter(Boolean)
                        .join(' · ')}
                    </td>
                    <td className="px-2 py-1.5">
                      <span className="flex flex-wrap gap-1">
                        {cookieRisks(cookie).length === 0 ? (
                          <span className="text-[9px] text-emerald-600 dark:text-emerald-300">hardened</span>
                        ) : (
                          cookieRisks(cookie).map((risk) => (
                            <RiskBadge key={risk.label} label={risk.label} tone={risk.tone} />
                          ))
                        )}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section>
        <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-xs font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
              localStorage &amp; sessionStorage
            </h2>
            <p className="max-w-xl text-[10px] text-slate-400">
              Read with a one-off injected function on explicit request. No eval, no automatic scraping; values
              are truncated to 500 characters and masked until revealed.
            </p>
          </div>
          <button
            type="button"
            onClick={readStorage}
            disabled={storageLoading}
            className="rounded-md border border-slate-200 px-2 py-1 text-[11px] font-medium text-slate-600 hover:bg-slate-100 disabled:opacity-50 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800"
          >
            {storageLoading ? 'Reading…' : 'Read page storage'}
          </button>
        </div>

        {storageError ? (
          <p className="rounded border border-amber-300 bg-amber-50 p-2 text-[11px] text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200">
            {storageError}
          </p>
        ) : null}

        {storageSnapshot ? (
          <div className="grid gap-3 md:grid-cols-2">
            {(['localStorage', 'sessionStorage'] as const).map((area) => (
              <div key={area} className="min-w-0">
                <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  {area} · {storageSnapshot[area].length}
                </h3>
                {storageSnapshot[area].length === 0 ? (
                  <p className="text-[11px] italic text-slate-500">empty</p>
                ) : (
                  <ul className="space-y-1">
                    {storageSnapshot[area].map((entry) => (
                      <li key={entry.key} className="rounded border border-slate-200 px-2 py-1 text-[10px] dark:border-ink-700">
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate font-mono font-medium text-slate-700 dark:text-slate-200">{entry.key}</span>
                          <RevealValue value={entry.value} label={entry.key} />
                        </div>
                        {entry.truncated ? <span className="text-[9px] text-amber-600 dark:text-amber-300">truncated</span> : null}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="rounded border border-dashed border-slate-300 p-3 text-center text-[11px] text-slate-500 dark:border-ink-700">
            Nothing read yet. Storage is only read when you ask.
          </p>
        )}
      </section>
    </div>
  );
}
