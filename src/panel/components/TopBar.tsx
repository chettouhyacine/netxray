import { useMemo, useRef, type ChangeEvent } from 'react';
import { importHar } from '../../core/harImport';
import { usePanelStore, type View } from '../store';
import { exportSession } from '../lib/export';
import { scoreColor } from '../lib/severity';

const VIEWS: { id: View; label: string; hint: string }[] = [
  { id: 'timeline', label: 'Timeline', hint: 'Animated request lifecycle' },
  { id: 'map', label: 'Map', hint: 'Domains the page talks to' },
  { id: 'security', label: 'Security', hint: 'Findings and score' },
  { id: 'storage', label: 'Storage', hint: 'Cookies and web storage' },
];

export function TopBar() {
  const view = usePanelStore((state) => state.view);
  const setView = usePanelStore((state) => state.setView);
  const events = usePanelStore((state) => state.events);
  const findings = usePanelStore((state) => state.findings);
  const score = usePanelStore((state) => state.score);
  const teachMe = usePanelStore((state) => state.teachMe);
  const toggleTeachMe = usePanelStore((state) => state.toggleTeachMe);
  const search = usePanelStore((state) => state.search);
  const setSearch = usePanelStore((state) => state.setSearch);
  const theme = usePanelStore((state) => state.theme);
  const setTheme = usePanelStore((state) => state.setTheme);
  const setSettingsOpen = usePanelStore((state) => state.setSettingsOpen);
  const clearSession = usePanelStore((state) => state.clearSession);
  const analysisFocus = usePanelStore((state) => state.analysisFocus);
  const exportRef = useRef<HTMLDetailsElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const loadHar = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    try {
      const result = importHar(await file.text());
      const store = usePanelStore.getState();
      store.clearSession();
      store.addEvents(result.events);
      store.setCookies(result.cookies);
      store.setPageUrl(result.pageUrl);
      const skipped =
        result.skipped > 0
          ? ` ${result.skipped} unusable ${result.skipped === 1 ? 'entry was' : 'entries were'} skipped.`
          : '';
      store.setNotice(
        `Imported ${result.events.length} requests from ${file.name}. Everything is analyzed locally.${skipped}`,
      );
    } catch (error) {
      usePanelStore
        .getState()
        .setNotice(error instanceof Error ? error.message : 'Could not import that HAR file.');
    }
  };

  const highFindings = findings.filter((finding) => finding.severity === 'high').length;
  const closeExport = () => exportRef.current?.removeAttribute('open');
  const cookieCount = usePanelStore((state) => state.cookies.length);
  const domainCount = useMemo(
    () =>
      new Set(
        events.map((event) => {
          try {
            return new URL(event.url).hostname;
          } catch {
            return event.url;
          }
        }),
      ).size,
    [events],
  );
  const counts: Record<View, number> = {
    timeline: events.length,
    map: domainCount,
    security: findings.length,
    storage: cookieCount,
  };

  return (
    <header className="relative z-20 shrink-0 border-b border-slate-200 bg-white/80 backdrop-blur dark:border-ink-700 dark:bg-ink-900/90">
      <div className="flex flex-wrap items-center gap-2 px-3 py-2">
        <div className="flex items-center gap-2">
          <div
            aria-hidden="true"
            className="flex h-7 w-7 items-center justify-center rounded-md bg-gradient-to-br from-accent to-emerald-600 text-sm font-black text-ink-950 shadow-[0_0_18px_rgba(56,225,198,0.35)]"
          >
            N
          </div>
          <div className="leading-tight">
            <div className="text-sm font-bold tracking-tight text-slate-900 dark:text-white">NetXRay</div>
            <div className="text-[10px] text-slate-500 dark:text-slate-400">network x-ray · stays on your machine</div>
          </div>
        </div>

        <div className="ml-1 flex items-center gap-1 rounded-full border border-slate-200 bg-slate-100 px-1 py-0.5 text-[11px] dark:border-ink-700 dark:bg-ink-850">
          <span className="px-1.5 text-slate-500 dark:text-slate-400">score</span>
          <span
            className="rounded-full px-2 py-0.5 font-bold tabular-nums"
            style={{ color: scoreColor(score.score), backgroundColor: `${scoreColor(score.score)}22` }}
          >
            {score.score}/100
          </span>
          {highFindings > 0 ? (
            <span className="px-1.5 font-semibold text-rose-600 dark:text-rose-400">{highFindings} high</span>
          ) : null}
          <span
            className="px-1.5 text-[9px] font-semibold uppercase tracking-wider text-slate-400"
            title={
              analysisFocus === 'v1'
                ? 'V1 reports four high-confidence attack classes'
                : 'Extended checks are on: all 34 rules'
            }
          >
            {analysisFocus === 'v1' ? 'v1 · 4 attacks' : 'all checks'}
          </span>
        </div>

        <nav className="flex flex-1 items-center gap-0.5" aria-label="Views">
          {VIEWS.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setView(item.id)}
              aria-current={view === item.id ? 'page' : undefined}
              title={item.hint}
              className={`group relative rounded-md px-2.5 py-1.5 text-xs font-medium transition ${
                view === item.id
                  ? 'bg-slate-900 text-white dark:bg-ink-700 dark:text-white'
                  : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-ink-800 dark:hover:text-slate-100'
              }`}
            >
              {item.label}
              <span
                className={`ml-1.5 rounded-full px-1 py-px text-[9px] tabular-nums ${
                  view === item.id ? 'bg-white/20' : 'bg-slate-200 text-slate-600 dark:bg-ink-700 dark:text-slate-300'
                }`}
              >
                {counts[item.id]}
              </span>
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-1">
          {view === 'timeline' ? (
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Filter requests  ( / )"
              aria-label="Filter requests"
              className="w-40 rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] text-slate-800 placeholder:text-slate-400 focus:border-accent focus:outline-none dark:border-ink-700 dark:bg-ink-850 dark:text-slate-100"
            />
          ) : null}
          <button
            type="button"
            onClick={toggleTeachMe}
            aria-pressed={teachMe}
            title="Show a one-line explanation under each network phase"
            className={`rounded-md border px-2 py-1 text-[11px] font-medium transition ${
              teachMe
                ? 'border-accent/60 bg-accent/10 text-accent-dim dark:text-accent-soft'
                : 'border-slate-200 text-slate-600 hover:bg-slate-100 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800'
            }`}
          >
            Teach me
          </button>

          <details ref={exportRef} className="relative">
            <summary className="cursor-pointer list-none rounded-md border border-slate-200 px-2 py-1 text-[11px] font-medium text-slate-600 hover:bg-slate-100 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800">
              Export ▾
            </summary>
            <div className="absolute right-0 z-50 mt-1 w-52 overflow-hidden rounded-md border border-slate-200 bg-white py-1 shadow-xl dark:border-ink-700 dark:bg-ink-850">
              <button
                type="button"
                className="block w-full px-3 py-1.5 text-left text-[11px] text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-ink-700"
                onClick={() => {
                  exportSession('html');
                  closeExport();
                }}
              >
                Shareable HTML report
              </button>
              <button
                type="button"
                className="block w-full px-3 py-1.5 text-left text-[11px] text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-ink-700"
                onClick={() => {
                  exportSession('json');
                  closeExport();
                }}
              >
                JSON report
              </button>
              <button
                type="button"
                className="block w-full px-3 py-1.5 text-left text-[11px] text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-ink-700"
                onClick={() => {
                  exportSession('har');
                  closeExport();
                }}
              >
                HAR (full capture)
              </button>
              <button
                type="button"
                className="block w-full px-3 py-1.5 text-left text-[11px] text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-ink-700"
                onClick={() => {
                  fileRef.current?.click();
                  closeExport();
                }}
              >
                Import HAR from any browser…
              </button>
            </div>
          </details>
          <input
            ref={fileRef}
            type="file"
            accept=".har,application/json"
            onChange={(event) => void loadHar(event)}
            className="hidden"
            aria-label="Import a HAR file"
          />

          <button
            type="button"
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            className="rounded-md border border-slate-200 px-2 py-1 text-[11px] text-slate-600 hover:bg-slate-100 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800"
          >
            {theme === 'dark' ? '☾' : '☀'}
          </button>
          <button
            type="button"
            onClick={() => setSettingsOpen(true)}
            title="Settings and privacy"
            aria-label="Settings and privacy"
            className="rounded-md border border-slate-200 px-2 py-1 text-[11px] text-slate-600 hover:bg-slate-100 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800"
          >
            ⚙
          </button>
          <button
            type="button"
            onClick={() => {
              if (window.confirm('Clear the captured session? Nothing is sent anywhere.')) clearSession();
            }}
            title="Clear captured session"
            aria-label="Clear captured session"
            className="rounded-md border border-slate-200 px-2 py-1 text-[11px] text-slate-600 hover:bg-rose-50 hover:text-rose-700 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-rose-500/10 dark:hover:text-rose-300"
          >
            ⨯
          </button>
        </div>
      </div>
    </header>
  );
}
