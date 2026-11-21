import { useEffect, useMemo } from 'react';
import { AnalysisClient } from './lib/analysisClient';
import { useSession } from './lib/useSession';
import { usePanelStore, type View } from './store';
import { TopBar } from './components/TopBar';
import { RequestDrawer } from './components/RequestDrawer';
import { FindingDrawer } from './components/FindingDrawer';
import { SettingsPanel } from './components/SettingsPanel';
import { Tour } from './components/Tour';
import { TimelineView } from './views/TimelineView';
import { SecurityView } from './views/SecurityView';
import { MapView } from './views/MapView';
import { StorageView } from './views/StorageView';

const KEY_TO_VIEW: Record<string, View> = {
  '1': 'timeline',
  '2': 'map',
  '3': 'security',
  '4': 'storage',
};

export function Panel() {
  useSession();

  const view = usePanelStore((state) => state.view);
  const events = usePanelStore((state) => state.events);
  const findings = usePanelStore((state) => state.findings);
  const cookies = usePanelStore((state) => state.cookies);
  const selectedEventId = usePanelStore((state) => state.selectedEventId);
  const selectedFindingId = usePanelStore((state) => state.selectedFindingId);
  const theme = usePanelStore((state) => state.theme);
  const notice = usePanelStore((state) => state.notice);
  const tourStep = usePanelStore((state) => state.tourStep);

  // Run analysis in a worker, debounced so bursts of requests stay smooth.
  useEffect(() => {
    const client = new AnalysisClient((result) => usePanelStore.getState().setAnalysis(result));
    const initial = usePanelStore.getState();
    client.schedule(initial.events, initial.cookies, initial.analysisFocus, 40);
    const unsubscribe = usePanelStore.subscribe((state, previous) => {
      if (
        state.events !== previous.events ||
        state.cookies !== previous.cookies ||
        state.analysisFocus !== previous.analysisFocus
      ) {
        client.schedule(state.events, state.cookies, state.analysisFocus);
      }
    });
    return () => {
      unsubscribe();
      client.dispose();
    };
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    document.documentElement.classList.toggle('light', theme === 'light');
  }, [theme]);

  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => usePanelStore.getState().setNotice(null), 7000);
    return () => clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) {
        if (event.key === 'Escape') (target as HTMLInputElement).blur();
        return;
      }
      const store = usePanelStore.getState();
      const mapped = KEY_TO_VIEW[event.key];
      if (mapped) {
        store.setView(mapped);
        return;
      }
      if (event.key === 'Escape') {
        if (store.selectedFindingId) store.selectFinding(null);
        else if (store.selectedEventId) store.selectEvent(null);
        else if (store.settingsOpen) store.setSettingsOpen(false);
        return;
      }
      if (event.key === 't') store.toggleTeachMe();
      if (event.key === '/') {
        event.preventDefault();
        document.querySelector<HTMLInputElement>('input[aria-label="Filter requests"]')?.focus();
      }
      if ((event.key === 'j' || event.key === 'k') && store.events.length > 0) {
        const index = store.events.findIndex((candidate) => candidate.id === store.selectedEventId);
        const next =
          event.key === 'j'
            ? Math.min(store.events.length - 1, index + 1)
            : Math.max(0, index <= 0 ? 0 : index - 1);
        const event_ = store.events[next];
        if (event_) {
          store.selectEvent(event_.id);
          if (store.view !== 'timeline') store.setView('timeline');
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const selectedEvent = useMemo(
    () => events.find((event) => event.id === selectedEventId) ?? null,
    [events, selectedEventId],
  );
  const selectedFinding = useMemo(
    () => findings.find((finding) => finding.id === selectedFindingId) ?? null,
    [findings, selectedFindingId],
  );

  // The panel keeps analysis fresh even when cookies change without new requests.
  useEffect(() => {
    void cookies;
  }, [cookies]);

  return (
    <div className="flex h-full flex-col bg-slate-50 text-slate-800 dark:bg-ink-900 dark:text-slate-200">
      <TopBar />
      <main className="relative min-h-0 flex-1">
        {view === 'timeline' ? <TimelineView /> : null}
        {view === 'map' ? <MapView /> : null}
        {view === 'security' ? <SecurityView /> : null}
        {view === 'storage' ? <StorageView /> : null}
        {selectedFinding ? (
          <FindingDrawer finding={selectedFinding} />
        ) : selectedEvent ? (
          <RequestDrawer event={selectedEvent} />
        ) : null}
      </main>

      <SettingsPanel />
      {tourStep !== null ? <Tour /> : null}

      {notice ? (
        <div
          role="status"
          className="absolute bottom-3 left-1/2 z-50 max-w-md -translate-x-1/2 rounded-md border border-slate-200 bg-white px-3 py-2 text-center text-[11px] text-slate-700 shadow-xl dark:border-ink-600 dark:bg-ink-800 dark:text-slate-200"
        >
          {notice}
        </div>
      ) : null}
    </div>
  );
}
