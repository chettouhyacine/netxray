import { useMemo } from 'react';
import { PHASES, PHASE_META } from '../../core/phases';
import { formatBytes, formatDuration } from '../../core/timings';
import { summarizeSession } from '../../core/session';
import { usePanelStore } from '../store';
import { EmptyState } from '../components/EmptyState';
import { RequestList } from '../components/RequestList';

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col">
      <span className="text-[9px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">{label}</span>
      <span className="text-xs font-semibold tabular-nums text-slate-700 dark:text-slate-200">{value}</span>
    </div>
  );
}

export function TimelineView() {
  const events = usePanelStore((state) => state.events);
  const findings = usePanelStore((state) => state.findings);
  const search = usePanelStore((state) => state.search);
  const selectedEventId = usePanelStore((state) => state.selectedEventId);
  const selectEvent = usePanelStore((state) => state.selectEvent);
  const teachMe = usePanelStore((state) => state.teachMe);

  const summary = useMemo(() => summarizeSession(events), [events]);
  const slowest = useMemo(
    () => events.reduce((max, event) => Math.max(max, event.timings.total), 0),
    [events],
  );
  const thirdParty = summary.domains.filter((domain) => domain.isThirdParty).length;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-x-6 gap-y-1 border-b border-slate-200 px-3 py-1.5 dark:border-ink-700">
        <Stat label="Requests" value={String(events.length)} />
        <Stat label="Transferred" value={formatBytes(summary.totalBytes)} />
        <Stat label="Domains" value={`${summary.domains.length} (${thirdParty} third-party)`} />
        <Stat label="Slowest" value={formatDuration(slowest)} />
        <Stat label="Findings" value={String(findings.length)} />
        <div className="ml-auto hidden items-center gap-2 lg:flex">
          {PHASES.map((name) => (
            <span key={name} className="inline-flex items-center gap-1 text-[10px] text-slate-500 dark:text-slate-400">
              <span
                aria-hidden="true"
                className="h-1.5 w-1.5 rounded-full"
                style={{ backgroundColor: PHASE_META[name].color }}
              />
              {PHASE_META[name].short}
            </span>
          ))}
        </div>
      </div>

      {teachMe ? (
        <div className="shrink-0 border-b border-accent/20 bg-accent/5 px-3 py-1 text-[11px] text-slate-600 dark:text-slate-300">
          <span className="font-semibold text-accent-dim dark:text-accent-soft">Teach me is on.</span>{' '}
          Select a request to walk through DNS, TCP, TLS, TTFB and download with one-line explanations.
        </div>
      ) : null}

      {events.length === 0 ? (
        <EmptyState title="No traffic captured yet">
          <p>
            Keep this panel open and reload the inspected page. Every request appears here with its real
            lifecycle timings. Analysis runs locally in a Web Worker. Nothing is uploaded.
          </p>
        </EmptyState>
      ) : (
        <RequestList
          events={events}
          findings={findings}
          search={search}
          selectedId={selectedEventId}
          onSelect={selectEvent}
        />
      )}
    </div>
  );
}
