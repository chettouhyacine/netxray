import { useEffect, useMemo, useRef, useState } from 'react';
import { formatBytes, formatDuration } from '../../core/timings';
import type { Finding, NetworkEvent, Severity } from '../../core/types';
import { SEVERITY_ORDER } from '../lib/severity';
import { displayHost, displayPath, resourceIcon, statusColor, truncateMiddle } from '../lib/severity';
import { PhaseBar } from './PhaseBar';
import { SeverityBadge } from './SeverityBadge';

const ROW_HEIGHT = 46;
const OVERSCAN = 8;

interface RequestListProps {
  events: NetworkEvent[];
  findings: Finding[];
  search: string;
  selectedId: string | null;
  onSelect: (id: string) => void;
}

function worstSeverityFor(findings: Finding[]): Severity | null {
  let worst: Severity | null = null;
  for (const finding of findings) {
    if (!worst || SEVERITY_ORDER.indexOf(finding.severity) < SEVERITY_ORDER.indexOf(worst)) {
      worst = finding.severity;
    }
  }
  return worst;
}

export function RequestList({ events, findings, search, selectedId, onSelect }: RequestListProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(480);

  useEffect(() => {
    const element = containerRef.current;
    if (!element) return;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry) setHeight(entry.contentRect.height);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return events;
    return events.filter(
      (event) =>
        event.url.toLowerCase().includes(needle) ||
        event.method.toLowerCase().includes(needle) ||
        String(event.status).includes(needle) ||
        event.resourceType.toLowerCase().includes(needle),
    );
  }, [events, search]);

  const findingsByEvent = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const finding of findings) {
      if (!finding.eventId) continue;
      const list = map.get(finding.eventId) ?? [];
      list.push(finding);
      map.set(finding.eventId, list);
    }
    return map;
  }, [findings]);

  const maxDuration = useMemo(
    () => filtered.reduce((max, event) => Math.max(max, event.timings.total), 1),
    [filtered],
  );

  const start = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const end = Math.min(filtered.length, start + Math.ceil(height / ROW_HEIGHT) + OVERSCAN * 2);
  const visible = filtered.slice(start, end);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="grid shrink-0 grid-cols-[54px_minmax(0,1fr)_110px_84px_76px_150px] gap-2 border-b border-slate-200 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500 dark:border-ink-700 dark:text-slate-400">
        <span>Status</span>
        <span>Request</span>
        <span>Type</span>
        <span className="text-right">Size</span>
        <span className="text-right">Time</span>
        <span>Lifecycle</span>
      </div>

      <div
        ref={containerRef}
        className="relative min-h-0 flex-1 overflow-y-auto"
        onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
        role="table"
        aria-label="Captured network requests"
        aria-rowcount={filtered.length}
      >
        <div style={{ height: filtered.length * ROW_HEIGHT, position: 'relative' }}>
          {visible.map((event, index) => {
            const row = start + index;
            const eventFindings = findingsByEvent.get(event.id) ?? [];
            const worst = worstSeverityFor(eventFindings);
            const isSelected = event.id === selectedId;
            const barWidth = Math.max(2, (event.timings.total / maxDuration) * 100);
            return (
              <button
                key={event.id}
                type="button"
                role="row"
                aria-selected={isSelected}
                onClick={() => onSelect(event.id)}
                style={{
                  position: 'absolute',
                  top: row * ROW_HEIGHT,
                  height: ROW_HEIGHT,
                  width: '100%',
                }}
                className={`grid grid-cols-[54px_minmax(0,1fr)_110px_84px_76px_150px] items-center gap-2 border-b border-slate-100 px-3 text-left transition-colors dark:border-ink-800 ${
                  isSelected
                    ? 'bg-accent/10 ring-1 ring-inset ring-accent/40'
                    : 'hover:bg-slate-50 dark:hover:bg-ink-850'
                }`}
              >
                <span className={`font-mono text-xs font-semibold tabular-nums ${statusColor(event.status)}`}>
                  {event.status || 'pending'}
                </span>
                <span className="flex min-w-0 flex-col">
                  <span className="flex items-center gap-1.5">
                    <span className="rounded bg-slate-100 px-1 text-[9px] font-bold text-slate-600 dark:bg-ink-700 dark:text-slate-300">
                      {event.method}
                    </span>
                    {worst ? <SeverityBadge severity={worst} small /> : null}
                    <span className="truncate text-[11px] text-slate-700 dark:text-slate-200" title={event.url}>
                      {truncateMiddle(displayPath(event.url), 90)}
                    </span>
                  </span>
                  <span className="truncate text-[10px] text-slate-400 dark:text-slate-500">
                    {displayHost(event.url)}
                    {event.fromCache ? ' · from cache' : ''}
                  </span>
                </span>
                <span className="flex items-center gap-1 text-[10px] text-slate-500 dark:text-slate-400">
                  <span aria-hidden="true" className="text-slate-400">
                    {resourceIcon(event.resourceType)}
                  </span>
                  {event.resourceType}
                </span>
                <span className="text-right font-mono text-[10px] tabular-nums text-slate-500 dark:text-slate-400">
                  {formatBytes(event.sizes.total)}
                </span>
                <span className="text-right font-mono text-[10px] tabular-nums text-slate-500 dark:text-slate-400">
                  {formatDuration(event.timings.total)}
                </span>
                <span className="pr-1">
                  <div style={{ width: `${barWidth}%`, minWidth: 6 }}>
                    <PhaseBar timings={event.timings} />
                  </div>
                </span>
              </button>
            );
          })}
        </div>
        {filtered.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center p-6 text-center text-xs text-slate-500">
            {events.length === 0
              ? 'No requests captured yet. Reload the inspected page to populate the timeline.'
              : `No requests match “${search}”.`}
          </div>
        ) : null}
      </div>
    </div>
  );
}
