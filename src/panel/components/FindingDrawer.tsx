import { ATTACK_BY_ID } from '../../core/attacks';
import type { Finding } from '../../core/types';
import { usePanelStore } from '../store';
import { CodeTabs } from './CodeTabs';
import { RevealValue } from './RevealValue';
import { SeverityBadge } from './SeverityBadge';

export function FindingDrawer({ finding }: { finding: Finding }) {
  const selectFinding = usePanelStore((state) => state.selectFinding);
  const selectEvent = usePanelStore((state) => state.selectEvent);
  const setView = usePanelStore((state) => state.setView);

  return (
    <aside
      className="absolute inset-y-0 right-0 z-40 flex w-[min(560px,100%)] flex-col border-l border-slate-200 bg-white shadow-2xl dark:border-ink-700 dark:bg-ink-900"
      aria-label="Finding details"
    >
      <div className="flex items-start justify-between gap-2 border-b border-slate-200 px-3 py-2 dark:border-ink-700">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <span className="font-mono text-[10px] text-slate-500 dark:text-slate-400">{finding.ruleId}</span>
            <span className="rounded-full border border-slate-200 px-1.5 py-px text-[9px] font-medium text-slate-500 dark:border-ink-700 dark:text-slate-400">
              {finding.attackClass ? ATTACK_BY_ID[finding.attackClass].label : 'Extended check'} ·{' '}
              {finding.confidence} confidence
            </span>
          </div>
          <h2 className="mt-1 text-sm font-semibold leading-tight text-slate-900 dark:text-white">{finding.title}</h2>
          <p className="mt-0.5 break-all font-mono text-[10px] text-slate-500 dark:text-slate-400">{finding.domain}</p>
        </div>
        <button
          type="button"
          onClick={() => selectFinding(null)}
          aria-label="Close finding details"
          className="rounded p-1 text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:hover:bg-ink-700 dark:hover:text-white"
        >
          ✕
        </button>
      </div>

      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-3">
        <section className="rounded-lg border border-slate-200 bg-slate-50 p-2.5 dark:border-ink-700 dark:bg-ink-850">
          <p className="text-xs font-medium text-slate-800 dark:text-slate-100">{finding.message}</p>
          {finding.occurrences && finding.occurrences > 1 ? (
            <p className="mt-0.5 text-[10px] text-slate-500 dark:text-slate-400">
              Seen on {finding.occurrences} requests in this session.
            </p>
          ) : null}
          {finding.detail ? (
            <p className="mt-1 text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">{finding.detail}</p>
          ) : null}
          {finding.evidence ? (
            <p className="mt-1.5 flex items-center gap-1 text-[10px] text-slate-500 dark:text-slate-400">
              <span className="font-semibold uppercase tracking-wider">Evidence</span>
              <RevealValue value={finding.evidence} label="evidence" />
            </p>
          ) : null}
        </section>

        <section>
          <h3 className="mb-1 text-[10px] font-bold uppercase tracking-wider text-accent-dim dark:text-accent-soft">
            What is it?
          </h3>
          <p className="text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">{finding.what}</p>
        </section>
        <section>
          <h3 className="mb-1 text-[10px] font-bold uppercase tracking-wider text-accent-dim dark:text-accent-soft">
            Why does it matter?
          </h3>
          <p className="text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">{finding.why}</p>
        </section>
        <section>
          <h3 className="mb-1 text-[10px] font-bold uppercase tracking-wider text-rose-600 dark:text-rose-300">
            How could an attacker use this?
          </h3>
          <p className="text-[11px] leading-relaxed text-slate-600 dark:text-slate-300">{finding.attack}</p>
        </section>
        <section>
          <h3 className="mb-1.5 text-[10px] font-bold uppercase tracking-wider text-emerald-700 dark:text-emerald-300">
            How to fix it
          </h3>
          <CodeTabs remediation={finding.remediation} />
        </section>

        {finding.eventId ? (
          <button
            type="button"
            onClick={() => {
              selectEvent(finding.eventId ?? null);
              selectFinding(null);
              setView('timeline');
            }}
            className="w-full rounded-md border border-slate-200 px-2 py-1.5 text-[11px] font-medium text-slate-600 hover:bg-slate-100 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800"
          >
            Inspect the request that triggered this →
          </button>
        ) : null}
      </div>
    </aside>
  );
}
