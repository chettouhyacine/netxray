import { useMemo } from 'react';
import { ATTACKS, ATTACK_BY_ID, type AttackClass } from '../../core/attacks';
import type { Severity } from '../../core/types';
import { usePanelStore } from '../store';
import { EmptyState } from '../components/EmptyState';
import { ScoreGauge } from '../components/ScoreGauge';
import { SeverityBadge } from '../components/SeverityBadge';
import { SEVERITY_META, SEVERITY_ORDER, scoreColor } from '../lib/severity';

export function SecurityView() {
  const findings = usePanelStore((state) => state.findings);
  const score = usePanelStore((state) => state.score);
  const filter = usePanelStore((state) => state.severityFilter);
  const setFilter = usePanelStore((state) => state.setSeverityFilter);
  const analysisFocus = usePanelStore((state) => state.analysisFocus);
  const setAnalysisFocus = usePanelStore((state) => state.setAnalysisFocus);
  const attackFilter = usePanelStore((state) => state.attackFilter);
  const setAttackFilter = usePanelStore((state) => state.setAttackFilter);
  const selectFinding = usePanelStore((state) => state.selectFinding);
  const selectedFindingId = usePanelStore((state) => state.selectedFindingId);

  const visible = useMemo(
    () =>
      findings.filter(
        (finding) =>
          (filter === 'all' || finding.severity === filter) &&
          (attackFilter === 'all' || finding.attack === attackFilter),
      ),
    [findings, filter, attackFilter],
  );

  const attackCounts = useMemo(() => {
    const counts: Record<AttackClass, number> = {
      'session-hijacking': 0,
      'cors-data-theft': 0,
      clickjacking: 0,
      'credential-leakage': 0,
    };
    for (const finding of findings) {
      if (finding.attackClass) counts[finding.attackClass] += 1;
    }
    return counts;
  }, [findings]);

  const grouped = useMemo(
    () =>
      SEVERITY_ORDER.map((severity) => ({
        severity,
        items: visible.filter((finding) => finding.severity === severity),
      })).filter((group) => group.items.length > 0),
    [visible],
  );

  return (
    <div className="flex h-full min-h-0 flex-col overflow-y-auto">
      <section className="grid shrink-0 gap-4 border-b border-slate-200 p-4 dark:border-ink-700 md:grid-cols-[auto_1fr]">
        <ScoreGauge score={score.score} grade={score.grade} />
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">
            Security score:{' '}
            <span style={{ color: scoreColor(score.score) }}>{score.score}/100</span>
          </h2>
          <p className="mt-1 max-w-2xl text-[11px] leading-relaxed text-slate-500 dark:text-slate-400">
            {analysisFocus === 'v1'
              ? 'V1 reports four attack classes only, and only when the evidence is direct. The score starts at 100 and loses points for each distinct rule that fires; repeats count less. It reflects this page’s network behaviour, not a penetration test.'
              : 'Extended mode shows every rule, including lower-confidence checks such as missing HSTS, TLS details and third-party inventory. Treat the extra findings as review prompts, not confirmed attacks.'}
          </p>

          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => setFilter('all')}
              aria-pressed={filter === 'all'}
              className={`rounded-full border px-2.5 py-1 text-[11px] font-medium ${
                filter === 'all'
                  ? 'border-accent bg-accent/10 text-accent-dim dark:text-accent-soft'
                  : 'border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800'
              }`}
            >
              All {findings.length}
            </button>
            {SEVERITY_ORDER.map((severity: Severity) => (
              <button
                key={severity}
                type="button"
                onClick={() => setFilter(severity)}
                aria-pressed={filter === severity}
                className={`flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-medium ${
                  filter === severity
                    ? 'border-accent bg-accent/10 text-accent-dim dark:text-accent-soft'
                    : 'border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800'
                }`}
              >
                <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${SEVERITY_META[severity].dot}`} />
                {SEVERITY_META[severity].label} {score.counts[severity]}
              </button>
            ))}
          </div>

          {analysisFocus === 'v1' ? (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                Attack class
              </span>
              <button
                type="button"
                onClick={() => setAttackFilter('all')}
                aria-pressed={attackFilter === 'all'}
                className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${
                  attackFilter === 'all'
                    ? 'border-accent/60 bg-accent/10 text-accent-dim dark:text-accent-soft'
                    : 'border-slate-200 text-slate-500 hover:bg-slate-50 dark:border-ink-700 dark:text-slate-400 dark:hover:bg-ink-800'
                }`}
              >
                All attacks
              </button>
              {ATTACKS.map((attack) => (
                <button
                  key={attack.id}
                  type="button"
                  onClick={() => setAttackFilter(attack.id)}
                  aria-pressed={attackFilter === attack.id}
                  title={attack.description}
                  className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${
                    attackFilter === attack.id
                      ? 'border-accent/60 bg-accent/10 text-accent-dim dark:text-accent-soft'
                      : 'border-slate-200 text-slate-500 hover:bg-slate-50 dark:border-ink-700 dark:text-slate-400 dark:hover:bg-ink-800'
                  }`}
                >
                  {attack.label} {attackCounts[attack.id]}
                </button>
              ))}
            </div>
          ) : null}

          <label className="mt-2 flex cursor-pointer items-center gap-1.5 text-[10px] text-slate-500 dark:text-slate-400">
            <input
              type="checkbox"
              checked={analysisFocus === 'all'}
              onChange={(event) => setAnalysisFocus(event.target.checked ? 'all' : 'v1')}
              className="accent-emerald-500"
            />
            Extended checks: all 34 rules, including lower-confidence findings
          </label>
        </div>
      </section>

      {findings.length === 0 ? (
        <EmptyState
          title={
            analysisFocus === 'v1'
              ? 'No confirmed findings in the four v1 attack classes'
              : 'No findings for this page yet'
          }
        >
          <p>
            {analysisFocus === 'v1'
              ? 'Capture a few requests first. An empty list means the four v1 attack classes found direct evidence on this page. Enable extended checks to review headers, TLS and third-party inventory too.'
              : 'Capture a few requests first. Rules also flag what headers are missing, so an empty list usually means the page is well configured, or that DevTools had not captured the document response.'}
          </p>
        </EmptyState>
      ) : (
        <div className="space-y-5 p-3">
          {grouped.map((group) => (
            <section key={group.severity}>
              <h3 className="mb-1.5 flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                <span aria-hidden="true" className={`h-2 w-2 rounded-full ${SEVERITY_META[group.severity].dot}`} />
                {SEVERITY_META[group.severity].label} severity
                <span className="font-normal normal-case tracking-normal text-slate-400">({group.items.length})</span>
              </h3>
              <ul className="space-y-1">
                {group.items.map((finding) => (
                  <li key={finding.id}>
                    <button
                      type="button"
                      onClick={() => selectFinding(finding.id)}
                      aria-pressed={finding.id === selectedFindingId}
                      className={`w-full rounded-lg border px-3 py-2 text-left transition ${
                        finding.id === selectedFindingId
                          ? 'border-accent/60 bg-accent/5'
                          : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50 dark:border-ink-700 dark:bg-ink-850 dark:hover:border-ink-600'
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={finding.severity} small />
                        <span className="text-xs font-semibold text-slate-800 dark:text-slate-100">{finding.title}</span>
                        <span className="ml-auto shrink-0 font-mono text-[10px] text-slate-400">{finding.domain}</span>
                      </div>
                      <p className="mt-1 text-[11px] text-slate-600 dark:text-slate-300">{finding.message}</p>
                      <p className="mt-0.5 truncate text-[10px] text-slate-400 dark:text-slate-500">
                        {finding.attackClass
                          ? `${ATTACK_BY_ID[finding.attackClass].label} · ${finding.confidence} confidence`
                          : `Extended check · ${finding.confidence} confidence`}{' '}
                        · {finding.ruleId}
                      </p>
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          ))}
          {visible.length === 0 ? (
            <p className="p-4 text-center text-[11px] italic text-slate-500">
              No findings for this severity and attack filter.
            </p>
          ) : null}
        </div>
      )}
    </div>
  );
}
