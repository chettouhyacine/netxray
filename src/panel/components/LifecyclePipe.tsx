import { useEffect, useMemo, useState } from 'react';
import { PHASES, PHASE_META } from '../../core/phases';
import { formatDuration, phaseAt } from '../../core/timings';
import type { PhaseTimings } from '../../core/phases';

const ANIMATION_MS = 2600;

/**
 * The heart of the "X-ray": one request is drawn as a pipe between the browser
 * and the server, split into real phase durations, with a packet moving through
 * it. Only one instance animates at a time, so this stays at 60fps.
 */
export function LifecyclePipe({
  timings,
  teachMe,
  compact = false,
}: {
  timings: PhaseTimings;
  teachMe: boolean;
  compact?: boolean;
}) {
  const [progress, setProgress] = useState(1);
  const [playing, setPlaying] = useState(true);
  const total = Math.max(timings.total, 0.001);

  useEffect(() => {
    setProgress(0);
    setPlaying(true);
    let frame = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const ratio = Math.min(1, (now - start) / ANIMATION_MS);
      setProgress(ratio);
      if (ratio < 1) frame = requestAnimationFrame(tick);
      else setPlaying(false);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [timings]);

  const activePhase = useMemo(() => phaseAt(timings, progress * total), [timings, progress, total]);
  const phases = PHASES.filter((name) => timings[name] > 0);

  return (
    <div className="rounded-lg border border-slate-200 bg-white p-3 dark:border-ink-700 dark:bg-ink-850">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
          <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-accent shadow-[0_0_8px_#38e1c6]" />
          request lifecycle
        </div>
        <button
          type="button"
          onClick={() => {
            setProgress(0);
            setPlaying(true);
          }}
          className="rounded border border-slate-200 px-2 py-0.5 text-[10px] font-medium text-slate-600 hover:bg-slate-100 dark:border-ink-700 dark:text-slate-300 dark:hover:bg-ink-800"
          aria-label="Replay request animation"
        >
          {playing ? 'playing…' : '↻ replay'}
        </button>
      </div>

      <div className="flex items-center gap-2">
        <span className="w-12 shrink-0 text-right text-[10px] font-semibold text-slate-500 dark:text-slate-400">
          Browser
        </span>
        <div className="relative h-8 flex-1">
          <div className="absolute inset-y-0 left-0 right-0 top-1/2 h-3 -translate-y-1/2 overflow-hidden rounded-full bg-slate-100 dark:bg-ink-900">
            <div className="flex h-full w-full">
              {phases.map((name) => (
                <div
                  key={name}
                  style={{
                    width: `${((timings[name] || 0) / total) * 100}%`,
                    backgroundColor: PHASE_META[name].color,
                    opacity: activePhase === name ? 1 : 0.55,
                  }}
                  title={`${PHASE_META[name].label}: ${formatDuration(timings[name])}`}
                />
              ))}
            </div>
          </div>
          <div
            aria-hidden="true"
            className="pointer-events-none absolute top-1/2 z-10 h-3 w-3 -translate-y-1/2 rounded-full border-2 border-white shadow-[0_0_12px_#38e1c6] dark:border-ink-950"
            style={{
              left: `calc(${(playing ? progress : 1) * 100}% - 6px)`,
              backgroundColor: activePhase ? PHASE_META[activePhase].color : '#38e1c6',
              transition: playing ? 'none' : 'left 120ms linear',
            }}
          />
        </div>
        <span className="w-12 shrink-0 text-[10px] font-semibold text-slate-500 dark:text-slate-400">Server</span>
      </div>

      <div className="mt-2 flex flex-wrap gap-1">
        {phases.map((name) => (
          <span
            key={name}
            className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] ${
              activePhase === name
                ? 'bg-slate-100 font-semibold text-slate-800 dark:bg-ink-700 dark:text-white'
                : 'text-slate-500 dark:text-slate-400'
            }`}
          >
            <span
              aria-hidden="true"
              className="h-1.5 w-1.5 rounded-full"
              style={{ backgroundColor: PHASE_META[name].color }}
            />
            {PHASE_META[name].short}
            <span className="font-mono tabular-nums">{formatDuration(timings[name])}</span>
          </span>
        ))}
      </div>

      {teachMe && !compact ? (
        <ul className="mt-2 space-y-1 border-t border-slate-100 pt-2 dark:border-ink-700">
          {phases.map((name) => (
            <li
              key={name}
              className={`flex gap-2 text-[11px] leading-snug ${
                activePhase === name ? 'text-slate-800 dark:text-slate-100' : 'text-slate-500 dark:text-slate-400'
              }`}
            >
              <span
                aria-hidden="true"
                className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full"
                style={{ backgroundColor: PHASE_META[name].color }}
              />
              <span>
                <span className="font-semibold">{PHASE_META[name].label}:</span> {PHASE_META[name].teach.split(': ').slice(1).join(': ')}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
