import { PHASE_META } from '../../core/phases';
import { phaseWidths } from '../../core/timings';
import type { PhaseTimings } from '../../core/phases';

export function PhaseBar({ timings, height = 6 }: { timings: PhaseTimings; height?: number }) {
  const widths = phaseWidths(timings);
  if (widths.length === 0) {
    return <div className="w-full rounded bg-slate-200 dark:bg-ink-700" style={{ height }} aria-hidden="true" />;
  }
  return (
    <div
      className="flex w-full overflow-hidden rounded"
      style={{ height }}
      role="img"
      aria-label={widths
        .map((entry) => `${PHASE_META[entry.name].label} ${Math.round(entry.width)}%`)
        .join(', ')}
    >
      {widths.map((entry) => (
        <div
          key={entry.name}
          style={{ width: `${entry.width}%`, backgroundColor: PHASE_META[entry.name].color }}
          title={`${PHASE_META[entry.name].label} · ${Math.round(entry.width)}%`}
        />
      ))}
    </div>
  );
}
