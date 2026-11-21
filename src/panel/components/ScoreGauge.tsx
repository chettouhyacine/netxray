import { scoreColor } from '../lib/severity';

export function ScoreGauge({ score, grade, size = 132 }: { score: number; grade: string; size?: number }) {
  const radius = (size - 14) / 2;
  const circumference = 2 * Math.PI * radius;
  const dash = (Math.max(0, Math.min(100, score)) / 100) * circumference;
  const color = scoreColor(score);

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} aria-label={`Security score ${score} out of 100, grade ${grade}`}>
      <svg width={size} height={size} className="-rotate-90" role="img" aria-hidden="true">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          strokeWidth={9}
          className="stroke-slate-200 dark:stroke-ink-700"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={9}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference}`}
          className="transition-[stroke-dasharray] duration-500"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold leading-none" style={{ color }}>
          {score}
        </span>
        <span className="mt-1 text-[10px] font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400">
          grade {grade}
        </span>
      </div>
    </div>
  );
}
