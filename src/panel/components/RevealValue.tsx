import { useState } from 'react';
import { maskSecret } from '../../core/redact';

/**
 * Displays a masked value by default. The full value never leaves memory; it
 * is only rendered after an explicit click.
 */
export function RevealValue({
  value,
  label,
  className = '',
}: {
  value: string;
  label?: string;
  className?: string;
}) {
  const [revealed, setRevealed] = useState(false);
  if (!value) return <span className="text-slate-500">n/a</span>;
  return (
    <button
      type="button"
      onClick={() => setRevealed((current) => !current)}
      className={`group inline-flex max-w-full items-center gap-1 rounded px-1 text-left font-mono text-[11px] hover:bg-slate-500/10 ${className}`}
      title={revealed ? 'Click to hide' : 'Click to reveal (stays local)'}
      aria-label={label ? `${label}: click to ${revealed ? 'hide' : 'reveal'}` : undefined}
    >
      <span className="truncate">{revealed ? value : maskSecret(value)}</span>
      <span aria-hidden="true" className="text-[9px] text-slate-500 group-hover:text-accent">
        {revealed ? 'hide' : 'show'}
      </span>
    </button>
  );
}
