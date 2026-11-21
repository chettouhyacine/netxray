import { useState } from 'react';
import type { Remediation } from '../../core/types';

const LABELS: Record<Remediation['framework'], string> = {
  express: 'Express',
  nextjs: 'Next.js',
  nginx: 'Nginx',
  generic: 'Docs',
};

export function CodeTabs({ remediation }: { remediation: Remediation[] }) {
  const [active, setActive] = useState(0);
  const [copied, setCopied] = useState(false);
  if (remediation.length === 0) return null;
  const current = remediation[Math.min(active, remediation.length - 1)];

  const copy = async () => {
    if (!current) return;
    try {
      await navigator.clipboard.writeText(current.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="overflow-hidden rounded-lg border border-slate-200 bg-slate-50 dark:border-ink-700 dark:bg-ink-950">
      <div className="flex items-center justify-between gap-2 border-b border-slate-200 px-2 py-1.5 dark:border-ink-700">
        <div className="flex gap-1" role="tablist" aria-label="Framework-specific fix">
          {remediation.map((item, index) => (
            <button
              key={`${item.framework}-${index}`}
              role="tab"
              aria-selected={index === active}
              onClick={() => setActive(index)}
              className={`rounded px-2 py-1 text-[11px] font-medium transition ${
                index === active
                  ? 'bg-white text-slate-900 shadow-sm dark:bg-ink-700 dark:text-white'
                  : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
              }`}
            >
              {LABELS[item.framework]}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={copy}
          className="rounded px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-slate-500 hover:text-accent"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      {current?.note ? (
        <p className="border-b border-slate-200 px-3 py-1.5 text-[11px] text-slate-500 dark:border-ink-700 dark:text-slate-400">
          {current.note}
        </p>
      ) : null}
      <pre className="max-h-64 overflow-auto p-3 text-[11px] leading-relaxed text-slate-800 dark:text-slate-200">
        <code>{current?.code}</code>
      </pre>
    </div>
  );
}
