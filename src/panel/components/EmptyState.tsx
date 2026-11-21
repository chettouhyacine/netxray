import type { ReactNode } from 'react';

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 p-10 text-center">
      <div aria-hidden="true" className="mb-1 text-3xl text-slate-300 dark:text-ink-600">
        ⟠
      </div>
      <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{title}</h3>
      <div className="max-w-md text-xs leading-relaxed text-slate-500 dark:text-slate-400">{children}</div>
    </div>
  );
}
