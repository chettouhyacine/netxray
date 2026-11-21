import type { Severity } from '../../core/types';
import { SEVERITY_META } from '../lib/severity';

export function SeverityBadge({ severity, small = false }: { severity: Severity; small?: boolean }) {
  const meta = SEVERITY_META[severity];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full font-semibold uppercase tracking-wide ${
        small ? 'px-1.5 py-0.5 text-[9px]' : 'px-2 py-0.5 text-[10px]'
      } ${meta.badge}`}
      title={`${meta.label} severity`}
    >
      <span aria-hidden="true">{meta.icon}</span>
      {meta.label}
    </span>
  );
}
