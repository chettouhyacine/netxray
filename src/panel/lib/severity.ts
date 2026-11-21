import type { Severity } from '../../core/types';

export interface SeverityMeta {
  label: string;
  icon: string;
  badge: string;
  dot: string;
  text: string;
}

/**
 * Severity uses an icon and a label as well as colour, so it remains readable
 * for colourblind users and in screenshots.
 */
export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  high: {
    label: 'High',
    icon: '▲',
    badge: 'bg-rose-500/15 text-rose-700 ring-1 ring-rose-500/40 dark:text-rose-300',
    dot: 'bg-rose-500',
    text: 'text-rose-700 dark:text-rose-300',
  },
  medium: {
    label: 'Medium',
    icon: '◆',
    badge: 'bg-amber-500/15 text-amber-700 ring-1 ring-amber-500/40 dark:text-amber-300',
    dot: 'bg-amber-500',
    text: 'text-amber-700 dark:text-amber-300',
  },
  low: {
    label: 'Low',
    icon: '●',
    badge: 'bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/40 dark:text-sky-300',
    dot: 'bg-sky-500',
    text: 'text-sky-700 dark:text-sky-300',
  },
  info: {
    label: 'Info',
    icon: '○',
    badge: 'bg-slate-500/15 text-slate-700 ring-1 ring-slate-500/40 dark:text-slate-300',
    dot: 'bg-slate-400',
    text: 'text-slate-600 dark:text-slate-300',
  },
};

export const SEVERITY_ORDER: Severity[] = ['high', 'medium', 'low', 'info'];

export function scoreColor(score: number): string {
  if (score >= 90) return '#22c55e';
  if (score >= 75) return '#84cc16';
  if (score >= 60) return '#f59e0b';
  if (score >= 40) return '#f97316';
  return '#f43f5e';
}

export function statusColor(status: number): string {
  if (status >= 500) return 'text-rose-600 dark:text-rose-400';
  if (status >= 400) return 'text-amber-600 dark:text-amber-400';
  if (status >= 300) return 'text-sky-600 dark:text-sky-400';
  if (status >= 200) return 'text-emerald-600 dark:text-emerald-400';
  return 'text-slate-500';
}

export function resourceIcon(type: string): string {
  switch (type) {
    case 'document':
      return '▤';
    case 'script':
      return '⌘';
    case 'stylesheet':
      return '#';
    case 'image':
      return '▣';
    case 'font':
      return 'A';
    case 'xhr':
    case 'fetch':
      return '⇄';
    case 'websocket':
      return '⇅';
    default:
      return '·';
  }
}

/** Hostname without throwing on malformed URLs. */
export function displayHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

export function displayPath(url: string): string {
  try {
    const parsed = new URL(url);
    const path = `${parsed.pathname}${parsed.search}`;
    return path === '/' ? '/' : path;
  } catch {
    return url;
  }
}

export function truncateMiddle(value: string, max: number): string {
  if (value.length <= max) return value;
  const half = Math.floor((max - 1) / 2);
  return `${value.slice(0, half)}…${value.slice(-half)}`;
}
