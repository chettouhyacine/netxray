import { PHASES, PHASE_META, type Phase, type PhaseTimings, type PhaseName } from './phases';
import type { HarTimings } from './types';

const nonNegative = (value: number | undefined): number =>
  typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : 0;

/**
 * HAR timings can be -1 (not applicable) or absent. `connect` includes the TLS
 * handshake, so TCP is `connect - ssl`. Returns a fully normalized timing set
 * that always adds up to `total`.
 */
export function normalizeTimings(timings: HarTimings | undefined): PhaseTimings {
  const blocked = nonNegative(timings?.blocked);
  const dns = nonNegative(timings?.dns);
  const connect = nonNegative(timings?.connect);
  const tls = nonNegative(timings?.ssl);
  const tcp = Math.max(0, connect - tls);
  const request = nonNegative(timings?.send);
  const wait = nonNegative(timings?.wait);
  const download = nonNegative(timings?.receive);
  const total = blocked + dns + tcp + tls + request + wait + download;

  return { blocked, dns, tcp, tls, request, wait, download, total };
}

/** Expand normalized timings into positioned segments for the pipe animation. */
export function toPhases(timings: PhaseTimings): Phase[] {
  const phases: Phase[] = [];
  let cursor = 0;
  for (const name of PHASES) {
    const duration = timings[name];
    if (duration > 0) {
      phases.push({
        name,
        label: PHASE_META[name].label,
        start: cursor,
        duration,
      });
    }
    cursor += duration;
  }
  return phases;
}

/** Returns the phase active at `atMs` (0 <= atMs <= total). */
export function phaseAt(timings: PhaseTimings, atMs: number): PhaseName | null {
  let cursor = 0;
  for (const name of PHASES) {
    const duration = timings[name];
    if (duration > 0 && atMs >= cursor && atMs < cursor + duration) return name;
    cursor += duration;
  }
  if (cursor > 0 && atMs >= cursor) return 'download';
  return null;
}

/** Share of the request spent on DNS + TCP + TLS (connection setup). */
export function connectionOverhead(timings: PhaseTimings): number {
  return timings.dns + timings.tcp + timings.tls;
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '0 ms';
  if (ms < 1) return '<1 ms';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/** Column widths (percent) for the waterfall, ignoring zero-length phases. */
export function phaseWidths(timings: PhaseTimings): { name: PhaseName; width: number }[] {
  const total = timings.total || 1;
  return PHASES.map((name) => ({ name, width: (timings[name] / total) * 100 })).filter(
    (entry) => entry.width > 0,
  );
}
