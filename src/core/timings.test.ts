import { describe, expect, it } from 'vitest';
import {
  connectionOverhead,
  formatBytes,
  formatDuration,
  normalizeTimings,
  phaseAt,
  phaseWidths,
  toPhases,
} from './timings';

describe('normalizeTimings', () => {
  it('subtracts TLS from connect and ignores -1 values', () => {
    const timings = normalizeTimings({ blocked: -1, dns: 5, connect: 30, ssl: 10, send: 2, wait: 40, receive: 8 });
    expect(timings.blocked).toBe(0);
    expect(timings.tcp).toBe(20);
    expect(timings.tls).toBe(10);
    expect(timings.total).toBe(85);
  });

  it('handles a cached response with no network timings', () => {
    const timings = normalizeTimings({ blocked: 12 });
    expect(timings.total).toBe(12);
    expect(timings.dns).toBe(0);
  });

  it('handles undefined timings', () => {
    expect(normalizeTimings(undefined).total).toBe(0);
  });
});

describe('toPhases', () => {
  it('positions only non-zero phases sequentially', () => {
    const phases = toPhases(normalizeTimings({ dns: 5, connect: 10, ssl: 0, send: 1, wait: 20, receive: 4 }));
    expect(phases.map((phase) => phase.name)).toEqual(['dns', 'tcp', 'request', 'wait', 'download']);
    expect(phases[1]?.start).toBe(5);
    expect(phases.at(-1)?.start).toBe(36);
  });
});

describe('phaseAt', () => {
  const timings = normalizeTimings({ dns: 10, connect: 10, ssl: 0, send: 1, wait: 20, receive: 5 });
  it('finds the active phase', () => {
    expect(phaseAt(timings, 0)).toBe('dns');
    expect(phaseAt(timings, 15)).toBe('tcp');
    expect(phaseAt(timings, 35)).toBe('wait');
  });
  it('returns null outside the request', () => {
    expect(phaseAt(normalizeTimings({}), 0)).toBeNull();
  });
  it('clamps the end to download', () => {
    expect(phaseAt(timings, 10_000)).toBe('download');
  });
});

describe('formatting', () => {
  it('formats durations', () => {
    expect(formatDuration(0)).toBe('0 ms');
    expect(formatDuration(0.4)).toBe('<1 ms');
    expect(formatDuration(250)).toBe('250 ms');
    expect(formatDuration(2500)).toBe('2.50 s');
    expect(formatDuration(20_000)).toBe('20.0 s');
  });

  it('formats byte sizes', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.00 MB');
  });
});

describe('helpers', () => {
  it('sums connection overhead', () => {
    expect(connectionOverhead(normalizeTimings({ dns: 2, connect: 8, ssl: 3 }))).toBe(10);
  });

  it('returns percentage widths that sum to 100', () => {
    const widths = phaseWidths(normalizeTimings({ dns: 10, connect: 10, ssl: 5, send: 5, wait: 60, receive: 10 }));
    const total = widths.reduce((sum, entry) => sum + entry.width, 0);
    expect(total).toBeCloseTo(100, 5);
  });
});
