import { describe, expect, it } from 'vitest';
import { countBySeverity, dedupeFindings, scoreFindings, sortFindings } from './score';
import type { Finding, Severity } from './types';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'rule:key',
    ruleId: 'rule',
    severity: 'high',
    title: 'Title',
    what: 'What',
    why: 'Why',
    attack: 'Attack',
    remediation: [],
    message: 'Message',
    tags: [],
    confidence: 'high',
    ...overrides,
  };
}

describe('scoreFindings', () => {
  it('returns 100 for a clean session', () => {
    expect(scoreFindings([])).toEqual({ score: 100, grade: 'A', counts: { high: 0, medium: 0, low: 0, info: 0 } });
  });

  it('deducts more for high severity than low', () => {
    const high = scoreFindings([finding({ severity: 'high' })]);
    const low = scoreFindings([finding({ severity: 'low' })]);
    expect(high.score).toBeLessThan(low.score);
    expect(high.grade).toBe('B');
  });

  it('discounts repeated findings from the same rule', () => {
    const once = scoreFindings([finding()]);
    const many = scoreFindings([finding(), finding({ id: '2' }), finding({ id: '3' })]);
    expect(many.score).toBeLessThan(once.score);
    expect(many.score).toBeGreaterThanOrEqual(0);
  });

  it('never goes below zero', () => {
    const findings = Array.from({ length: 20 }, (_, index) =>
      finding({ id: String(index), ruleId: `rule-${index}`, severity: 'high' }),
    );
    expect(scoreFindings(findings).score).toBe(0);
    expect(scoreFindings(findings).grade).toBe('F');
  });
});

describe('countBySeverity', () => {
  it('counts every severity bucket', () => {
    const severities: Severity[] = ['high', 'low', 'low', 'info'];
    const counts = countBySeverity(severities.map((severity, index) => finding({ id: String(index), severity })));
    expect(counts).toEqual({ high: 1, medium: 0, low: 2, info: 1 });
  });
});

describe('sortFindings', () => {
  it('orders highest severity first', () => {
    const sorted = sortFindings([
      finding({ id: 'a', severity: 'low', title: 'A' }),
      finding({ id: 'b', severity: 'high', title: 'B' }),
      finding({ id: 'c', severity: 'info', title: 'C' }),
    ]);
    expect(sorted.map((item) => item.severity)).toEqual(['high', 'low', 'info']);
  });
});

describe('dedupeFindings', () => {
  it('keeps one finding per id and counts repeats', () => {
    const result = dedupeFindings([finding({ id: 'x' }), finding({ id: 'x' }), finding({ id: 'x' })]);
    expect(result).toHaveLength(1);
    expect(result[0]?.occurrences).toBe(3);
  });

  it('never copies request URLs into the detail', () => {
    const result = dedupeFindings([
      finding({ id: 'x', detail: 'Original.', url: 'https://app.example.com/a?token=secret' }),
      finding({ id: 'x', url: 'https://app.example.com/b?token=other' }),
    ]);
    expect(result[0]?.detail).toBe('Original.');
  });
});
