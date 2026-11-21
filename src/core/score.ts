import type { Finding, ScoreResult, Severity } from './types';

export const SEVERITY_ORDER: Record<Severity, number> = {
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** Points deducted from a perfect score when a rule fires at least once. */
const DEDUCTION: Record<Severity, number> = {
  high: 20,
  medium: 9,
  low: 4,
  info: 1,
};

/** Repeat findings of the same rule count less; the first one is the loudest. */
const REPEAT_DEDUCTION: Record<Severity, number> = {
  high: 4,
  medium: 2,
  low: 1,
  info: 0,
};

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/**
 * Score = 100 minus per-rule deductions. The first occurrence of a rule costs
 * the full amount, repeats cost a fraction, so a hundred missing headers on a
 * hundred assets cannot drown out a different high-severity problem.
 */
export function scoreFindings(findings: Finding[]): ScoreResult {
  const perRule = new Map<string, Finding[]>();
  for (const finding of findings) {
    const list = perRule.get(finding.ruleId) ?? [];
    list.push(finding);
    perRule.set(finding.ruleId, list);
  }

  let deduction = 0;
  for (const [, group] of perRule) {
    const severity = group[0]?.severity ?? 'info';
    deduction += DEDUCTION[severity];
    deduction += Math.min(3, group.length - 1) * REPEAT_DEDUCTION[severity];
  }

  const score = Math.max(0, Math.min(100, Math.round(100 - deduction)));
  return {
    score,
    grade: score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F',
    counts: countBySeverity(findings),
  };
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (bySeverity !== 0) return bySeverity;
    return a.title.localeCompare(b.title);
  });
}

/**
 * Removes duplicate findings produced by the same rule for the same object.
 * The first occurrence is kept; repeats only increment a count, so a finding
 * never copies raw request URLs (which may contain credentials) into `detail`.
 */
export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const finding of findings) {
    const existing = seen.get(finding.id);
    if (!existing) {
      seen.set(finding.id, { ...finding, occurrences: 1 });
      continue;
    }
    existing.occurrences = (existing.occurrences ?? 1) + 1;
  }
  return Array.from(seen.values());
}
