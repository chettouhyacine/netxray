import { describe, expect, it } from 'vitest';
import { ATTACK_IDS } from '../core/attacks';
import { rules } from './index';
import { RULE_CATALOG, ruleMeta } from './catalog';

describe('rule catalog', () => {
  it('has metadata for every registered rule', () => {
    for (const rule of rules) {
      expect(RULE_CATALOG[rule.id], `missing catalog metadata for ${rule.id}`).toBeDefined();
    }
  });

  it('maps only known attack classes', () => {
    for (const meta of Object.values(RULE_CATALOG)) {
      if (meta.attack) expect(ATTACK_IDS).toContain(meta.attack);
    }
  });

  it('makes every v1 finding high confidence', () => {
    for (const meta of Object.values(RULE_CATALOG)) {
      if (meta.attack) expect(meta.confidence).toBe('high');
    }
  });

  it('covers each of the four v1 attacks with at least one rule', () => {
    const covered = new Set(
      Object.values(RULE_CATALOG)
        .map((meta) => meta.attack)
        .filter((attack): attack is NonNullable<typeof attack> => Boolean(attack)),
    );
    for (const attack of ATTACK_IDS) expect(covered).toContain(attack);
  });

  it('falls back safely for unknown ids', () => {
    expect(ruleMeta('not-a-rule')).toEqual({ confidence: 'medium' });
  });
});
