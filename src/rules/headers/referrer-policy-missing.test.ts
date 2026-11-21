import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './referrer-policy-missing';

describe('header-referrer-policy-missing', () => {
  it('flags a missing policy', () => {
    expect(rule.evaluate(makeContext())[0]?.key).toBe('missing');
  });

  it('flags leaky policies', () => {
    expect(rule.evaluate(makeContext({ responseHeaders: { 'referrer-policy': 'unsafe-url' } }))).toHaveLength(1);
  });

  it('accepts strict-origin-when-cross-origin', () => {
    expect(
      rule.evaluate(makeContext({ responseHeaders: { 'referrer-policy': 'strict-origin-when-cross-origin' } })),
    ).toEqual([]);
  });
});
