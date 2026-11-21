import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './permissions-policy-missing';

describe('header-permissions-policy-missing', () => {
  it('flags a missing header as info', () => {
    expect(rule.evaluate(makeContext())).toHaveLength(1);
    expect(rule.severity).toBe('info');
  });

  it('accepts a policy', () => {
    expect(rule.evaluate(makeContext({ responseHeaders: { 'permissions-policy': 'camera=()' } }))).toEqual([]);
  });
});
