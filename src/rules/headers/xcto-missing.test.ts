import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './xcto-missing';

describe('header-xcto-missing', () => {
  it('flags a missing header', () => {
    expect(rule.evaluate(makeContext())).toHaveLength(1);
  });

  it('flags a wrong value', () => {
    expect(rule.evaluate(makeContext({ responseHeaders: { 'x-content-type-options': 'sniff' } }))).toHaveLength(1);
  });

  it('accepts nosniff', () => {
    expect(rule.evaluate(makeContext({ responseHeaders: { 'x-content-type-options': 'nosniff' } }))).toEqual([]);
  });
});
