import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './outdated-protocol';

describe('tls-outdated-protocol', () => {
  it('flags TLS 1.0 and 1.1', () => {
    expect(rule.evaluate(makeContext({ tls: { protocol: 'TLS 1.0' } }))).toHaveLength(1);
    expect(rule.evaluate(makeContext({ tls: { protocol: 'TLSv1.1' } }))).toHaveLength(1);
  });

  it('accepts TLS 1.2/1.3 and missing data', () => {
    expect(rule.evaluate(makeContext({ tls: { protocol: 'TLS 1.3' } }))).toEqual([]);
    expect(rule.evaluate(makeContext())).toEqual([]);
  });
});
