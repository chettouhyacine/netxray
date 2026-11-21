import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './certificate-expiring';

const days = (count: number) => Date.now() + count * 24 * 60 * 60 * 1000;

describe('tls-certificate-expiring', () => {
  it('flags certificates expiring within 14 days', () => {
    const hits = rule.evaluate(makeContext({ tls: { certificate: { validTo: days(3) } } }));
    expect(hits[0]?.message).toMatch(/expires in [23] day/);
  });

  it('flags expired certificates', () => {
    const hits = rule.evaluate(makeContext({ tls: { certificate: { validTo: days(-2) } } }));
    expect(hits[0]?.message).toContain('expired');
  });

  it('ignores healthy and unknown certificates', () => {
    expect(rule.evaluate(makeContext({ tls: { certificate: { validTo: days(90) } } }))).toEqual([]);
    expect(rule.evaluate(makeContext())).toEqual([]);
  });
});
