import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './tracker';

describe('third-party-tracker', () => {
  it('flags known analytics hosts and subdomains', () => {
    expect(rule.evaluate(makeContext({ url: 'https://www.google-analytics.com/collect' }))).toHaveLength(1);
    expect(rule.evaluate(makeContext({ url: 'https://region1.google-analytics.com/g/collect' }))).toHaveLength(1);
  });

  it('ignores first-party and non-tracker requests', () => {
    expect(rule.evaluate(makeContext({ url: 'https://app.example.com/api' }))).toEqual([]);
    expect(rule.evaluate(makeContext({ url: 'https://cdn.jsdelivr.net/npm/react.js' }))).toEqual([]);
  });
});
