import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './unknown-origin';

describe('third-party-unknown', () => {
  it('flags an unexpected third-party host as info', () => {
    const hits = rule.evaluate(makeContext({ url: 'https://cdn.other.com/lib.js' }));
    expect(hits).toHaveLength(1);
    expect(rule.severity).toBe('info');
  });

  it('ignores same-site, tracker and local hosts', () => {
    expect(rule.evaluate(makeContext({ url: 'https://api.example.com/data' }))).toEqual([]);
    expect(rule.evaluate(makeContext({ url: 'https://www.google-analytics.com/collect' }))).toEqual([]);
    expect(rule.evaluate(makeContext({ url: 'http://localhost:4000/api' }))).toEqual([]);
  });
});
