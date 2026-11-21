import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule, { matchesHostname } from './hostname-mismatch';

describe('matchesHostname', () => {
  it('supports exact and single-label wildcards', () => {
    expect(matchesHostname('example.com', 'example.com')).toBe(true);
    expect(matchesHostname('*.example.com', 'api.example.com')).toBe(true);
    expect(matchesHostname('*.example.com', 'a.b.example.com')).toBe(false);
    expect(matchesHostname('*.example.com', 'example.com')).toBe(false);
    expect(matchesHostname('', 'example.com')).toBe(false);
  });
});

describe('tls-hostname-mismatch', () => {
  it('flags a certificate for another host', () => {
    const hits = rule.evaluate(
      makeContext({
        url: 'https://app.example.com/',
        tls: { certificate: { subjectName: 'other.example', sanList: ['other.example'] } },
      }),
    );
    expect(hits).toHaveLength(1);
    expect(rule.severity).toBe('high');
  });

  it('accepts a matching SAN and ignores missing TLS data', () => {
    expect(
      rule.evaluate(
        makeContext({
          url: 'https://app.example.com/',
          tls: { certificate: { subjectName: 'app.example.com', sanList: ['*.example.com'] } },
        }),
      ),
    ).toEqual([]);
    expect(rule.evaluate(makeContext())).toEqual([]);
  });
});
