import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './frame-options-missing';

describe('header-frame-options-missing', () => {
  it('flags a document with neither control', () => {
    expect(rule.evaluate(makeContext())).toHaveLength(1);
  });

  it('accepts effective X-Frame-Options or frame-ancestors values', () => {
    expect(rule.evaluate(makeContext({ responseHeaders: { 'x-frame-options': 'DENY' } }))).toEqual([]);
    expect(rule.evaluate(makeContext({ responseHeaders: { 'x-frame-options': 'SAMEORIGIN' } }))).toEqual([]);
    expect(
      rule.evaluate(
        makeContext({ responseHeaders: { 'content-security-policy': "frame-ancestors 'none'" } }),
      ),
    ).toEqual([]);
    expect(
      rule.evaluate(
        makeContext({ responseHeaders: { 'content-security-policy': "frame-ancestors 'self'" } }),
      ),
    ).toEqual([]);
  });

  it('does not accept controls that still allow arbitrary origins', () => {
    expect(
      rule.evaluate(makeContext({ responseHeaders: { 'content-security-policy': 'frame-ancestors *' } })),
    ).toHaveLength(1);
    expect(
      rule.evaluate(makeContext({ responseHeaders: { 'content-security-policy': 'frame-ancestors https:' } })),
    ).toHaveLength(1);
    expect(
      rule.evaluate(makeContext({ responseHeaders: { 'x-frame-options': 'ALLOW-FROM https://app.example.com' } })),
    ).toHaveLength(1);
  });
});
