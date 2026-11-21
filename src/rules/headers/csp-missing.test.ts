import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './csp-missing';

describe('header-csp-missing', () => {
  it('flags documents without CSP', () => {
    const hits = rule.evaluate(makeContext());
    expect(hits).toHaveLength(1);
    expect(rule.severity).toBe('high');
  });

  it('is quiet when CSP is present', () => {
    expect(rule.evaluate(makeContext({ responseHeaders: { 'content-security-policy': "default-src 'self'" } }))).toEqual(
      [],
    );
  });
});
