import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './mixed-content';

describe('mixed-content', () => {
  it('flags HTTP subresources on an HTTPS page', () => {
    const hits = rule.evaluate(
      makeContext({ url: 'http://cdn.example.com/lib.js', resourceType: 'script' }),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.detail).toContain('can be modified');
  });

  it('ignores HTTP documents (handled by insecure-http)', () => {
    const ctx = makeContext({
      url: 'http://app.example.com/',
      pageOrigin: 'http://app.example.com',
      resourceType: 'document',
    });
    expect(rule.evaluate(ctx)).toEqual([]);
  });

  it('ignores secure and localhost requests', () => {
    expect(rule.evaluate(makeContext({ url: 'https://cdn.example.com/lib.js' }))).toEqual([]);
    expect(rule.evaluate(makeContext({ url: 'http://localhost:3000/lib.js' }))).toEqual([]);
  });
});
