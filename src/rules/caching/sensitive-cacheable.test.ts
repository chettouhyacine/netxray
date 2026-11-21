import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './sensitive-cacheable';

describe('cache-sensitive-response', () => {
  it('flags a Set-Cookie response with max-age', () => {
    const hits = rule.evaluate(
      makeContext({
        setCookie: ['sid=abc; HttpOnly'],
        responseHeaders: { 'cache-control': 'public, max-age=600' },
        cacheControl: 'public, max-age=600',
      }),
    );
    expect(hits).toHaveLength(1);
  });

  it('flags authorized responses without private/no-store', () => {
    const hits = rule.evaluate(
      makeContext({
        requestHeaders: { authorization: 'Bearer x' },
        responseHeaders: { 'cache-control': 'max-age=60' },
        cacheControl: 'max-age=60',
      }),
    );
    expect(hits).toHaveLength(1);
  });

  it('accepts private/no-store and non-sensitive responses', () => {
    expect(
      rule.evaluate(
        makeContext({
          setCookie: ['sid=abc'],
          responseHeaders: { 'cache-control': 'private, no-store' },
          cacheControl: 'private, no-store',
        }),
      ),
    ).toEqual([]);
    expect(rule.evaluate(makeContext())).toEqual([]);
  });
});
