import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './insecure-http';

describe('insecure-http', () => {
  it('flags plain HTTP documents', () => {
    const hits = rule.evaluate(
      makeContext({
        url: 'http://shop.example.com/',
        pageUrl: 'http://shop.example.com/',
        pageOrigin: 'http://shop.example.com',
      }),
    );
    expect(hits).toHaveLength(1);
  });

  it('accepts HTTPS documents and localhost dev servers', () => {
    expect(rule.evaluate(makeContext())).toEqual([]);
    expect(
      rule.evaluate(
        makeContext({
          url: 'http://localhost:4000/',
          pageUrl: 'http://localhost:4000/',
          pageOrigin: 'http://localhost:4000',
        }),
      ),
    ).toEqual([]);
  });

  it('ignores non-document resources', () => {
    expect(rule.evaluate(makeContext({ url: 'http://cdn.example.com/a.js', resourceType: 'script' }))).toEqual([]);
  });
});
