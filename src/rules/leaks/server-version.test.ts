import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './server-version';

describe('server-version-disclosure', () => {
  it('flags Server and X-Powered-By headers', () => {
    const hits = rule.evaluate(
      makeContext({ responseHeaders: { server: 'nginx/1.18.0', 'x-powered-by': 'Express' } }),
    );
    expect(hits).toHaveLength(2);
    expect(hits.map((hit) => hit.key)).toEqual(['server', 'x-powered-by']);
  });

  it('is quiet without banners', () => {
    expect(rule.evaluate(makeContext({ responseHeaders: { 'content-type': 'text/html' } }))).toEqual([]);
  });
});
