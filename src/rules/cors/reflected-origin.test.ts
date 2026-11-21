import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './reflected-origin';

const base = {
  requestHeaders: { origin: 'https://evil.example' },
  responseHeaders: {
    'access-control-allow-origin': 'https://evil.example',
    'access-control-allow-credentials': 'true',
  },
};

describe('cors-reflected-origin', () => {
  it('flags a foreign origin echoed back with credentials', () => {
    const hits = rule.evaluate(makeContext(base));
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toContain('https://evil.example');
  });

  it('does not flag the page’s own origin', () => {
    expect(
      rule.evaluate(
        makeContext({
          requestHeaders: { origin: 'https://app.example.com' },
          responseHeaders: { 'access-control-allow-origin': 'https://app.example.com' },
        }),
      ),
    ).toEqual([]);
  });

  it('ignores wildcards and missing Origin headers', () => {
    expect(
      rule.evaluate(
        makeContext({
          requestHeaders: { origin: 'https://evil.example' },
          responseHeaders: { 'access-control-allow-origin': '*' },
        }),
      ),
    ).toEqual([]);
    expect(rule.evaluate(makeContext({ responseHeaders: { 'access-control-allow-origin': 'https://x.test' } }))).toEqual([]);
  });
});
