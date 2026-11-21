import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './wildcard-credentials';

describe('cors-wildcard-credentials', () => {
  it('flags * with credentials', () => {
    const hits = rule.evaluate(
      makeContext({
        responseHeaders: {
          'access-control-allow-origin': '*',
          'access-control-allow-credentials': 'true',
        },
      }),
    );
    expect(hits).toHaveLength(1);
    expect(rule.severity).toBe('high');
  });

  it('ignores wildcard without credentials and credentials without wildcard', () => {
    expect(rule.evaluate(makeContext({ responseHeaders: { 'access-control-allow-origin': '*' } }))).toEqual([]);
    expect(
      rule.evaluate(
        makeContext({
          responseHeaders: {
            'access-control-allow-origin': 'https://app.example.com',
            'access-control-allow-credentials': 'true',
          },
        }),
      ),
    ).toEqual([]);
  });
});
