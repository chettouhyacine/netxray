import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './permissive';

describe('cors-permissive', () => {
  it('flags destructive methods', () => {
    const hits = rule.evaluate(
      makeContext({
        responseHeaders: {
          'access-control-allow-origin': 'https://app.example.com',
          'access-control-allow-methods': 'GET, DELETE, PATCH',
        },
      }),
    );
    expect(hits[0]?.message).toContain('DELETE');
  });

  it('flags wildcard headers', () => {
    const hits = rule.evaluate(
      makeContext({
        responseHeaders: {
          'access-control-allow-origin': 'https://app.example.com',
          'access-control-allow-headers': '*',
        },
      }),
    );
    expect(hits.some((hit) => hit.key === 'headers')).toBe(true);
  });

  it('accepts a minimal policy and ignores non-CORS responses', () => {
    expect(
      rule.evaluate(
        makeContext({
          responseHeaders: {
            'access-control-allow-origin': 'https://app.example.com',
            'access-control-allow-methods': 'GET, POST',
            'access-control-allow-headers': 'Content-Type, Authorization',
          },
        }),
      ),
    ).toEqual([]);
    expect(rule.evaluate(makeContext())).toEqual([]);
  });
});
