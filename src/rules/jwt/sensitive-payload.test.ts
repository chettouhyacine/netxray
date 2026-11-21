import { describe, expect, it } from 'vitest';
import { makeContext, makeJwt } from '../../test-utils';
import rule from './sensitive-payload';

describe('jwt-sensitive-payload', () => {
  it('flags passwords and API keys in the payload', () => {
    const token = makeJwt({ alg: 'HS256' }, { sub: 'x', password: 'hunter2', api_key: 'abc' });
    const hits = rule.evaluate(makeContext({ responseBodyText: token }));
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toContain('password');
    expect(rule.severity).toBe('high');
  });

  it('accepts identifier-only claims', () => {
    const token = makeJwt({ alg: 'HS256' }, { sub: 'x', role: 'user' });
    expect(rule.evaluate(makeContext({ responseBodyText: token }))).toEqual([]);
  });
});
