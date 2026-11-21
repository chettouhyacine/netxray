import { describe, expect, it } from 'vitest';
import { makeContext, makeJwt } from '../../test-utils';
import rule from './alg-none';

describe('jwt-alg-none', () => {
  it('flags an unsigned token', () => {
    const token = makeJwt({ alg: 'none' }, { sub: 'admin' }, '');
    const hits = rule.evaluate(
      makeContext({ mimeType: 'application/json', responseBodyText: `{"token":"${token}"}` }),
    );
    expect(hits).toHaveLength(1);
    expect(rule.severity).toBe('high');
  });

  it('accepts signed tokens', () => {
    const token = makeJwt({ alg: 'HS256' }, { sub: 'x' });
    expect(rule.evaluate(makeContext({ responseBodyText: token }))).toEqual([]);
  });
});
