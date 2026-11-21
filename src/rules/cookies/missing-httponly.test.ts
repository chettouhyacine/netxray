import { describe, expect, it } from 'vitest';
import { cookie, makeContext } from '../../test-utils';
import rule from './missing-httponly';

describe('cookie-missing-httponly', () => {
  it('flags cookies without HttpOnly', () => {
    const hits = rule.evaluate(makeContext({}, [cookie({ httpOnly: false })]));
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toContain('`sid`');
    expect(hits[0]?.evidence).not.toContain('super-secret');
  });

  it('is quiet when HttpOnly is present', () => {
    expect(rule.evaluate(makeContext({}, [cookie()]))).toEqual([]);
  });

  it('falls back to Set-Cookie headers', () => {
    const ctx = makeContext({ setCookie: ['theme=dark; Path=/'] });
    expect(rule.evaluate(ctx)[0]?.message).toContain('theme');
  });

  it('ships three framework fixes', () => {
    expect(rule.remediation.map((item) => item.framework)).toEqual(['express', 'nextjs', 'nginx']);
    expect(rule.severity).toBe('medium');
  });
});
