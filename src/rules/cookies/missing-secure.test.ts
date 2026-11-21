import { describe, expect, it } from 'vitest';
import { cookie, makeContext } from '../../test-utils';
import rule from './missing-secure';

describe('cookie-missing-secure', () => {
  it('flags non-Secure cookies on HTTPS pages', () => {
    const hits = rule.evaluate(makeContext({}, [cookie({ secure: false })]));
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toContain('Secure');
  });

  it('ignores non-session cookies and HTTP pages', () => {
    expect(rule.evaluate(makeContext({}, [cookie({ name: 'prefs', secure: false })]))).toEqual([]);
    expect(rule.evaluate(makeContext({}, [cookie()]))).toEqual([]);
    const httpCtx = makeContext(
      { pageOrigin: 'http://app.example.com', pageUrl: 'http://app.example.com/', url: 'http://app.example.com/' },
      [cookie({ secure: false })],
    );
    expect(rule.evaluate(httpCtx)).toEqual([]);
  });
});
