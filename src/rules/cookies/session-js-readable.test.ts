import { describe, expect, it } from 'vitest';
import { cookie, makeContext } from '../../test-utils';
import rule from './session-js-readable';

describe('cookie-session-js-readable', () => {
  it('flags a script-readable session cookie', () => {
    const hits = rule.evaluate(makeContext({}, [cookie({ name: 'connect.sid', httpOnly: false })]));
    expect(hits).toHaveLength(1);
    expect(rule.severity).toBe('high');
  });

  it('ignores non-session cookies', () => {
    expect(rule.evaluate(makeContext({}, [cookie({ name: 'theme', httpOnly: false })]))).toEqual([]);
  });

  it('ignores HttpOnly session cookies', () => {
    expect(rule.evaluate(makeContext({}, [cookie({ name: 'session_id' })]))).toEqual([]);
  });
});
