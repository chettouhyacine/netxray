import { describe, expect, it } from 'vitest';
import { cookie, makeContext } from '../../test-utils';
import rule from './broad-scope';

describe('cookie-broad-scope', () => {
  it('flags cookies scoped to a parent domain', () => {
    const ctx = makeContext({ url: 'https://app.example.com/' }, [
      cookie({ domain: '.example.com', hostOnly: false }),
    ]);
    const hits = rule.evaluate(ctx);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toContain('*.example.com');
  });

  it('accepts host-only cookies', () => {
    expect(rule.evaluate(makeContext({ url: 'https://app.example.com/' }, [cookie()]))).toEqual([]);
  });

  it('ignores explicit domains equal to the host', () => {
    const ctx = makeContext({ url: 'https://example.com/' }, [
      cookie({ domain: '.example.com', hostOnly: false }),
    ]);
    expect(rule.evaluate(ctx)).toEqual([]);
  });
});
