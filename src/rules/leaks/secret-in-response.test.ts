import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './secret-in-response';

describe('secret-in-response', () => {
  it('flags AWS keys in a JSON response', () => {
    const hits = rule.evaluate(
      makeContext({
        mimeType: 'application/json',
        responseBodyText: '{"credentials":{"accessKeyId":"AKIAIOSFODNN7EXAMPLE"}}',
      }),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toContain('AWS');
    expect(hits[0]?.evidence).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('ignores clean responses and captured metadata without bodies', () => {
    expect(rule.evaluate(makeContext({ responseBodyText: '{"ok":true}' }))).toEqual([]);
    expect(rule.evaluate(makeContext())).toEqual([]);
  });
});
