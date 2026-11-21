import { describe, expect, it } from 'vitest';
import { makeContext } from '../../test-utils';
import rule from './verbose-error';

describe('verbose-error', () => {
  it('flags stack traces on error responses', () => {
    const hits = rule.evaluate(
      makeContext({
        status: 500,
        responseBodyText:
          'Error: connect ECONNREFUSED\n    at TCPConnectWrap.afterConnect (node:net:1595:16)\n    at /home/app/node_modules/pg/lib/client.js:12:9',
      }),
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toContain('500');
  });

  it('flags database errors on 400 responses', () => {
    expect(
      rule.evaluate(makeContext({ status: 400, responseBodyText: 'SQLSTATE[42S02]: table users not found' })),
    ).toHaveLength(1);
  });

  it('ignores successful responses and generic errors', () => {
    expect(rule.evaluate(makeContext({ status: 200, responseBodyText: 'at Foo (bar.js:1:2)' }))).toEqual([]);
    expect(rule.evaluate(makeContext({ status: 500, responseBodyText: '{"error":"Internal server error"}' }))).toEqual(
      [],
    );
  });
});
