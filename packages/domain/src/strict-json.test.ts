import { describe, expect, it } from 'vitest';
import { DEFAULT_LIMITS, parseStrictJson, StrictJsonError } from './strict-json.js';

describe('duplicate keys', () => {
  it('rejects a duplicated key instead of silently keeping the last', () => {
    // JSON.parse yields 5000 here and discards 500. A validator reading one value
    // while the destination reads the other is a parser differential, and the signed
    // fingerprint would cover only one of them.
    const text = '{"discount_basis_points": 500, "discount_basis_points": 5000}';
    expect(JSON.parse(text)).toEqual({ discount_basis_points: 5000 }); // what we refuse to do
    expect(() => parseStrictJson(text)).toThrow(StrictJsonError);
    expect(() => parseStrictJson(text)).toThrow(/duplicate key/);
  });

  it('rejects duplicates nested inside an object', () => {
    expect(() => parseStrictJson('{"a":{"b":1,"b":2}}')).toThrow(/duplicate key/);
  });

  it('allows the same key name in sibling objects', () => {
    expect(parseStrictJson('{"a":{"x":1},"b":{"x":2}}')).toEqual({ a: { x: 1 }, b: { x: 2 } });
  });
});

describe('prototype safety', () => {
  it('treats __proto__ as an ordinary own key without polluting anything', () => {
    const parsed = parseStrictJson('{"__proto__":{"polluted":true}}') as Record<string, unknown>;
    expect(Object.hasOwn(parsed, '__proto__')).toBe(true);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });

  it('produces objects with no prototype chain to walk', () => {
    expect(Object.getPrototypeOf(parseStrictJson('{"a":1}'))).toBeNull();
  });
});

describe('bounds', () => {
  it('rejects nesting past the depth limit before evaluating anything', () => {
    const deep = '['.repeat(20) + ']'.repeat(20);
    expect(() => parseStrictJson(deep)).toThrow(/depth/);
  });

  it('rejects a payload over the size limit', () => {
    const big = JSON.stringify({ pad: 'x'.repeat(DEFAULT_LIMITS.maxBytes) });
    expect(() => parseStrictJson(big)).toThrow(/limit/);
  });

  it('rejects an object with too many keys', () => {
    const wide = `{${Array.from({ length: 100 }, (_, i) => `"k${i}":1`).join(',')}}`;
    expect(() => parseStrictJson(wide)).toThrow(/keys/);
  });
});

describe('numbers', () => {
  it('rejects an integer that cannot survive a round trip', () => {
    // JSON.parse('9007199254740993') silently yields 9007199254740992.
    expect(() => parseStrictJson('{"n":9007199254740993}')).toThrow(/safe range/);
  });

  it('rejects a non-finite exponent', () => {
    expect(() => parseStrictJson('{"n":1e999}')).toThrow(/non-finite/);
  });

  it('accepts ordinary integers and decimals', () => {
    expect(parseStrictJson('{"a":1500,"b":-3,"c":1.5}')).toEqual({ a: 1500, b: -3, c: 1.5 });
  });
});

describe('malformed input', () => {
  it.each([
    ['{"a":1,}', 'trailing comma'],
    ["{'a':1}", 'single quotes'],
    ['{a:1}', 'unquoted key'],
    ['{"a":undefined}', 'undefined'],
    ['{"a":01}', 'leading zero run'],
    ['{"a":"\u0001"}', 'raw control character'],
    ['{"a":1}{"b":2}', 'trailing content'],
    ['', 'empty'],
  ])('rejects %j (%s)', (text) => {
    expect(() => parseStrictJson(text)).toThrow(StrictJsonError);
  });

  it('accepts a normal request body', () => {
    expect(
      parseStrictJson(
        '{"action":"crm.discount.apply","parameters":{"discount_basis_points":1500}}',
      ),
    ).toEqual({
      action: 'crm.discount.apply',
      parameters: { discount_basis_points: 1500 },
    });
  });
});
