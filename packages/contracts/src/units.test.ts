import { describe, expect, it } from 'vitest';
import { MAX_BASIS_POINTS, toBasisPoints, toMinorUnits } from './units.js';

describe('toBasisPoints', () => {
  it.each([0, 1, 1_000, 2_000, MAX_BASIS_POINTS])('accepts in-range integer %i', (v) => {
    expect(toBasisPoints(v)).toBe(v);
  });

  // prd.md §18: "Discount 25% or unassigned region -> deny even if an approver is
  // available". 2,500 bps is in range here; the DENY is a policy decision, not a
  // validation failure. Keeping these separate matters: a validation error and a
  // policy deny are different reason codes to the caller.
  it('treats 2500 bps as valid input, leaving the deny to policy', () => {
    expect(toBasisPoints(2_500)).toBe(2_500);
  });

  it.each([-1, MAX_BASIS_POINTS + 1, 99_999])('rejects out-of-range %i', (v) => {
    expect(() => toBasisPoints(v)).toThrow(RangeError);
  });

  // The whole reason for the branded integer type.
  it.each([10.5, 0.1 + 0.2, NaN, Infinity])('rejects non-integer %p', (v) => {
    expect(() => toBasisPoints(v)).toThrow(TypeError);
  });
});

describe('toMinorUnits', () => {
  it('accepts zero and large safe integers', () => {
    expect(toMinorUnits(0)).toBe(0);
    expect(toMinorUnits(Number.MAX_SAFE_INTEGER)).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('rejects values past the safe integer boundary rather than silently rounding', () => {
    expect(() => toMinorUnits(Number.MAX_SAFE_INTEGER + 2)).toThrow(RangeError);
  });

  it.each([1.5, NaN, Infinity])('rejects non-integer %p', (v) => {
    expect(() => toMinorUnits(v)).toThrow(TypeError);
  });

  it('allows negative amounts, which represent credits, not invalid input', () => {
    expect(toMinorUnits(-500)).toBe(-500);
  });
});
