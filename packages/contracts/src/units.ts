/**
 * INVARIANT 10. Money and percentages never touch a float.
 *
 * A discount compared as 0.1 + 0.2 > 0.3 authorizes a payout nobody approved. These
 * branded integer types make the mistake a compile error rather than a production
 * incident.
 */

declare const BasisPointsBrand: unique symbol;
declare const MinorUnitsBrand: unique symbol;

/** Integer basis points. 1,000 bps = 10%. prd.md §8.1. */
export type BasisPoints = number & { readonly [BasisPointsBrand]: true };

/** Integer minor units of a currency (paise, cents). Always carries a currency alongside. */
export type MinorUnits = number & { readonly [MinorUnitsBrand]: true };

export interface Money {
  readonly amount: MinorUnits;
  /** ISO 4217, uppercase. */
  readonly currency: string;
}

/** Discounts outside 0..10000 bps are not "clamped" — they are invalid input. */
export const MAX_BASIS_POINTS = 10_000;

export function toBasisPoints(value: number): BasisPoints {
  if (!Number.isInteger(value)) {
    throw new TypeError(`basis points must be an integer, received ${value}`);
  }
  if (value < 0 || value > MAX_BASIS_POINTS) {
    throw new RangeError(`basis points must be within 0..${MAX_BASIS_POINTS}, received ${value}`);
  }
  return value as BasisPoints;
}

export function toMinorUnits(value: number): MinorUnits {
  if (!Number.isInteger(value)) {
    throw new TypeError(`minor units must be an integer, received ${value}`);
  }
  if (!Number.isSafeInteger(value)) {
    throw new RangeError(`minor units exceed safe integer range: ${value}`);
  }
  return value as MinorUnits;
}
