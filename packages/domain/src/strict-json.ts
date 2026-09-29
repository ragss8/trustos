/**
 * A strict JSON parser (architecture.md §8.1 step 2: "reject duplicate JSON keys").
 *
 * JSON.parse silently keeps the LAST value for a duplicated key. That is a parser
 * differential: a gateway validating {"discount_basis_points": 500, "discount_basis_points": 5000}
 * may read 500 while the destination reads 5000, or vice versa, and the signed
 * fingerprint would cover only one of them. The safe answer is to refuse the document.
 *
 * Also enforces depth and size bounds before anything is hashed or evaluated (§7.1),
 * so a deeply nested payload cannot cost CPU on the decision path.
 */

export type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };

export interface StrictJsonLimits {
  readonly maxDepth: number;
  readonly maxBytes: number;
  readonly maxKeysPerObject: number;
}

export const DEFAULT_LIMITS: StrictJsonLimits = {
  maxDepth: 8,
  maxBytes: 16 * 1024, // 16 KiB request bound, NFR-01
  maxKeysPerObject: 64,
};

export class StrictJsonError extends Error {
  constructor(
    readonly code:
      | 'DUPLICATE_KEY'
      | 'DEPTH_EXCEEDED'
      | 'SIZE_EXCEEDED'
      | 'TOO_MANY_KEYS'
      | 'MALFORMED'
      | 'UNSUPPORTED_NUMBER',
    message: string,
    readonly position?: number,
  ) {
    super(message);
    this.name = 'StrictJsonError';
  }
}

class Parser {
  #i = 0;
  constructor(
    private readonly text: string,
    private readonly limits: StrictJsonLimits,
  ) {}

  parse(): JsonValue {
    this.#ws();
    const value = this.#value(0);
    this.#ws();
    if (this.#i !== this.text.length) {
      throw new StrictJsonError('MALFORMED', 'trailing content after JSON value', this.#i);
    }
    return value;
  }

  #fail(code: StrictJsonError['code'], message: string): never {
    throw new StrictJsonError(code, message, this.#i);
  }

  #ws(): void {
    while (this.#i < this.text.length) {
      const c = this.text[this.#i]!;
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') this.#i += 1;
      else break;
    }
  }

  #expect(ch: string): void {
    if (this.text[this.#i] !== ch) this.#fail('MALFORMED', `expected ${ch}`);
    this.#i += 1;
  }

  #value(depth: number): JsonValue {
    if (depth > this.limits.maxDepth) {
      this.#fail('DEPTH_EXCEEDED', `nesting exceeds depth ${this.limits.maxDepth}`);
    }
    const c = this.text[this.#i];
    if (c === undefined) this.#fail('MALFORMED', 'unexpected end of input');
    if (c === '{') return this.#object(depth);
    if (c === '[') return this.#array(depth);
    if (c === '"') return this.#string();
    if (c === 't') return this.#literal('true', true);
    if (c === 'f') return this.#literal('false', false);
    if (c === 'n') return this.#literal('null', null);
    return this.#number();
  }

  #literal<T>(word: string, value: T): T {
    if (this.text.startsWith(word, this.#i)) {
      this.#i += word.length;
      return value;
    }
    return this.#fail('MALFORMED', `expected ${word}`);
  }

  #object(depth: number): { [k: string]: JsonValue } {
    this.#expect('{');
    const out: { [k: string]: JsonValue } = Object.create(null) as { [k: string]: JsonValue };
    const seen = new Set<string>();
    this.#ws();
    if (this.text[this.#i] === '}') {
      this.#i += 1;
      return out;
    }
    for (;;) {
      this.#ws();
      const key = this.#string();
      // The whole reason this parser exists.
      if (seen.has(key)) this.#fail('DUPLICATE_KEY', `duplicate key ${JSON.stringify(key)}`);
      seen.add(key);
      if (seen.size > this.limits.maxKeysPerObject) {
        this.#fail('TOO_MANY_KEYS', `object exceeds ${this.limits.maxKeysPerObject} keys`);
      }
      this.#ws();
      this.#expect(':');
      this.#ws();
      out[key] = this.#value(depth + 1);
      this.#ws();
      const c = this.text[this.#i];
      if (c === ',') {
        this.#i += 1;
        continue;
      }
      if (c === '}') {
        this.#i += 1;
        return out;
      }
      this.#fail('MALFORMED', 'expected , or }');
    }
  }

  #array(depth: number): JsonValue[] {
    this.#expect('[');
    const out: JsonValue[] = [];
    this.#ws();
    if (this.text[this.#i] === ']') {
      this.#i += 1;
      return out;
    }
    for (;;) {
      this.#ws();
      out.push(this.#value(depth + 1));
      this.#ws();
      const c = this.text[this.#i];
      if (c === ',') {
        this.#i += 1;
        continue;
      }
      if (c === ']') {
        this.#i += 1;
        return out;
      }
      this.#fail('MALFORMED', 'expected , or ]');
    }
  }

  #string(): string {
    this.#expect('"');
    let out = '';
    for (;;) {
      const c = this.text[this.#i];
      if (c === undefined) this.#fail('MALFORMED', 'unterminated string');
      if (c === '"') {
        this.#i += 1;
        return out;
      }
      if (c === '\\') {
        this.#i += 1;
        const esc = this.text[this.#i];
        this.#i += 1;
        switch (esc) {
          case '"':
            out += '"';
            break;
          case '\\':
            out += '\\';
            break;
          case '/':
            out += '/';
            break;
          case 'b':
            out += '\b';
            break;
          case 'f':
            out += '\f';
            break;
          case 'n':
            out += '\n';
            break;
          case 'r':
            out += '\r';
            break;
          case 't':
            out += '\t';
            break;
          case 'u': {
            const hex = this.text.slice(this.#i, this.#i + 4);
            if (hex.length !== 4) this.#fail('MALFORMED', 'bad \\u escape');
            const code = Number.parseInt(hex, 16);
            if (Number.isNaN(code)) this.#fail('MALFORMED', 'bad \\u escape');
            out += String.fromCharCode(code);
            this.#i += 4;
            break;
          }
          default:
            this.#fail('MALFORMED', `bad escape \\${String(esc)}`);
        }
        continue;
      }
      // Raw control characters are not legal in a JSON string.
      if (c < ' ') this.#fail('MALFORMED', 'unescaped control character in string');
      out += c;
      this.#i += 1;
    }
  }

  #number(): number {
    const start = this.#i;
    if (this.text[this.#i] === '-') this.#i += 1;
    // JSON forbids a leading zero run. Accepting 01 is another parser differential:
    // some readers treat it as octal, others as 1.
    const firstDigit = this.text[this.#i];
    if (firstDigit === '0') {
      this.#i += 1;
      const next = this.text[this.#i];
      if (next !== undefined && next >= '0' && next <= '9') {
        this.#fail('MALFORMED', 'leading zeros are not valid JSON');
      }
    } else {
      while (
        this.#i < this.text.length &&
        this.text[this.#i]! >= '0' &&
        this.text[this.#i]! <= '9'
      ) {
        this.#i += 1;
      }
    }
    let isFloat = false;
    if (this.text[this.#i] === '.') {
      isFloat = true;
      this.#i += 1;
      while (
        this.#i < this.text.length &&
        this.text[this.#i]! >= '0' &&
        this.text[this.#i]! <= '9'
      ) {
        this.#i += 1;
      }
    }
    if (this.text[this.#i] === 'e' || this.text[this.#i] === 'E') {
      isFloat = true;
      this.#i += 1;
      if (this.text[this.#i] === '+' || this.text[this.#i] === '-') this.#i += 1;
      while (
        this.#i < this.text.length &&
        this.text[this.#i]! >= '0' &&
        this.text[this.#i]! <= '9'
      ) {
        this.#i += 1;
      }
    }
    const raw = this.text.slice(start, this.#i);
    if (raw === '' || raw === '-') this.#fail('MALFORMED', 'invalid number');
    const n = Number(raw);
    if (!Number.isFinite(n)) this.#fail('UNSUPPORTED_NUMBER', `non-finite number ${raw}`);
    // A value that cannot survive a round trip must not be hashed as if it could:
    // 1e999 and 9007199254740993 both lose information silently.
    if (!isFloat && !Number.isSafeInteger(n)) {
      this.#fail('UNSUPPORTED_NUMBER', `integer ${raw} exceeds safe range`);
    }
    return n;
  }
}

export function parseStrictJson(
  text: string,
  limits: StrictJsonLimits = DEFAULT_LIMITS,
): JsonValue {
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > limits.maxBytes) {
    throw new StrictJsonError(
      'SIZE_EXCEEDED',
      `payload is ${bytes} bytes, limit ${limits.maxBytes}`,
    );
  }
  return new Parser(text, limits).parse();
}
