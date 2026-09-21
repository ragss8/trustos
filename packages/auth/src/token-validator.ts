import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyOptions } from 'jose';

/**
 * Access-token validation (architecture.md §5.1, §5.2).
 *
 * "Validate issuer, intended audience, expiry, signature algorithm and key identity.
 * Reject unexpected token types/algorithms."
 *
 * The algorithm allowlist is the part that is easy to leave out and expensive to
 * leave out. A verifier that accepts whatever `alg` the token header names will
 * accept `none`, and will accept HS256 signed with a public key it treats as a shared
 * secret. Both turn "verified" into "parsed". jose refuses `none` outright, and this
 * module pins the accepted set explicitly rather than inheriting a default.
 */

/**
 * 'unknown' is deliberate. A gate that requires an interactively authenticated human
 * must fail closed on a token it cannot classify, rather than guessing. Inferring
 * 'human' from the ABSENCE of a machine marker is how a service account ends up
 * satisfying an MFA requirement.
 */
export type TokenType = 'human' | 'machine' | 'unknown';

export interface ValidatedToken {
  readonly subject: string;
  readonly issuer: string;
  readonly audience: readonly string[];
  readonly clientId: string | undefined;
  readonly scopes: readonly string[];
  readonly type: TokenType;
  /** Present only when the identity provider asserted it. Never inferred. */
  readonly authenticatedAt: Date | undefined;
  readonly amr: readonly string[];
  readonly expiresAt: Date;
  readonly raw: JWTPayload;
}

export class TokenValidationError extends Error {
  constructor(
    readonly code:
      | 'INVALID_CREDENTIAL'
      | 'UNSUPPORTED_ALGORITHM'
      | 'AUDIENCE_MISMATCH'
      | 'ISSUER_MISMATCH'
      | 'TOKEN_EXPIRED'
      | 'MALFORMED_TOKEN',
    message: string,
  ) {
    super(message);
    this.name = 'TokenValidationError';
  }
}

export interface TokenValidatorConfig {
  readonly issuer: string;
  readonly audience: string;
  /** Asymmetric only. A symmetric algorithm here would enable key confusion. */
  readonly algorithms?: readonly string[];
  /** Seconds of permitted clock skew. Kept small; §13.2 alerts on real drift. */
  readonly clockToleranceSeconds?: number;
}

const DEFAULT_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384'] as const;

function asStringArray(value: unknown): string[] {
  if (typeof value === 'string') return value.split(' ').filter(Boolean);
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  return [];
}

export class TokenValidator {
  readonly #jwks: ReturnType<typeof createRemoteJWKSet>;
  readonly #options: JWTVerifyOptions;

  constructor(private readonly config: TokenValidatorConfig) {
    const algorithms = config.algorithms ?? DEFAULT_ALGORITHMS;
    if (algorithms.some((a) => a.startsWith('HS') || a === 'none')) {
      // Refuse at construction. A symmetric or absent algorithm on a JWKS-backed
      // verifier means any holder of the public key can mint tokens.
      throw new TokenValidationError(
        'UNSUPPORTED_ALGORITHM',
        'symmetric and "none" algorithms are not permitted for provider-issued tokens',
      );
    }
    // jose caches keys and refetches on unknown kid, with its own rate limiting. §13.2:
    // an unknown key during a provider outage is rejected, never assumed valid.
    this.#jwks = createRemoteJWKSet(new URL(`${config.issuer}/protocol/openid-connect/certs`));
    this.#options = {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: [...algorithms],
      clockTolerance: config.clockToleranceSeconds ?? 5,
    };
  }

  async validate(token: string): Promise<ValidatedToken> {
    if (typeof token !== 'string' || token.length === 0) {
      throw new TokenValidationError('MALFORMED_TOKEN', 'token is empty');
    }

    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, this.#jwks, this.#options));
    } catch (error) {
      const code = (error as { code?: string }).code;
      switch (code) {
        case 'ERR_JWT_EXPIRED':
          throw new TokenValidationError('TOKEN_EXPIRED', 'token has expired');
        case 'ERR_JWT_CLAIM_VALIDATION_FAILED': {
          const claim = (error as { claim?: string }).claim;
          if (claim === 'aud')
            throw new TokenValidationError('AUDIENCE_MISMATCH', 'token audience does not match');
          if (claim === 'iss')
            throw new TokenValidationError('ISSUER_MISMATCH', 'token issuer does not match');
          throw new TokenValidationError('INVALID_CREDENTIAL', `claim ${claim} failed validation`);
        }
        case 'ERR_JOSE_ALG_NOT_ALLOWED':
          throw new TokenValidationError(
            'UNSUPPORTED_ALGORITHM',
            'token algorithm is not in the permitted set',
          );
        default:
          // Deliberately unspecific: signature failure and unknown-key must not be
          // distinguishable to a caller probing the endpoint.
          throw new TokenValidationError('INVALID_CREDENTIAL', 'token could not be verified');
      }
    }

    if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
      throw new TokenValidationError('MALFORMED_TOKEN', 'token has no subject');
    }
    if (typeof payload.exp !== 'number') {
      throw new TokenValidationError('MALFORMED_TOKEN', 'token has no expiry');
    }

    // Claim shapes differ by provider. These are Keycloak's (verified against 26.x,
    // where the session claim is `sid`; older docs say `session_state`, which this
    // version no longer emits). Both branches require POSITIVE evidence:
    //
    //   client_id present -> service-account token (client credentials)
    //   sid present       -> interactive session
    //
    // Anything else is 'unknown' and satisfies neither kind of gate.
    const serviceAccountClient =
      typeof payload['client_id'] === 'string' ? payload['client_id'] : undefined;
    const hasSession = typeof payload['sid'] === 'string' && payload['sid'].length > 0;
    const type: TokenType =
      serviceAccountClient !== undefined ? 'machine' : hasSession ? 'human' : 'unknown';

    // azp is the authorized party for both kinds; client_id appears only on machine
    // tokens. Preferring client_id keeps a service account attributable to its client.
    const clientId =
      serviceAccountClient ?? (typeof payload['azp'] === 'string' ? payload['azp'] : undefined);

    return {
      subject: payload.sub,
      issuer: this.config.issuer,
      audience: asStringArray(payload.aud),
      clientId,
      scopes: asStringArray(payload['scope']),
      type,
      authenticatedAt:
        typeof payload['auth_time'] === 'number'
          ? new Date(payload['auth_time'] * 1000)
          : undefined,
      amr: asStringArray(payload['amr']),
      expiresAt: new Date(payload.exp * 1000),
      raw: payload,
    };
  }
}
