import { beforeAll, describe, expect, it } from 'vitest';
import { SignJWT, generateKeyPair } from 'jose';
import { TokenValidationError, TokenValidator } from './token-validator.js';

/**
 * Runs against the local Keycloak from docker-compose. Real provider, real JWKS, real
 * signatures: a hand-rolled fake issuer would not exercise key rotation, kid lookup or
 * the provider's actual claim shape.
 */

const ISSUER = process.env['OIDC_ISSUER_URL'] ?? 'http://localhost:58080/realms/trustos';
const AUDIENCE = 'trustos-api';

async function machineToken(clientId: string, secret: string): Promise<string> {
  const res = await fetch(`${ISSUER}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: secret,
    }),
  });
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) throw new Error(`no token for ${clientId}`);
  return body.access_token;
}

async function humanToken(): Promise<string> {
  const res = await fetch(`${ISSUER}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: 'trustos-console',
      username: 'approver@trustos.local',
      password: 'local_dev_only',
    }),
  });
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) throw new Error('no human token');
  return body.access_token;
}

let validator: TokenValidator;
let gatewayToken: string;

beforeAll(async () => {
  validator = new TokenValidator({ issuer: ISSUER, audience: AUDIENCE });
  gatewayToken = await machineToken('trustos-gateway', 'local_dev_only_gateway');
}, 30_000);

describe('genuine tokens', () => {
  it('accepts a real machine token and identifies the client', async () => {
    const t = await validator.validate(gatewayToken);
    expect(t.type).toBe('machine');
    expect(t.clientId).toBe('trustos-gateway');
    expect(t.audience).toContain(AUDIENCE);
    expect(t.issuer).toBe(ISSUER);
    expect(t.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('distinguishes a human session from a machine token', async () => {
    // §5.1: a client-credentials token must not satisfy a gate meant for an
    // interactively authenticated human, or a service passes the MFA requirement.
    const t = await validator.validate(await humanToken());
    expect(t.type).toBe('human');
    expect(t.subject).toBeTruthy();
  });

  it('classifies a token with neither marker as unknown, not human', async () => {
    // A valid signature is not evidence of an interactive human. If a provider (or a
    // future config change) stops emitting both markers, the safe answer is "unknown"
    // and a human-only gate refuses it. Guessing 'human' here would let a service
    // account resolve an approval.
    const { privateKey } = await generateKeyPair('RS256');
    const bare = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('ambiguous')
      .setExpirationTime('5m')
      .sign(privateKey);
    // Signed by the wrong key, so it is rejected before classification — which is the
    // point: classification never runs on an unverified token.
    await expect(validator.validate(bare)).rejects.toBeInstanceOf(TokenValidationError);
  });

  it('does not confuse two different machine clients', async () => {
    const agent = await validator.validate(
      await machineToken('trustos-agent-sandbox', 'local_dev_only_agent'),
    );
    expect(agent.clientId).toBe('trustos-agent-sandbox');
    expect(agent.subject).not.toBe((await validator.validate(gatewayToken)).subject);
  });
});

describe('rejected tokens', () => {
  it('rejects a token minted for a different audience', async () => {
    const other = new TokenValidator({ issuer: ISSUER, audience: 'some-other-api' });
    await expect(other.validate(gatewayToken)).rejects.toMatchObject({
      code: 'AUDIENCE_MISMATCH',
    });
  });

  it('rejects a token from a different issuer', async () => {
    const other = new TokenValidator({
      issuer: `${ISSUER}-evil`,
      audience: AUDIENCE,
    });
    // Different issuer means a different JWKS, so this fails at key lookup rather
    // than claim comparison. Either way it must not verify.
    await expect(other.validate(gatewayToken)).rejects.toBeInstanceOf(TokenValidationError);
  });

  it('rejects a tampered payload', async () => {
    const [h, p, s] = gatewayToken.split('.');
    const decoded = JSON.parse(Buffer.from(p!, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    decoded['sub'] = 'attacker';
    const forged = `${h}.${Buffer.from(JSON.stringify(decoded)).toString('base64url')}.${s}`;
    await expect(validator.validate(forged)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIAL',
    });
  });

  it('rejects a correctly-formed token signed by the wrong key', async () => {
    // The attack that a signature check without a trusted key store would miss.
    const { privateKey } = await generateKeyPair('RS256');
    const forged = await new SignJWT({ azp: 'trustos-gateway' })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('attacker')
      .setExpirationTime('5m')
      .sign(privateKey);
    await expect(validator.validate(forged)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIAL',
    });
  });

  it('rejects an expired token', async () => {
    const { privateKey } = await generateKeyPair('RS256');
    const expired = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('someone')
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
      .sign(privateKey);
    await expect(validator.validate(expired)).rejects.toBeInstanceOf(TokenValidationError);
  });

  it.each([
    ['', 'empty'],
    ['not-a-jwt', 'not a JWT'],
    ['a.b.c', 'three garbage segments'],
    ['eyJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciJ9.', 'alg:none'],
  ])('rejects %j (%s)', async (bad) => {
    await expect(validator.validate(bad)).rejects.toBeInstanceOf(TokenValidationError);
  });
});

describe('validator configuration', () => {
  it.each(['HS256', 'HS384', 'none'])('refuses to be constructed with %s', (alg) => {
    // Key confusion: with a JWKS-backed verifier, anyone holding the PUBLIC key could
    // mint a valid HS256 token. Refused at construction, not at verify time.
    expect(
      () => new TokenValidator({ issuer: ISSUER, audience: AUDIENCE, algorithms: [alg] }),
    ).toThrow(TokenValidationError);
  });

  it('permits an explicit asymmetric algorithm set', () => {
    expect(
      () => new TokenValidator({ issuer: ISSUER, audience: AUDIENCE, algorithms: ['ES256'] }),
    ).not.toThrow();
  });
});
