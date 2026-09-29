/**
 * OIDC authorization code flow with PKCE (architecture.md §5.1).
 *
 * The console is a public client, so it gets no secret and PKCE is what stops an
 * intercepted authorization code being exchanged by anyone else. Implemented against
 * the provider's standard endpoints rather than hand-rolling anything.
 *
 * Tokens are held in memory only. sessionStorage survives a tab crash but is readable
 * by any script on the origin; INVARIANT 13 says machine credentials never go in
 * browser storage, and an access token is one. The verifier is the exception — it
 * must survive the redirect, is single-use, and is worthless without the matching
 * authorization code.
 */

const ISSUER = import.meta.env['VITE_OIDC_ISSUER'] ?? 'http://localhost:58080/realms/trustos';
const CLIENT_ID = import.meta.env['VITE_OIDC_CLIENT_ID'] ?? 'trustos-console';
const REDIRECT_URI = window.location.origin + '/';
const VERIFIER_KEY = 'trustos.pkce_verifier';

function randomString(bytes = 32): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function challengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

export async function beginLogin(): Promise<void> {
  const verifier = randomString();
  sessionStorage.setItem(VERIFIER_KEY, verifier);
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid profile email',
    code_challenge: await challengeFor(verifier),
    code_challenge_method: 'S256',
    state: randomString(16),
  });
  window.location.assign(`${ISSUER}/protocol/openid-connect/auth?${params.toString()}`);
}

export async function completeLogin(): Promise<string | null> {
  const code = new URLSearchParams(window.location.search).get('code');
  if (!code) return null;
  const verifier = sessionStorage.getItem(VERIFIER_KEY);
  if (!verifier) return null;
  sessionStorage.removeItem(VERIFIER_KEY);

  const response = await fetch(`${ISSUER}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    }),
  });
  if (!response.ok) return null;
  const body = (await response.json()) as { access_token: string };
  // Clear the code from the URL so a refresh or a shared link cannot replay it.
  window.history.replaceState({}, '', REDIRECT_URI);
  return body.access_token;
}
