import { buildGateway } from './gateway.js';
import { startFakeCrm } from './fake-crm.js';

/** Runs the fake destination and the gateway together for local development. */
async function main(): Promise<void> {
  const crmPort = Number(process.env['FAKE_CRM_PORT'] ?? 53003);
  const gatewayPort = Number(process.env['GATEWAY_PORT'] ?? 53004);
  await startFakeCrm(crmPort);

  const issuer = process.env['OIDC_ISSUER_URL'] ?? '';
  const clientId = process.env['OIDC_GATEWAY_CLIENT_ID'] ?? 'trustos-gateway';
  const clientSecret = process.env['OIDC_GATEWAY_CLIENT_SECRET'] ?? '';

  // Fetched per call. A cached token that outlives a revocation is exactly the
  // failure mode epochs exist to close (IDN-04).
  const tokenProvider = async (): Promise<string> => {
    const res = await fetch(`${issuer}/protocol/openid-connect/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
    const body = (await res.json()) as { access_token?: string };
    if (!body.access_token) throw new Error('gateway could not obtain a token');
    return body.access_token;
  };

  const gateway = buildGateway({
    trustosUrl: `http://localhost:${process.env['DECISION_API_PORT'] ?? 53002}`,
    crmUrl: `http://localhost:${crmPort}`,
    ledgerPath: process.env['GATEWAY_LEDGER_PATH'] ?? '.volumes/gateway-ledger.json',
    tokenProvider,
    gatewayAudience: clientId,
  });
  await gateway.listen({ port: gatewayPort, host: '0.0.0.0' });
  process.stdout.write(`gateway listening on ${gatewayPort}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${(error as Error).stack ?? String(error)}\n`);
  process.exitCode = 1;
});
