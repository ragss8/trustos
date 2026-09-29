import Fastify, { type FastifyInstance } from 'fastify';

/**
 * A stand-in destination system.
 *
 * Deliberately supports the two things architecture.md §8.3 requires of a real
 * destination, because without them the enforcement story does not hold:
 *
 *   ETag / If-Match  an approved action must not land on a record that changed
 *                    after the decision was made
 *   Idempotency-Key  a retried write must not apply twice
 *
 * It also fakes a timeout on demand, so the "destination times out after writing"
 * path can be exercised rather than argued about.
 */

interface Lead {
  id: string;
  name: string;
  region: string;
  version: number;
  discount_basis_points: number;
}

export function buildFakeCrm(): FastifyInstance {
  const app = Fastify({ logger: false });

  const leads = new Map<string, Lead>([
    [
      'lead_demo',
      {
        id: 'lead_demo',
        name: 'Northwind Traders',
        region: 'KA',
        version: 17,
        discount_basis_points: 0,
      },
    ],
    [
      'lead_other',
      { id: 'lead_other', name: 'Contoso', region: 'MH', version: 3, discount_basis_points: 0 },
    ],
  ]);

  /** Applied writes, keyed by idempotency key. A replay returns the first result. */
  const applied = new Map<string, unknown>();

  app.get('/leads/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    const lead = leads.get(id);
    if (!lead) return reply.code(404).send({ error: 'not_found' });
    return reply.header('etag', String(lead.version)).send(lead);
  });

  app.post('/leads/:id/discount', async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as { discount_basis_points: number; simulate?: string };
    const idempotencyKey = request.headers['idempotency-key'] as string | undefined;
    const ifMatch = request.headers['if-match'] as string | undefined;

    if (idempotencyKey && applied.has(idempotencyKey)) {
      // The destination's own idempotency. TrustOS cannot provide this; it can only
      // require that the destination has it (§8.3).
      return reply.header('x-replayed', 'true').send(applied.get(idempotencyKey));
    }

    const lead = leads.get(id);
    if (!lead) return reply.code(404).send({ error: 'not_found' });

    if (ifMatch !== undefined && ifMatch !== String(lead.version)) {
      // 412: the record moved since the decision was made.
      return reply.code(412).send({ error: 'precondition_failed', current_version: lead.version });
    }

    if (body.simulate === 'timeout') {
      // Writes, THEN hangs up: the caller cannot tell whether it applied. Exactly the
      // case that must be recorded as unknown rather than retried.
      lead.discount_basis_points = body.discount_basis_points;
      lead.version += 1;
      return reply.code(504).send({ error: 'gateway_timeout' });
    }

    lead.discount_basis_points = body.discount_basis_points;
    lead.version += 1;
    const result = {
      operation_id: `crm-op-${Math.random().toString(36).slice(2, 10)}`,
      lead_id: id,
      discount_basis_points: lead.discount_basis_points,
      version: lead.version,
    };
    if (idempotencyKey) applied.set(idempotencyKey, result);
    return reply.header('etag', String(lead.version)).send(result);
  });

  app.get('/health', async () => ({ status: 'ok' }));
  return app;
}

export async function startFakeCrm(port = 53003): Promise<void> {
  const app = buildFakeCrm();
  await app.listen({ port, host: '0.0.0.0' });
  process.stdout.write(`fake-crm listening on ${port}\n`);
}
