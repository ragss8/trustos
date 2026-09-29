/**
 * Local development seed.
 *
 * Creates two tenants so cross-tenant isolation is exercised by ordinary use rather
 * than only by the isolation suite (architecture.md §12.1), and wires the Keycloak
 * clients from infra/keycloak to real principals.
 *
 * Idempotent: safe to re-run. Nothing here is a credential — the secrets live in
 * Keycloak and .env.
 */
import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import { type Pool } from 'pg';
import { createPool, withNewTenantTransaction, withTenantTransaction } from '../dist/index.js';

const ISSUER = process.env['OIDC_ISSUER_URL'] ?? 'http://localhost:58080/realms/trustos';

/** The prd.md §8.1 discount ladder, as a publishable bundle. */
const DISCOUNT_RULES = {
  schema_version: '1',
  rules: [
    {
      schema_version: '1',
      rule_id: 'region_must_be_assigned',
      action: 'crm.discount.apply',
      effect: 'deny',
      when: { not: { field: 'context.customer_region', op: 'in', value: ['KA', 'MH', 'TN'] } },
    },
    {
      schema_version: '1',
      rule_id: 'discount_above_ceiling',
      action: 'crm.discount.apply',
      effect: 'deny',
      when: { field: 'parameters.discount_basis_points', op: 'gt', value: 2000 },
    },
    {
      schema_version: '1',
      rule_id: 'discount_manager_approval',
      action: 'crm.discount.apply',
      effect: 'approval_required',
      when: {
        all: [
          { field: 'parameters.discount_basis_points', op: 'gt', value: 1000 },
          { field: 'parameters.discount_basis_points', op: 'lte', value: 2000 },
        ],
      },
      approval: { group_key: 'regional_sales_manager', timeout_seconds: 600 },
      obligations: ['business_reason_required', 'execution_report_required'],
    },
    {
      schema_version: '1',
      rule_id: 'discount_within_authority',
      action: 'crm.discount.apply',
      effect: 'allow',
      when: { field: 'parameters.discount_basis_points', op: 'lte', value: 1000 },
      obligations: ['execution_report_required'],
    },
    {
      schema_version: '1',
      rule_id: 'lead_read_allowed',
      action: 'crm.lead.read',
      effect: 'allow',
      when: { field: 'context.customer_region', op: 'in', value: ['KA', 'MH', 'TN'] },
    },
  ],
};

function sha256(value: unknown): string {
  return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
}

async function seedTenant(
  pool: Pool,
  opts: { name: string; gatewayClientId: string; agentClientId: string },
): Promise<{ tenantId: string; agentId: string }> {
  const tenantId = randomUUID();

  const ids = await withNewTenantTransaction(pool, tenantId, async (c) => {
    await c.query(`INSERT INTO organizations (id,name,region) VALUES ($1,$2,'IN')`, [
      tenantId,
      opts.name,
    ]);

    const env = await c.query<{ id: string }>(
      `INSERT INTO environments (tenant_id,name,mode,enforcement,current_bundle_revision)
       VALUES ($1,'production','production','enforced',1) RETURNING id`,
      [tenantId],
    );
    const environmentId = env.rows[0]!.id;

    const owner = await c.query<{ id: string }>(
      `INSERT INTO memberships (tenant_id,user_id,role)
       VALUES ($1,'admin@trustos.local','security_admin') RETURNING id`,
      [tenantId],
    );
    const approver = await c.query<{ id: string }>(
      `INSERT INTO memberships (tenant_id,user_id,role)
       VALUES ($1,'approver@trustos.local','approver') RETURNING id`,
      [tenantId],
    );

    const group = await c.query<{ id: string }>(
      `INSERT INTO approver_groups (tenant_id,group_key,name)
       VALUES ($1,'regional_sales_manager','Regional Sales Managers') RETURNING id`,
      [tenantId],
    );
    await c.query(
      `INSERT INTO approver_group_members (tenant_id,group_id,membership_id) VALUES ($1,$2,$3)`,
      [tenantId, group.rows[0]!.id, approver.rows[0]!.id],
    );

    // Agent: owned, acknowledged, active. IDN-02 requires all three before authority.
    const agent = await c.query<{ id: string }>(
      `INSERT INTO principals
         (tenant_id,environment_id,type,name,owner_membership_id,status,owner_acknowledged_at,metadata)
       VALUES ($1,$2,'agent','Sales assistant',$3,'active',now(),$4) RETURNING id`,
      [tenantId, environmentId, owner.rows[0]!.id, JSON.stringify({ runtime: 'self-reported' })],
    );
    const gateway = await c.query<{ id: string }>(
      `INSERT INTO principals (tenant_id,environment_id,type,name,status)
       VALUES ($1,$2,'gateway','Reference CRM gateway','active') RETURNING id`,
      [tenantId, environmentId],
    );

    // Maps the Keycloak client to the principal. This is the only lookup that runs
    // unscoped, because resolving the tenant is its job.
    for (const [clientId, principalId] of [
      [opts.gatewayClientId, gateway.rows[0]!.id],
      [opts.agentClientId, agent.rows[0]!.id],
    ] as const) {
      await c.query(
        `INSERT INTO credential_bindings
           (tenant_id,environment_id,principal_id,issuer,provider_client_id)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (issuer, provider_client_id) DO NOTHING`,
        [tenantId, environmentId, principalId, ISSUER, clientId],
      );
    }

    // Capabilities bound the evaluator (POL-07). Policy narrows these; never widens.
    for (const [action, resourceType] of [
      ['crm.discount.apply', 'crm.lead'],
      ['crm.lead.read', 'crm.lead'],
    ] as const) {
      await c.query(
        `INSERT INTO capabilities (tenant_id,environment_id,action_key,resource_type,schema)
         VALUES ($1,$2,$3,$4,'{}'::jsonb)`,
        [tenantId, environmentId, action, resourceType],
      );
      await c.query(
        `INSERT INTO capability_grants (tenant_id,environment_id,principal_id,action_key,constraints)
         VALUES ($1,$2,$3,$4,$5)`,
        [
          tenantId,
          environmentId,
          agent.rows[0]!.id,
          action,
          JSON.stringify({ max_discount_basis_points: 2000 }),
        ],
      );
    }

    // Publish the bundle at revision 1, with an independent reviewer (SEC-01).
    const policy = await c.query<{ id: string }>(
      `INSERT INTO policies (tenant_id,environment_id,name,status)
       VALUES ($1,$2,'discount-policy','published') RETURNING id`,
      [tenantId, environmentId],
    );
    const version = await c.query<{ id: string }>(
      `INSERT INTO policy_versions
         (tenant_id,environment_id,policy_id,version,content,hash,author_id,published_at)
       VALUES ($1,$2,$3,1,$4,$5,$6,now()) RETURNING id`,
      [
        tenantId,
        environmentId,
        policy.rows[0]!.id,
        JSON.stringify(DISCOUNT_RULES),
        sha256(DISCOUNT_RULES),
        owner.rows[0]!.id,
      ],
    );
    await c.query(
      `INSERT INTO policy_reviews (tenant_id,version_id,reviewed_hash,reviewer_id,decision)
       VALUES ($1,$2,$3,$4,'approved')`,
      [tenantId, version.rows[0]!.id, sha256(DISCOUNT_RULES), approver.rows[0]!.id],
    );
    await c.query(
      `INSERT INTO policy_bundles
         (tenant_id,environment_id,revision,version_ids,compiled,compiled_hash,evaluator_version)
       VALUES ($1,$2,1,$3,$4,$5,'1.0.0')`,
      [
        tenantId,
        environmentId,
        [version.rows[0]!.id],
        JSON.stringify(DISCOUNT_RULES),
        sha256(DISCOUNT_RULES),
      ],
    );

    return { agentId: agent.rows[0]!.id, environmentId };
  });

  return { tenantId, agentId: ids.agentId };
}

async function main(): Promise<void> {
  const pool = createPool(process.env['DATABASE_URL'] ?? '');
  try {
    const existing = await pool.query<{ n: string }>(
      `SELECT count(*) AS n FROM credential_bindings WHERE provider_client_id = 'trustos-gateway'`,
    );
    if (Number(existing.rows[0]!.n) > 0) {
      process.stdout.write('already seeded; nothing to do\n');
      return;
    }

    const primary = await seedTenant(pool, {
      name: 'Acme Sales',
      gatewayClientId: 'trustos-gateway',
      agentClientId: 'trustos-agent-sandbox',
    });

    // A second tenant with no credential bindings: it exists purely so every query
    // path has a neighbour to leak to if isolation is ever wrong.
    const second = randomUUID();
    await withNewTenantTransaction(pool, second, async (c) => {
      await c.query(
        `INSERT INTO organizations (id,name,region) VALUES ($1,'Globex Support','IN')`,
        [second],
      );
      await c.query(
        `INSERT INTO environments (tenant_id,name,mode) VALUES ($1,'production','production')`,
        [second],
      );
    });

    process.stdout.write(
      `seeded\n  tenant:  ${primary.tenantId}\n  agent:   ${primary.agentId}\n  neighbour tenant: ${second}\n`,
    );

    const check = await withTenantTransaction(
      pool,
      { tenantId: primary.tenantId },
      async (c) =>
        (await c.query<{ n: string }>('SELECT count(*) AS n FROM organizations')).rows[0]!.n,
    );
    process.stdout.write(`  isolation check: tenant sees ${check} organization(s)\n`);
  } finally {
    await pool.end();
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${(error as Error).stack ?? String(error)}\n`);
  process.exitCode = 1;
});
