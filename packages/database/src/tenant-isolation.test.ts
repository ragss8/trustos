import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import { createPool } from './pool.js';
import {
  InvalidTenantScopeError,
  withNewTenantTransaction,
  withTenantTransaction,
} from './tenant-transaction.js';

/**
 * Tenant isolation suite (ORG-01, INVARIANT 5).
 *
 * These run as trustos_app against a real PostgreSQL. That matters more than it
 * sounds: RLS is bypassed by the table owner and by any BYPASSRLS role, so a suite
 * that connects as the owner passes while proving nothing. The first test below
 * asserts the connected role is actually subject to the policies.
 */

const APP_URL =
  process.env['DATABASE_URL'] ??
  'postgresql://trustos_app:local_dev_only@localhost:55432/trustos?schema=public';

let pool: Pool;
const acme = randomUUID();
const globex = randomUUID();
let acmeEnv: string;

beforeAll(async () => {
  pool = createPool(APP_URL);
  for (const [id, name] of [
    [acme, 'Acme'],
    [globex, 'Globex'],
  ] as const) {
    await withNewTenantTransaction(pool, id, async (c) => {
      await c.query('INSERT INTO organizations (id, name, region) VALUES ($1, $2, $3)', [
        id,
        name,
        'IN',
      ]);
      await c.query(
        'INSERT INTO environments (tenant_id, name, mode) VALUES ($1, $2, $3) RETURNING id',
        [id, 'sandbox', 'sandbox'],
      );
    });
  }
  acmeEnv = await withTenantTransaction(pool, { tenantId: acme }, async (c) => {
    const r = await c.query<{ id: string }>('SELECT id FROM environments LIMIT 1');
    return r.rows[0]!.id;
  });
});

afterAll(async () => {
  await pool?.end();
});

describe('the suite is actually testing something', () => {
  it('connects as a role that RLS applies to', async () => {
    const r = await pool.query<{ rolname: string; rolsuper: boolean; rolbypassrls: boolean }>(
      'SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user',
    );
    const role = r.rows[0]!;
    // If any of these flip, every other test in this file becomes meaningless.
    expect(role.rolsuper, 'connected as a superuser: RLS would be bypassed').toBe(false);
    expect(role.rolbypassrls, 'connected with BYPASSRLS: RLS would be bypassed').toBe(false);
    expect(role.rolname).toBe('trustos_app');
  });

  it('is not the owner of the tables it queries', async () => {
    const r = await pool.query<{ count: string }>(
      `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname='public' AND c.relkind='r' AND pg_get_userbyid(c.relowner) = current_user`,
    );
    expect(Number(r.rows[0]!.count), 'app role owns tables; owner bypasses RLS').toBe(0);
  });

  it('leaves no table both reachable and unprotected', async () => {
    // The real invariant is not "every table has RLS". Infrastructure tables such as
    // schema_migrations carry no tenant_id, so a row policy on them would be
    // meaningless; they are protected by being unreachable instead.
    //
    // So: every table must be EITHER covered by RLS with FORCE, OR have no privilege
    // granted to this role. A table that is neither is a hole, and this is how a
    // future migration that forgets RLS gets caught.
    const r = await pool.query<{ relname: string }>(
      `SELECT c.relname
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relkind = 'r'
         AND NOT (c.relrowsecurity AND c.relforcerowsecurity)
         AND has_table_privilege(current_user, c.oid, 'SELECT, INSERT, UPDATE, DELETE')`,
    );
    expect(r.rows.map((x) => x.relname)).toEqual([]);
  });

  it('covers every tenant-scoped table with RLS and FORCE', async () => {
    // The other half: anything carrying tenant_id must be policy-protected, whether
    // or not this role currently holds a grant on it.
    const r = await pool.query<{ relname: string }>(
      `SELECT c.relname
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relkind = 'r'
         AND EXISTS (
           SELECT 1 FROM pg_attribute a
           WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
             AND a.attnum > 0 AND NOT a.attisdropped)
         AND NOT (c.relrowsecurity AND c.relforcerowsecurity)`,
    );
    expect(r.rows.map((x) => x.relname)).toEqual([]);
  });
});

describe('cross-tenant reads', () => {
  it('sees only its own organization', async () => {
    const rows = await withTenantTransaction(
      pool,
      { tenantId: acme },
      async (c) => (await c.query<{ id: string }>('SELECT id FROM organizations')).rows,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.id).toBe(acme);
  });

  it('cannot read another tenant by explicit id', async () => {
    const rows = await withTenantTransaction(
      pool,
      { tenantId: acme },
      async (c) => (await c.query('SELECT id FROM organizations WHERE id = $1', [globex])).rows,
    );
    expect(rows).toEqual([]);
  });

  it('cannot count another tenant into existence', async () => {
    // Existence disclosure via aggregate is still disclosure (§9.5).
    const n = await withTenantTransaction(pool, { tenantId: acme }, async (c) =>
      Number((await c.query<{ n: string }>('SELECT count(*) AS n FROM environments')).rows[0]!.n),
    );
    expect(n).toBe(1);
  });
});

describe('cross-tenant writes', () => {
  it('rejects an INSERT tagged with another tenant', async () => {
    await expect(
      withTenantTransaction(pool, { tenantId: acme }, async (c) => {
        await c.query('INSERT INTO environments (tenant_id, name, mode) VALUES ($1,$2,$3)', [
          globex,
          'stolen',
          'sandbox',
        ]);
      }),
    ).rejects.toThrow(/row-level security/i);
  });

  it('updates zero rows when targeting another tenant', async () => {
    const n = await withTenantTransaction(
      pool,
      { tenantId: acme },
      async (c) =>
        (await c.query('UPDATE organizations SET name = $1 WHERE id = $2', ['pwned', globex]))
          .rowCount,
    );
    expect(n).toBe(0);
  });

  it('deletes zero rows when targeting another tenant', async () => {
    const n = await withTenantTransaction(
      pool,
      { tenantId: acme },
      async (c) => (await c.query('DELETE FROM organizations WHERE id = $1', [globex])).rowCount,
    );
    expect(n).toBe(0);
  });

  it('leaves the victim intact after all of the above', async () => {
    const rows = await withTenantTransaction(
      pool,
      { tenantId: globex },
      async (c) => (await c.query<{ name: string }>('SELECT name FROM organizations')).rows,
    );
    expect(rows).toEqual([{ name: 'Globex' }]);
  });
});

describe('composite foreign keys', () => {
  it('refuses to attach a row from another tenant even with a valid id', async () => {
    // The environment id is real. It just belongs to someone else. A plain FK on (id)
    // would accept this (§6.1).
    await expect(
      withTenantTransaction(pool, { tenantId: globex }, async (c) => {
        await c.query(
          `INSERT INTO principals (tenant_id, environment_id, type, name)
           VALUES ($1, $2, 'agent', 'cross-tenant agent')`,
          [globex, acmeEnv],
        );
      }),
    ).rejects.toThrow(/violates foreign key|row-level security/i);
  });
});

describe('failing closed', () => {
  it('returns nothing when no scope is set', async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const r = await client.query<{ n: string }>('SELECT count(*) AS n FROM organizations');
      // The dangerous alternative is "sees every tenant".
      expect(Number(r.rows[0]!.n)).toBe(0);
      await client.query('COMMIT');
    } finally {
      client.release();
    }
  });

  it('rejects an INSERT when no scope is set', async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await expect(
        client.query('INSERT INTO organizations (name, region) VALUES ($1,$2)', ['ghost', 'IN']),
      ).rejects.toThrow(/row-level security/i);
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }
  });

  it.each([
    ['not-a-uuid', 'plain string'],
    ["' OR 1=1--", 'injection attempt'],
    ['', 'empty'],
  ])('rejects scope %j (%s) before taking a connection', async (bad) => {
    await expect(
      withTenantTransaction(pool, { tenantId: bad }, async () => 'unreachable'),
    ).rejects.toThrow(InvalidTenantScopeError);
  });
});

describe('connection pooling', () => {
  it('does not leak scope to the next borrower of the same connection', async () => {
    // The classic failure: `SET` instead of set_config(..., true). The scope survives
    // the transaction and the next tenant inherits it.
    const single = createPool(`${APP_URL}&application_name=leak_probe`);
    try {
      await withTenantTransaction(single, { tenantId: acme }, async (c) => {
        await c.query('SELECT 1');
      });
      const client = await single.connect();
      try {
        const r = await client.query<{ leaked: string | null }>(
          `SELECT nullif(current_setting('trustos.tenant_id', true), '') AS leaked`,
        );
        expect(r.rows[0]!.leaked).toBeNull();
      } finally {
        client.release();
      }
    } finally {
      await single.end();
    }
  });

  it('keeps concurrent transactions on different tenants separate', async () => {
    const [a, g] = await Promise.all([
      withTenantTransaction(pool, { tenantId: acme }, async (c) => {
        await new Promise((r) => setTimeout(r, 25)); // force interleaving
        return (await c.query<{ name: string }>('SELECT name FROM organizations')).rows;
      }),
      withTenantTransaction(pool, { tenantId: globex }, async (c) => {
        return (await c.query<{ name: string }>('SELECT name FROM organizations')).rows;
      }),
    ]);
    expect(a).toEqual([{ name: 'Acme' }]);
    expect(g).toEqual([{ name: 'Globex' }]);
  });

  it('rolls back on error without committing partial work', async () => {
    const name = `rollback-probe-${randomUUID()}`;
    await expect(
      withTenantTransaction(pool, { tenantId: acme }, async (c) => {
        await c.query('INSERT INTO environments (tenant_id, name, mode) VALUES ($1,$2,$3)', [
          acme,
          name,
          'sandbox',
        ]);
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');

    const rows = await withTenantTransaction(
      pool,
      { tenantId: acme },
      async (c) => (await c.query('SELECT 1 FROM environments WHERE name = $1', [name])).rows,
    );
    expect(rows).toEqual([]);
  });
});
