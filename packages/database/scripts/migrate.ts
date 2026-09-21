/**
 * Migration runner.
 *
 * Applies packages/database/db/*.sql in filename order, once each, tracked in
 * schema_migrations. Two roles are involved by design (architecture.md §6.1):
 *
 *   001_roles.sql  runs as the bootstrap superuser, because it CREATEs roles.
 *   everything else runs as trustos_migrator, which owns the tables.
 *
 * The application role appears nowhere here. It must never be able to alter schema.
 */
import { readdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from 'pg';

const DB_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'db');

const ROOT_URL =
  process.env['DATABASE_ROOT_URL'] ??
  'postgresql://trustos_root:local_dev_only@localhost:55432/trustos';
const MIGRATION_URL =
  process.env['DATABASE_MIGRATION_URL'] ??
  'postgresql://trustos_migrator:local_dev_only@localhost:55432/trustos';

/**
 * A migration declares which role it needs with a `-- @role: root` header. Root is
 * for statements only a superuser or the object's owner can run (CREATE ROLE, and
 * grants on root-owned tables). Everything else defaults to the table owner.
 *
 * A marker beats a hardcoded filename list: the requirement travels with the file.
 */
function requiredRole(sql: string): 'root' | 'migrator' {
  return /^--\s*@role:\s*root\s*$/m.test(sql) ? 'root' : 'migrator';
}

async function run(url: string, sql: string, file: string): Promise<void> {
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    // Each file is one transaction: a half-applied migration is worse than none.
    await client.query('BEGIN');
    await client.query(sql);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw new Error(`migration ${file} failed: ${(error as Error).message}`, { cause: error });
  } finally {
    await client.end();
  }
}

async function main(): Promise<void> {
  const root = new Client({ connectionString: ROOT_URL });
  await root.connect();
  try {
    await migrateWith(root);
  } finally {
    // Without this, a failed migration leaves the connection open and the process
    // hangs rather than exiting with the error.
    await root.end();
  }
}

async function migrateWith(root: Client): Promise<void> {
  await root.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename    text PRIMARY KEY,
      checksum    text NOT NULL,
      applied_at  timestamptz NOT NULL DEFAULT now()
    )`);
  const applied = new Map(
    (
      await root.query<{ filename: string; checksum: string }>(
        'SELECT filename, checksum FROM schema_migrations',
      )
    ).rows.map((r) => [r.filename, r.checksum]),
  );

  const files = (await readdir(DB_DIR)).filter((f) => f.endsWith('.sql')).sort();
  let count = 0;

  for (const file of files) {
    const sql = await readFile(join(DB_DIR, file), 'utf8');
    const checksum = createHash('sha256').update(sql).digest('hex');
    const previous = applied.get(file);

    if (previous === checksum) continue;
    if (previous !== undefined) {
      // Editing an applied migration makes environments silently diverge.
      throw new Error(
        `${file} was already applied but its contents changed. Add a new migration ` +
          `instead of editing this one (expand/migrate/contract, §15).`,
      );
    }

    process.stdout.write(`applying ${file}\n`);
    await run(requiredRole(sql) === 'root' ? ROOT_URL : MIGRATION_URL, sql, file);
    await root.query('INSERT INTO schema_migrations (filename, checksum) VALUES ($1, $2)', [
      file,
      checksum,
    ]);
    count += 1;
  }

  process.stdout.write(count === 0 ? 'up to date\n' : `applied ${count} migration(s)\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${(error as Error).message}\n`);
  process.exitCode = 1;
});
