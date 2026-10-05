import { env } from 'cloudflare:workers';
import { evictDurableObject, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { getSchemaVersion, migrate, MIGRATIONS } from '../src/migrations';

function freshHub() {
  return env.SIGNER_HUB.getByName(crypto.randomUUID());
}

function tableNames(sql: SqlStorage): string[] {
  return sql
    .exec<{
      name: string;
    }>("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
    .toArray()
    .map(({ name }) => name);
}

function appliedMigrations(sql: SqlStorage) {
  return sql
    .exec<{
      id: number;
      applied_at: number;
    }>('SELECT id, applied_at FROM _sql_schema_migrations ORDER BY id')
    .toArray();
}

function insertTestIdentity(sql: SqlStorage, pubkey: string): void {
  sql.exec(
    `INSERT INTO identities
      (pubkey, encrypted_private_key, iv, kdf_salt, key_version, created_at, updated_at)
      VALUES (?, ?, ?, ?, 1, 1, 1)`,
    pubkey,
    new Uint8Array(48),
    new Uint8Array(12),
    new Uint8Array(32),
  );
}

const PUBKEY = 'ab'.repeat(32);

describe('schema migrations', () => {
  it('migrates a fresh SignerHub during construction', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const { sql } = state.storage;
      expect(tableNames(sql)).toEqual(
        expect.arrayContaining(['_sql_schema_migrations', 'identities']),
      );
      expect(getSchemaVersion(sql)).toBe(MIGRATIONS.at(-1)?.id);
      expect(appliedMigrations(sql).map(({ id }) => id)).toEqual([1]);
    });
  });

  it('creates only the identities application table in version 1', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const tables = tableNames(state.storage.sql).filter(
        (name) => !name.startsWith('_'),
      );
      expect(tables).toEqual(['identities']);
    });
  });

  it('creates the identities table with the designed columns', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const columns = state.storage.sql
        .exec<{
          name: string;
          type: string;
          notnull: number;
          pk: number;
        }>(
          'SELECT name, type, "notnull", pk FROM pragma_table_info(?)',
          'identities',
        )
        .toArray();
      expect(columns).toEqual([
        { name: 'pubkey', type: 'TEXT', notnull: 0, pk: 1 },
        { name: 'encrypted_private_key', type: 'BLOB', notnull: 1, pk: 0 },
        { name: 'iv', type: 'BLOB', notnull: 1, pk: 0 },
        { name: 'kdf_salt', type: 'BLOB', notnull: 1, pk: 0 },
        { name: 'key_version', type: 'INTEGER', notnull: 1, pk: 0 },
        { name: 'created_at', type: 'INTEGER', notnull: 1, pk: 0 },
        { name: 'updated_at', type: 'INTEGER', notnull: 1, pk: 0 },
      ]);
    });
  });

  it('keeps data and does not re-run migrations when re-initialized', async () => {
    const stub = freshHub();
    const before = await runInDurableObject(stub, (_instance, state) => {
      insertTestIdentity(state.storage.sql, PUBKEY);
      return appliedMigrations(state.storage.sql);
    });

    await evictDurableObject(stub);

    await runInDurableObject(stub, (_instance, state) => {
      const { sql } = state.storage;
      expect(appliedMigrations(sql)).toEqual(before);
      migrate(state.storage);
      expect(appliedMigrations(sql)).toEqual(before);
      expect(sql.exec('SELECT pubkey FROM identities').toArray()).toEqual([
        { pubkey: PUBKEY },
      ]);
    });
  });

  it('applies later migrations without losing identities', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const { sql } = state.storage;
      insertTestIdentity(sql, PUBKEY);

      const evolved = [
        ...MIGRATIONS,
        { id: 2, sql: 'ALTER TABLE identities ADD COLUMN label TEXT;' },
      ];
      migrate(state.storage, evolved);
      // Running the ALTER TABLE a second time would throw.
      migrate(state.storage, evolved);

      expect(getSchemaVersion(sql)).toBe(2);
      expect(appliedMigrations(sql).map(({ id }) => id)).toEqual([1, 2]);
      expect(
        sql.exec('SELECT pubkey, label FROM identities').toArray(),
      ).toEqual([{ pubkey: PUBKEY, label: null }]);
    });
  });

  it('applies pending migrations in version order', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const { sql } = state.storage;
      migrate(state.storage, [
        ...MIGRATIONS,
        { id: 2, sql: 'CREATE TABLE ordering (step INTEGER NOT NULL);' },
        { id: 3, sql: 'INSERT INTO ordering (step) VALUES (3);' },
        { id: 5, sql: 'INSERT INTO ordering (step) VALUES (5);' },
      ]);
      expect(getSchemaVersion(sql)).toBe(5);
      expect(appliedMigrations(sql).map(({ id }) => id)).toEqual([1, 2, 3, 5]);
      expect(
        sql.exec('SELECT step FROM ordering ORDER BY rowid').toArray(),
      ).toEqual([{ step: 3 }, { step: 5 }]);
    });
  });

  it('rolls back a failed migration and leaves it pending', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const { sql } = state.storage;
      expect(() =>
        migrate(state.storage, [
          ...MIGRATIONS,
          {
            id: 2,
            sql: 'CREATE TABLE partial (id INTEGER); INSERT INTO missing VALUES (1);',
          },
        ]),
      ).toThrow();
      expect(getSchemaVersion(sql)).toBe(1);
      expect(tableNames(sql)).not.toContain('partial');
      expect(sql.exec('SELECT pubkey FROM identities').toArray()).toEqual([]);
    });
  });

  it('rejects migration lists that are not strictly increasing', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const invalid = [
        [
          { id: 2, sql: 'SELECT 1;' },
          { id: 1, sql: 'SELECT 1;' },
        ],
        [
          { id: 1, sql: 'SELECT 1;' },
          { id: 1, sql: 'SELECT 1;' },
        ],
        [{ id: 0, sql: 'SELECT 1;' }],
        [{ id: 1.5, sql: 'SELECT 1;' }],
      ];
      for (const migrations of invalid) {
        expect(() => migrate(state.storage, migrations)).toThrow(
          'Migration ids must be strictly increasing positive integers',
        );
      }
      expect(getSchemaVersion(state.storage.sql)).toBe(1);
    });
  });
});
