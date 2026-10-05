export interface Migration {
  readonly id: number;
  readonly sql: string;
}

// Append-only. Never edit or reorder an applied migration; add a new one instead.
export const MIGRATIONS: readonly Migration[] = [
  {
    id: 1,
    sql: `
      CREATE TABLE identities (
        pubkey TEXT PRIMARY KEY,
        encrypted_private_key BLOB NOT NULL,
        iv BLOB NOT NULL,
        kdf_salt BLOB NOT NULL,
        key_version INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `,
  },
];

// Durable Object SQLite does not support PRAGMA user_version, so applied
// migrations are tracked in a table of our own.
const CREATE_MIGRATIONS_TABLE = `
  CREATE TABLE IF NOT EXISTS _sql_schema_migrations (
    id INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
  );
`;

export function getSchemaVersion(sql: SqlStorage): number {
  return sql
    .exec<{
      version: number;
    }>('SELECT COALESCE(MAX(id), 0) AS version FROM _sql_schema_migrations')
    .one().version;
}

export function migrate(
  storage: DurableObjectStorage,
  migrations: readonly Migration[] = MIGRATIONS,
): void {
  assertOrdered(migrations);

  const { sql } = storage;
  sql.exec(CREATE_MIGRATIONS_TABLE);
  const version = getSchemaVersion(sql);

  for (const migration of migrations) {
    if (migration.id <= version) {
      continue;
    }
    // Each migration and its tracking row commit together, so a failed
    // migration leaves no partial schema behind and is retried next time.
    storage.transactionSync(() => {
      sql.exec(migration.sql);
      sql.exec(
        'INSERT INTO _sql_schema_migrations (id, applied_at) VALUES (?, ?)',
        migration.id,
        Math.floor(Date.now() / 1000),
      );
    });
  }
}

function assertOrdered(migrations: readonly Migration[]): void {
  let previous = 0;
  for (const { id } of migrations) {
    if (!Number.isSafeInteger(id) || id <= previous) {
      throw new Error(
        'Migration ids must be strictly increasing positive integers',
      );
    }
    previous = id;
  }
}
