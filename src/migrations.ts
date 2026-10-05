export interface Migration {
  readonly id: number;
  readonly sql: string;
}

// Append-only, with ids 1, 2, 3, ... Never edit or reorder an applied
// migration; add a new one with the next id instead.
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
  {
    id: 2,
    sql: `
      CREATE TABLE admin_sessions (
        token_hash BLOB PRIMARY KEY,
        admin_pubkey TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE admin_auth_events (
        event_id TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      );
    `,
  },
  {
    id: 3,
    sql: `
      CREATE TABLE pairings (
        id TEXT PRIMARY KEY,
        identity_pubkey TEXT NOT NULL,
        secret_hash BLOB NOT NULL UNIQUE,
        permissions TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE INDEX pairings_identity_pubkey
      ON pairings(identity_pubkey);

      CREATE TABLE sessions (
        client_pubkey TEXT PRIMARY KEY,
        identity_pubkey TEXT NOT NULL,
        permissions TEXT NOT NULL,

        client_name TEXT,
        client_url TEXT,
        client_image TEXT,

        created_at INTEGER NOT NULL,
        last_used_at INTEGER NOT NULL
      );

      CREATE INDEX sessions_identity_pubkey
      ON sessions(identity_pubkey);
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
  assertConsecutive(migrations);

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

// The schema version is MAX(id), so a skipped id added later would never be
// applied. Requiring 1, 2, 3, ... rules that out.
function assertConsecutive(migrations: readonly Migration[]): void {
  let expectedId = 1;
  for (const { id } of migrations) {
    if (id !== expectedId) {
      throw new Error(
        'Migration ids must be consecutive positive integers starting at 1',
      );
    }
    expectedId++;
  }
}
