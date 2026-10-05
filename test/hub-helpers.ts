import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { generateSecretKey } from 'nostr-tools/pure';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { registerIdentity } from '../src/identities';
import type { SignerHub } from '../src/signer-hub';

// Cloudflare's documented error for writes to a full SQLite-backed Durable Object.
export const SQLITE_FULL_MESSAGE = 'database or disk is full: SQLITE_FULL';

export function freshHub(): DurableObjectStub<SignerHub> {
  return env.SIGNER_HUB.getByName(crypto.randomUUID());
}

// Registers an identity with a random private key and returns its pubkey.
export function addIdentity(
  hub: DurableObjectStub<SignerHub>,
  now = 1_700_000_000,
): Promise<string> {
  return runInDurableObject(hub, async (_instance, state) => {
    const identity = await registerIdentity(
      state.storage.sql,
      crypto.getRandomValues(new Uint8Array(32)),
      bytesToHex(generateSecretKey()),
      now,
    );
    return identity.pubkey;
  });
}

// Every value in every table, so tests can assert what was persisted.
export function allStoredValues(sql: SqlStorage): SqlStorageValue[] {
  return sql
    .exec<{ name: string }>(
      "SELECT name FROM sqlite_master WHERE type = 'table'",
    )
    .toArray()
    .flatMap(({ name }) =>
      [...sql.exec(`SELECT * FROM "${name}"`).raw()].flat(),
    );
}

// Stored values that contain a hex secret as text, as its ASCII bytes, or as
// the bytes it encodes.
export function valuesContainingSecret(
  sql: SqlStorage,
  secret: string,
): SqlStorageValue[] {
  const encodings = [
    bytesToHex(new TextEncoder().encode(secret)),
    bytesToHex(hexToBytes(secret)),
  ];
  return allStoredValues(sql).filter((value) =>
    value instanceof ArrayBuffer
      ? encodings.some((encoding) =>
          bytesToHex(new Uint8Array(value)).includes(encoding),
        )
      : typeof value === 'string' && value.toLowerCase().includes(secret),
  );
}

// Delegates to the real storage, recording each statement, but throws
// `message` instead of running statements that match `failing`.
export function instrumentedStorage(
  storage: DurableObjectStorage,
  options: { failing?: RegExp; message?: string; statements?: string[] } = {},
): DurableObjectStorage {
  const sql = {
    exec(query: string, ...bindings: SqlStorageValue[]) {
      options.statements?.push(query.replace(/\s+/g, ' ').trim());
      if (options.failing?.test(query)) {
        throw new Error(options.message ?? 'statement failed');
      }
      return storage.sql.exec(query, ...bindings);
    },
  } as SqlStorage;
  return {
    sql,
    transactionSync: <T>(closure: () => T) => storage.transactionSync(closure),
  } as unknown as DurableObjectStorage;
}
