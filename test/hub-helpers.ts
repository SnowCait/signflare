import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { generateSecretKey } from 'nostr-tools/pure';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { vi } from 'vitest';
import { registerIdentity } from '../src/identities';
import type { SignerHub } from '../src/signer-hub';

// Cloudflare's documented error for writes to a full SQLite-backed Durable Object.
export const SQLITE_FULL_MESSAGE = 'database or disk is full: SQLITE_FULL';

// Statements that write without deleting, which fail on full storage.
export const NON_DELETE_WRITE =
  /^\s*(INSERT|UPDATE|REPLACE|UPSERT|CREATE|ALTER)\b/i;

// Test-only value for the MASTER_ENCRYPTION_KEY secret. Not a real secret.
export const TEST_MASTER_ENCRYPTION_KEY =
  'test-only MASTER_ENCRYPTION_KEY, not a real secret';

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

// Replaces the env that the SignerHub instance behind `hub` reads, so that a
// test controls MASTER_ENCRYPTION_KEY instead of inheriting whatever the local
// environment provides. Lasts until the instance is evicted.
export function replaceHubEnv(
  hub: DurableObjectStub<SignerHub>,
  replace: (env: Record<string, unknown>) => Record<string, unknown>,
): Promise<void> {
  return runInDurableObject(hub, (instance) => {
    const target = instance as unknown as { env: Record<string, unknown> };
    target.env = replace(target.env);
  });
}

// undefined removes the secret.
export function setMasterEncryptionKey(
  hub: DurableObjectStub<SignerHub>,
  value: unknown,
): Promise<void> {
  return replaceHubEnv(hub, (hubEnv) => {
    const replaced = { ...hubEnv };
    if (value === undefined) {
      delete replaced.MASTER_ENCRYPTION_KEY;
    } else {
      replaced.MASTER_ENCRYPTION_KEY = value;
    }
    return replaced;
  });
}

// `workerEnv` without the binding `name`. The generated Env types every
// configured value as present, but a deployment can still lack one.
export function withoutBinding(workerEnv: Env, name: keyof Env): Env {
  const remaining: Partial<Env> = { ...workerEnv };
  delete remaining[name];
  return remaining as Env;
}

// An env that records every read of MASTER_ENCRYPTION_KEY into `reads`.
export function recordingMasterKeyReads<T extends object>(
  target: T,
  reads: string[],
): T {
  return recordingReads(target, ['MASTER_ENCRYPTION_KEY'], reads);
}

// An env that records every read of one of `names` into `reads`.
export function recordingReads<T extends object>(
  target: T,
  names: readonly string[],
  reads: string[],
): T {
  const record = (key: PropertyKey) => {
    if (typeof key === 'string' && names.includes(key)) {
      reads.push(key);
    }
  };
  return new Proxy(target, {
    get(object, key, receiver) {
      record(key);
      return Reflect.get(object, key, receiver);
    },
    has(object, key) {
      record(key);
      return Reflect.has(object, key);
    },
    getOwnPropertyDescriptor(object, key) {
      record(key);
      return Reflect.getOwnPropertyDescriptor(object, key);
    },
  });
}

// Like instrumentedStorage(), but for the storage that SignerHub methods use
// themselves: in every SignerHub, until mocks are restored, each statement is
// recorded and statements matching `failing` throw `message`.
export async function instrumentHubSql(
  hub: DurableObjectStub<SignerHub>,
  options: { failing?: RegExp; message?: string; statements?: string[] },
): Promise<void> {
  const prototype = await runInDurableObject(
    hub,
    (_instance, state): SqlStorage => Object.getPrototypeOf(state.storage.sql),
  );
  const exec = prototype.exec;
  vi.spyOn(prototype, 'exec').mockImplementation(function (
    this: SqlStorage,
    query: string,
    ...bindings: SqlStorageValue[]
  ) {
    options.statements?.push(query.replace(/\s+/g, ' ').trim());
    if (options.failing?.test(query)) {
      throw new Error(options.message ?? 'statement failed');
    }
    return exec.call(this, query, ...bindings);
  });
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
