import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { npubEncode, nsecEncode } from 'nostr-tools/nip19';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { afterEach, describe, expect, it, type MockInstance, vi } from 'vitest';
import {
  deleteIdentity,
  DuplicateIdentityError,
  getIdentity,
  identityExists,
  insertIdentity,
  listIdentities,
  registerIdentity,
} from '../src/identities';
import { InvalidPrivateKeyError } from '../src/private-key';
import {
  PrivateKeyDecryptionError,
  withDecryptedPrivateKey,
} from '../src/private-key-encryption';
import type { RegisterIdentityResult, SignerHub } from '../src/signer-hub';
import {
  addIdentity,
  instrumentedStorage,
  instrumentHubSql,
  NON_DELETE_WRITE,
  recordingMasterKeyReads,
  replaceHubEnv,
  setMasterEncryptionKey,
  SQLITE_FULL_MESSAGE,
  TEST_MASTER_ENCRYPTION_KEY,
} from './hub-helpers';
import { randomKey } from './nostr-helpers';

// Test-only fixtures: trivially guessable scalars that must never hold funds or identity.
const SECRET_ONE_HEX = `${'00'.repeat(31)}01`;
const SECRET_ONE_NSEC =
  'nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsmhltgl';
const PUBKEY_ONE =
  '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const SECRET_THREE_HEX = `${'00'.repeat(31)}03`;
const PUBKEY_THREE =
  'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';

const NOW = 1_700_000_000;

function freshHub() {
  return env.SIGNER_HUB.getByName(crypto.randomUUID());
}

function randomMasterKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  return bytesToHex(haystack).includes(bytesToHex(needle));
}

// Every value in every table, so tests can assert what was persisted.
function allStoredValues(sql: SqlStorage): SqlStorageValue[] {
  const tables = sql
    .exec<{ name: string }>(
      "SELECT name FROM sqlite_master WHERE type = 'table'",
    )
    .toArray();
  return tables.flatMap(({ name }) =>
    [...sql.exec(`SELECT * FROM "${name}"`).raw()].flat(),
  );
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('registerIdentity', () => {
  it('registers an identity from an nsec', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const identity = await registerIdentity(
        state.storage.sql,
        randomMasterKey(),
        SECRET_ONE_NSEC,
        NOW,
      );
      expect(identity).toEqual({
        pubkey: PUBKEY_ONE,
        npub: npubEncode(PUBKEY_ONE),
        createdAt: NOW,
        updatedAt: NOW,
      });
      expect(identityExists(state.storage.sql, PUBKEY_ONE)).toBe(true);
    });
  });

  it('registers an identity from hex', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const identity = await registerIdentity(
        state.storage.sql,
        randomMasterKey(),
        SECRET_THREE_HEX,
        NOW,
      );
      expect(identity.pubkey).toBe(PUBKEY_THREE);
      expect(identityExists(state.storage.sql, PUBKEY_THREE)).toBe(true);
    });
  });

  it('returns only public identity metadata', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const identity = await registerIdentity(
        state.storage.sql,
        randomMasterKey(),
        SECRET_ONE_NSEC,
        NOW,
      );
      expect(Object.keys(identity).sort()).toEqual([
        'createdAt',
        'npub',
        'pubkey',
        'updatedAt',
      ]);
      const serialized = JSON.stringify(identity);
      expect(serialized).not.toContain(SECRET_ONE_HEX);
      expect(serialized).not.toContain(SECRET_ONE_NSEC);
    });
  });

  it('stores an encrypted envelope that decrypts to the registered key', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const masterKey = randomMasterKey();
      await registerIdentity(state.storage.sql, masterKey, SECRET_ONE_HEX, NOW);

      const row = state.storage.sql
        .exec<{
          encrypted_private_key: ArrayBuffer;
          iv: ArrayBuffer;
          kdf_salt: ArrayBuffer;
          key_version: number;
          created_at: number;
          updated_at: number;
        }>('SELECT * FROM identities WHERE pubkey = ?', PUBKEY_ONE)
        .one();
      expect(row.encrypted_private_key).toBeInstanceOf(ArrayBuffer);
      expect(row.encrypted_private_key.byteLength).toBe(48);
      expect(row.iv.byteLength).toBe(12);
      expect(row.kdf_salt.byteLength).toBe(32);
      expect(row.key_version).toBe(1);
      expect(row.created_at).toBe(NOW);
      expect(row.updated_at).toBe(NOW);

      const record = getIdentity(state.storage.sql, PUBKEY_ONE);
      expect(record).not.toBeNull();
      const decrypted = await withDecryptedPrivateKey(
        masterKey,
        PUBKEY_ONE,
        record!.encryptedPrivateKey,
        (secretKey) => bytesToHex(secretKey),
      );
      expect(decrypted).toBe(SECRET_ONE_HEX);
    });
  });

  it('does not store the plaintext private key anywhere in the database', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      await registerIdentity(
        state.storage.sql,
        randomMasterKey(),
        SECRET_ONE_NSEC,
        NOW,
      );
      await registerIdentity(
        state.storage.sql,
        randomMasterKey(),
        SECRET_THREE_HEX,
        NOW,
      );

      const values = allStoredValues(state.storage.sql);
      expect(values.length).toBeGreaterThan(0);
      for (const secretHex of [SECRET_ONE_HEX, SECRET_THREE_HEX]) {
        const secret = hexToBytes(secretHex);
        const nsec = nsecEncode(secret);
        for (const value of values) {
          if (value instanceof ArrayBuffer) {
            expect(containsBytes(new Uint8Array(value), secret)).toBe(false);
          } else if (typeof value === 'string') {
            expect(value.toLowerCase()).not.toContain(secretHex);
            expect(value).not.toContain(nsec);
          }
        }
      }
    });
  });

  it('rejects a duplicate identity in either input form', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const { sql } = state.storage;
      await registerIdentity(sql, randomMasterKey(), SECRET_ONE_NSEC, NOW);
      const stored = getIdentity(sql, PUBKEY_ONE);

      for (const input of [SECRET_ONE_NSEC, SECRET_ONE_HEX]) {
        const attempt = registerIdentity(
          sql,
          randomMasterKey(),
          input,
          NOW + 1,
        );
        await expect(attempt).rejects.toThrow(DuplicateIdentityError);
        await expect(attempt).rejects.toMatchObject({ pubkey: PUBKEY_ONE });
      }

      expect(listIdentities(sql)).toHaveLength(1);
      expect(getIdentity(sql, PUBKEY_ONE)).toEqual(stored);
    });
  });

  it('rejects an invalid private key without storing anything', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      await expect(
        registerIdentity(state.storage.sql, randomMasterKey(), 'nsec1invalid'),
      ).rejects.toThrow(InvalidPrivateKeyError);
      await expect(
        registerIdentity(state.storage.sql, randomMasterKey(), '00'.repeat(32)),
      ).rejects.toThrow(InvalidPrivateKeyError);
      expect(listIdentities(state.storage.sql)).toEqual([]);
    });
  });

  it('uses the current time when no timestamp is given', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const before = Math.floor(Date.now() / 1000);
      const identity = await registerIdentity(
        state.storage.sql,
        randomMasterKey(),
        SECRET_ONE_HEX,
      );
      expect(identity.createdAt).toBeGreaterThanOrEqual(before);
      expect(identity.createdAt).toBeLessThanOrEqual(
        Math.floor(Date.now() / 1000),
      );
      expect(identity.updatedAt).toBe(identity.createdAt);
    });
  });
});

describe('insertIdentity', () => {
  it('rejects a record whose pubkey already exists', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const { sql } = state.storage;
      await registerIdentity(sql, randomMasterKey(), SECRET_ONE_HEX, NOW);
      const existing = getIdentity(sql, PUBKEY_ONE)!;

      expect(() =>
        insertIdentity(sql, { ...existing, createdAt: NOW + 1 }),
      ).toThrow(DuplicateIdentityError);
      expect(getIdentity(sql, PUBKEY_ONE)).toEqual(existing);
    });
  });
});

describe('listIdentities', () => {
  it('returns an empty list when no identity is registered', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      expect(listIdentities(state.storage.sql)).toEqual([]);
    });
  });

  it('lists public metadata only, oldest first', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const { sql } = state.storage;
      await registerIdentity(
        sql,
        randomMasterKey(),
        SECRET_THREE_HEX,
        NOW + 10,
      );
      await registerIdentity(sql, randomMasterKey(), SECRET_ONE_NSEC, NOW);

      const identities = listIdentities(sql);
      expect(identities).toEqual([
        {
          pubkey: PUBKEY_ONE,
          npub: npubEncode(PUBKEY_ONE),
          createdAt: NOW,
          updatedAt: NOW,
        },
        {
          pubkey: PUBKEY_THREE,
          npub: npubEncode(PUBKEY_THREE),
          createdAt: NOW + 10,
          updatedAt: NOW + 10,
        },
      ]);
      for (const identity of identities) {
        expect(Object.keys(identity).sort()).toEqual([
          'createdAt',
          'npub',
          'pubkey',
          'updatedAt',
        ]);
      }
    });
  });
});

describe('getIdentity', () => {
  it('looks up an identity record by pubkey', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const { sql } = state.storage;
      await registerIdentity(sql, randomMasterKey(), SECRET_ONE_HEX, NOW);

      const record = getIdentity(sql, PUBKEY_ONE);
      expect(record).toMatchObject({
        pubkey: PUBKEY_ONE,
        createdAt: NOW,
        updatedAt: NOW,
        encryptedPrivateKey: { keyVersion: 1 },
      });
      expect(record?.encryptedPrivateKey.ciphertext).toBeInstanceOf(Uint8Array);
      expect(record?.encryptedPrivateKey.ciphertext.byteLength).toBe(48);
      expect(record?.encryptedPrivateKey.iv.byteLength).toBe(12);
      expect(record?.encryptedPrivateKey.kdfSalt.byteLength).toBe(32);
    });
  });

  it('returns null for an unknown pubkey', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      expect(getIdentity(state.storage.sql, PUBKEY_ONE)).toBeNull();
    });
  });
});

describe('deleteIdentity', () => {
  it('deletes an identity so it can no longer be looked up', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const { sql } = state.storage;
      await registerIdentity(sql, randomMasterKey(), SECRET_ONE_HEX, NOW);
      await registerIdentity(sql, randomMasterKey(), SECRET_THREE_HEX, NOW);

      expect(deleteIdentity(state.storage, PUBKEY_ONE)).toBe(true);

      expect(getIdentity(sql, PUBKEY_ONE)).toBeNull();
      expect(identityExists(sql, PUBKEY_ONE)).toBe(false);
      expect(listIdentities(sql).map(({ pubkey }) => pubkey)).toEqual([
        PUBKEY_THREE,
      ]);
      expect(getIdentity(sql, PUBKEY_THREE)).not.toBeNull();
    });
  });

  it('reports when there was nothing to delete', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      expect(deleteIdentity(state.storage, PUBKEY_ONE)).toBe(false);
    });
  });

  it('allows the identity to be registered again after deletion', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const { sql } = state.storage;
      await registerIdentity(sql, randomMasterKey(), SECRET_ONE_HEX, NOW);
      deleteIdentity(state.storage, PUBKEY_ONE);
      const identity = await registerIdentity(
        sql,
        randomMasterKey(),
        SECRET_ONE_NSEC,
        NOW + 1,
      );
      expect(identity.createdAt).toBe(NOW + 1);
    });
  });
});

describe('identity deletion cascade', () => {
  type Hub = DurableObjectStub<SignerHub>;

  async function pair(hub: Hub, identity: string): Promise<string> {
    const result = await hub.createPairing(identity, 'all', NOW);
    if (result.status !== 'created') {
      throw new Error(result.status);
    }
    return result.secret;
  }

  async function connect(hub: Hub, identity: string): Promise<string> {
    const result = await hub.establishSession({
      secret: await pair(hub, identity),
      clientPubkey: randomKey().pubkey,
      now: NOW + 1,
    });
    if (result.status !== 'created') {
      throw new Error(result.status);
    }
    return result.session.clientPubkey;
  }

  // Two sessions and two unused pairings for the identity to delete, and one
  // of each for another identity.
  async function populated() {
    const hub = freshHub();
    const target = await addIdentity(hub);
    const other = await addIdentity(hub);
    return {
      hub,
      target,
      other,
      targetClients: [await connect(hub, target), await connect(hub, target)],
      targetSecrets: [await pair(hub, target), await pair(hub, target)],
      otherClient: await connect(hub, other),
      otherSecret: await pair(hub, other),
    };
  }

  function rowCounts(sql: SqlStorage, pubkey: string) {
    const count = (query: string) =>
      sql.exec<{ count: number }>(query, pubkey).one().count;
    return {
      identities: count(
        'SELECT COUNT(*) AS count FROM identities WHERE pubkey = ?',
      ),
      pairings: count(
        'SELECT COUNT(*) AS count FROM pairings WHERE identity_pubkey = ?',
      ),
      sessions: count(
        'SELECT COUNT(*) AS count FROM sessions WHERE identity_pubkey = ?',
      ),
    };
  }

  function counts(hub: Hub, ...pubkeys: string[]) {
    return runInDurableObject(hub, (_instance, state) =>
      pubkeys.map((pubkey) => rowCounts(state.storage.sql, pubkey)),
    );
  }

  it('removes the identity with its sessions and pairings', async () => {
    const { hub, target, other } = await populated();
    expect(await counts(hub, target, other)).toEqual([
      { identities: 1, pairings: 2, sessions: 2 },
      { identities: 1, pairings: 1, sessions: 1 },
    ]);

    expect(await hub.deleteIdentity(target)).toBe(true);

    expect(await counts(hub, target, other)).toEqual([
      { identities: 0, pairings: 0, sessions: 0 },
      { identities: 1, pairings: 1, sessions: 1 },
    ]);
  });

  it('leaves no session or pairing secret of the identity usable', async () => {
    const { hub, target, targetClients, targetSecrets } = await populated();
    await hub.deleteIdentity(target);

    for (const clientPubkey of targetClients) {
      expect(await hub.getSession(clientPubkey)).toBeNull();
      expect(await hub.touchSession(clientPubkey, NOW + 2)).toBe(false);
    }
    expect(await hub.listSessions(target)).toEqual([]);
    for (const secret of targetSecrets) {
      expect(
        await hub.establishSession({
          secret,
          clientPubkey: randomKey().pubkey,
          now: NOW + 2,
        }),
      ).toEqual({ status: 'invalid_secret' });
    }
    expect(await hub.createPairing(target, 'all', NOW + 2)).toEqual({
      status: 'identity_not_found',
    });
  });

  it('keeps the sessions and pairings of other identities', async () => {
    const { hub, target, other, otherClient, otherSecret } = await populated();
    const session = await hub.getSession(otherClient);
    await hub.deleteIdentity(target);

    expect(await hub.getSession(otherClient)).toEqual(session);
    expect(await hub.listSessions(other)).toEqual([session]);
    expect(
      await hub.establishSession({
        secret: otherSecret,
        clientPubkey: randomKey().pubkey,
        now: NOW + 2,
      }),
    ).toMatchObject({ status: 'created', session: { identityPubkey: other } });
  });

  it('reports false for an unknown identity and changes nothing', async () => {
    const { hub, target, other } = await populated();
    const before = await counts(hub, target, other);
    expect(await hub.deleteIdentity(randomKey().pubkey)).toBe(false);
    expect(await counts(hub, target, other)).toEqual(before);

    expect(await hub.deleteIdentity(target)).toBe(true);
    expect(await hub.deleteIdentity(target)).toBe(false);
  });

  it('deletes sessions, then pairings, then the identity', async () => {
    const { hub, target } = await populated();
    await runInDurableObject(hub, (_instance, state) => {
      const statements: string[] = [];
      const storage = instrumentedStorage(state.storage, { statements });
      expect(deleteIdentity(storage, target)).toBe(true);
      expect(statements).toEqual([
        'DELETE FROM sessions WHERE identity_pubkey = ?',
        'DELETE FROM pairings WHERE identity_pubkey = ?',
        'DELETE FROM identities WHERE pubkey = ? RETURNING pubkey',
      ]);
    });
  });

  it.each([
    ['sessions', /DELETE FROM sessions/],
    ['pairings', /DELETE FROM pairings/],
    ['the identity', /DELETE FROM identities/],
  ])('rolls everything back when deleting %s fails', async (_case, failing) => {
    const { hub, target, targetClients } = await populated();
    const before = await counts(hub, target);
    await runInDurableObject(hub, (_instance, state) => {
      const storage = instrumentedStorage(state.storage, {
        failing,
        message: 'unexpected',
      });
      expect(() => deleteIdentity(storage, target)).toThrow('unexpected');
    });
    expect(await counts(hub, target)).toEqual(before);
    expect(await hub.getSession(targetClients[0])).not.toBeNull();
  });

  it('needs no writes other than deletes, so it works on full storage', async () => {
    const { hub, target, other } = await populated();
    await runInDurableObject(hub, (_instance, state) => {
      const statements: string[] = [];
      const storage = instrumentedStorage(state.storage, {
        failing: /^\s*(INSERT|UPDATE|REPLACE|UPSERT|CREATE|ALTER)\b/i,
        message: SQLITE_FULL_MESSAGE,
        statements,
      });
      expect(deleteIdentity(storage, target)).toBe(true);
      expect(statements.length).toBeGreaterThan(0);
      for (const statement of statements) {
        expect(statement).toMatch(/^DELETE FROM /);
      }
    });
    expect(await counts(hub, target, other)).toEqual([
      { identities: 0, pairings: 0, sessions: 0 },
      { identities: 1, pairings: 1, sessions: 1 },
    ]);
  });

  it('needs no MASTER_ENCRYPTION_KEY and never reads it', async () => {
    const { hub, target, other } = await populated();
    await setMasterEncryptionKey(hub, undefined);
    const reads: string[] = [];
    await replaceHubEnv(hub, (hubEnv) =>
      recordingMasterKeyReads(hubEnv, reads),
    );

    expect(await hub.deleteIdentity(target)).toBe(true);
    expect(reads).toEqual([]);
    expect(await counts(hub, target, other)).toEqual([
      { identities: 0, pairings: 0, sessions: 0 },
      { identities: 1, pairings: 1, sessions: 1 },
    ]);
  });
});

describe('SignerHub.registerIdentity', () => {
  type Hub = DurableObjectStub<SignerHub>;

  async function configuredHub(masterKey: unknown): Promise<Hub> {
    const hub = freshHub();
    await setMasterEncryptionKey(hub, masterKey);
    return hub;
  }

  function identityRows(hub: Hub) {
    return runInDurableObject(hub, (_instance, state) =>
      state.storage.sql.exec('SELECT * FROM identities').toArray(),
    );
  }

  // The buffers that TextEncoder produced from the test master key.
  function masterKeyBuffers(
    encode: MockInstance<TextEncoder['encode']>,
  ): Uint8Array[] {
    return encode.mock.calls.flatMap(([input], index) =>
      input === TEST_MASTER_ENCRYPTION_KEY
        ? [encode.mock.results[index].value]
        : [],
    );
  }

  // Decrypts the stored key of `pubkey` with the given root key material.
  function decryptStored(
    hub: Hub,
    pubkey: string,
    masterKey: Uint8Array,
  ): Promise<string> {
    return runInDurableObject(hub, (_instance, state) => {
      const record = getIdentity(state.storage.sql, pubkey);
      if (record === null) {
        throw new Error('identity not found');
      }
      return withDecryptedPrivateKey(
        masterKey,
        pubkey,
        record.encryptedPrivateKey,
        (secretKey) => bytesToHex(secretKey),
      );
    });
  }

  it('registers an identity with the configured MASTER_ENCRYPTION_KEY', async () => {
    const hub = await configuredHub(TEST_MASTER_ENCRYPTION_KEY);
    expect(await hub.registerIdentity(SECRET_ONE_NSEC, NOW)).toEqual({
      status: 'created',
      identity: {
        pubkey: PUBKEY_ONE,
        npub: npubEncode(PUBKEY_ONE),
        createdAt: NOW,
        updatedAt: NOW,
      },
    });
    expect(
      await decryptStored(hub, PUBKEY_ONE, utf8(TEST_MASTER_ENCRYPTION_KEY)),
    ).toBe(SECRET_ONE_HEX);
  });

  it('registers an identity from hex', async () => {
    const hub = await configuredHub(TEST_MASTER_ENCRYPTION_KEY);
    expect(await hub.registerIdentity(SECRET_THREE_HEX, NOW)).toMatchObject({
      status: 'created',
      identity: { pubkey: PUBKEY_THREE },
    });
  });

  it.each<[string, string]>([
    ['exactly 32 bytes', 'test-only master key: 32 bytes!!'],
    ['longer than 32 bytes', TEST_MASTER_ENCRYPTION_KEY.repeat(4)],
    ['32 bytes in 16 characters', '\u00e9'.repeat(16)],
  ])('accepts a key of %s', async (_case, masterKey) => {
    const hub = await configuredHub(masterKey);
    expect(await hub.registerIdentity(SECRET_ONE_HEX, NOW)).toMatchObject({
      status: 'created',
    });
    expect(await decryptStored(hub, PUBKEY_ONE, utf8(masterKey))).toBe(
      SECRET_ONE_HEX,
    );
  });

  it.each<[string, string, (secret: string) => Uint8Array]>([
    [
      'trimmed',
      ' \ttest-only master key, surrounded by whitespace\n',
      (secret) => utf8(secret.trim()),
    ],
    [
      'normalized',
      'test-only cafe\u0301 master key, decomposed',
      (secret) => utf8(secret.normalize('NFC')),
    ],
    [
      'decoded from hex',
      '0123456789abcdef'.repeat(4),
      (secret) => hexToBytes(secret),
    ],
    [
      'decoded from base64',
      btoa('test-only master key: 32 bytes!!'),
      (secret) => Uint8Array.from(atob(secret), (c) => c.charCodeAt(0)),
    ],
  ])('uses the key text as is, not %s', async (_case, secret, misread) => {
    // Long enough to be a valid key, so only the bytes differ.
    expect(misread(secret).byteLength).toBeGreaterThanOrEqual(32);
    const hub = await configuredHub(secret);
    expect(await hub.registerIdentity(SECRET_ONE_HEX, NOW)).toMatchObject({
      status: 'created',
    });

    expect(await decryptStored(hub, PUBKEY_ONE, utf8(secret))).toBe(
      SECRET_ONE_HEX,
    );
    await expect(
      decryptStored(hub, PUBKEY_ONE, misread(secret)),
    ).rejects.toThrow(PrivateKeyDecryptionError);
  });

  it.each<[string, unknown]>([
    ['missing', undefined],
    ['empty', ''],
    ['31 bytes long', 'test-only master key: 31 bytes!'],
    ['30 bytes in 10 characters', '\u9375'.repeat(10)],
    ['not a string', 12_345],
  ])(
    'reports a configuration error when the key is %s',
    async (_case, masterKey) => {
      const hub = await configuredHub(masterKey);
      expect(await hub.registerIdentity(SECRET_ONE_HEX, NOW)).toEqual({
        status: 'configuration_error',
      });
      // The key is checked before the private key is even parsed.
      expect(await hub.registerIdentity('nsec1invalid', NOW)).toEqual({
        status: 'configuration_error',
      });
      expect(await identityRows(hub)).toEqual([]);
    },
  );

  it.each<[string, unknown]>([
    ['an invalid nsec', 'nsec1invalid'],
    ['an nsec with a bad checksum', `${SECRET_ONE_NSEC.slice(0, -1)}q`],
    ['an npub', npubEncode(PUBKEY_ONE)],
    ['hex that is too short', SECRET_ONE_HEX.slice(1)],
    ['hex outside the secp256k1 range', '00'.repeat(32)],
    ['an empty string', ''],
    ['a value that is not a string', 1],
  ])('reports %s as an invalid private key', async (_case, privateKey) => {
    const hub = await configuredHub(TEST_MASTER_ENCRYPTION_KEY);
    expect(await hub.registerIdentity(privateKey as string, NOW)).toEqual({
      status: 'invalid_private_key',
    });
    expect(await identityRows(hub)).toEqual([]);
  });

  it('reports a duplicate in either input form and keeps the stored identity', async () => {
    const hub = await configuredHub(TEST_MASTER_ENCRYPTION_KEY);
    await hub.registerIdentity(SECRET_ONE_NSEC, NOW);
    const before = await identityRows(hub);

    for (const input of [SECRET_ONE_NSEC, SECRET_ONE_HEX]) {
      expect(await hub.registerIdentity(input, NOW + 1)).toEqual({
        status: 'duplicate',
      });
    }
    expect(await identityRows(hub)).toEqual(before);
  });

  it('reports full storage without storing anything', async () => {
    const hub = await configuredHub(TEST_MASTER_ENCRYPTION_KEY);
    await instrumentHubSql(hub, {
      failing: NON_DELETE_WRITE,
      message: SQLITE_FULL_MESSAGE,
    });
    expect(await hub.registerIdentity(SECRET_ONE_HEX, NOW)).toEqual({
      status: 'storage_full',
    });
    vi.restoreAllMocks();
    expect(await identityRows(hub)).toEqual([]);
  });

  it('throws unexpected errors instead of reporting them', async () => {
    const hub = await configuredHub(TEST_MASTER_ENCRYPTION_KEY);
    await instrumentHubSql(hub, {
      failing: /INSERT INTO identities/,
      message: 'unexpected failure',
    });
    await runInDurableObject(hub, async (instance) => {
      await expect(
        instance.registerIdentity(SECRET_ONE_HEX, NOW),
      ).rejects.toThrow('unexpected failure');
    });
    vi.restoreAllMocks();
    expect(await identityRows(hub)).toEqual([]);
  });

  it('overwrites the key bytes whatever the outcome', async () => {
    const hub = await configuredHub(TEST_MASTER_ENCRYPTION_KEY);
    await hub.registerIdentity(SECRET_THREE_HEX, NOW);
    const encode = vi.spyOn(TextEncoder.prototype, 'encode');
    const importKey = vi.spyOn(crypto.subtle, 'importKey');

    const outcomes: RegisterIdentityResult['status'][] = [];
    for (const privateKey of [SECRET_ONE_HEX, 'nsec1invalid', SECRET_ONE_HEX]) {
      outcomes.push((await hub.registerIdentity(privateKey, NOW)).status);
    }
    await instrumentHubSql(hub, {
      failing: NON_DELETE_WRITE,
      message: SQLITE_FULL_MESSAGE,
    });
    const { secretKey } = randomKey();
    outcomes.push(
      (await hub.registerIdentity(bytesToHex(secretKey), NOW)).status,
    );
    expect(outcomes).toEqual([
      'created',
      'invalid_private_key',
      'duplicate',
      'storage_full',
    ]);

    const keyBuffers = masterKeyBuffers(encode);
    expect(keyBuffers).toHaveLength(outcomes.length);
    const zeros = new Uint8Array(utf8(TEST_MASTER_ENCRYPTION_KEY).byteLength);
    for (const buffer of keyBuffers) {
      expect(buffer).toEqual(zeros);
    }
    // The bytes handed to HKDF are those same buffers.
    const hkdfKeys = importKey.mock.calls
      .filter(([, , algorithm]) => algorithm === 'HKDF')
      .map(([, keyData]) => keyData);
    expect(hkdfKeys).toHaveLength(2);
    for (const keyData of hkdfKeys) {
      expect(keyBuffers).toContain(keyData);
    }
  });

  it('overwrites the key bytes when an unexpected error is thrown', async () => {
    const hub = await configuredHub(TEST_MASTER_ENCRYPTION_KEY);
    const encode = vi.spyOn(TextEncoder.prototype, 'encode');
    await instrumentHubSql(hub, {
      failing: /INSERT INTO identities/,
      message: 'unexpected failure',
    });
    await runInDurableObject(hub, async (instance) => {
      await expect(
        instance.registerIdentity(SECRET_ONE_HEX, NOW),
      ).rejects.toThrow('unexpected failure');
    });
    const keyBuffers = masterKeyBuffers(encode);
    expect(keyBuffers).toEqual([
      new Uint8Array(utf8(TEST_MASTER_ENCRYPTION_KEY).byteLength),
    ]);
  });

  it('returns public metadata only and logs nothing', async () => {
    const hub = await configuredHub(TEST_MASTER_ENCRYPTION_KEY);
    const logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map(
      (method) => vi.spyOn(console, method).mockImplementation(() => {}),
    );
    const results = [
      await hub.registerIdentity(SECRET_ONE_NSEC, NOW),
      await hub.registerIdentity(SECRET_ONE_HEX, NOW),
      await hub.registerIdentity(`${SECRET_ONE_NSEC.slice(0, -1)}q`, NOW),
    ];
    await setMasterEncryptionKey(hub, undefined);
    results.push(await hub.registerIdentity(SECRET_THREE_HEX, NOW));

    expect(results.map(({ status }) => status)).toEqual([
      'created',
      'duplicate',
      'invalid_private_key',
      'configuration_error',
    ]);
    const created = results[0];
    if (created.status !== 'created') {
      throw new Error(created.status);
    }
    expect(Object.keys(created).sort()).toEqual(['identity', 'status']);
    expect(Object.keys(created.identity).sort()).toEqual([
      'createdAt',
      'npub',
      'pubkey',
      'updatedAt',
    ]);
    const text = JSON.stringify(results);
    for (const secret of [
      SECRET_ONE_HEX,
      SECRET_ONE_NSEC,
      SECRET_THREE_HEX,
      TEST_MASTER_ENCRYPTION_KEY,
      bytesToHex(utf8(TEST_MASTER_ENCRYPTION_KEY)),
    ]) {
      expect(text).not.toContain(secret);
    }
    for (const log of logs) {
      expect(log).not.toHaveBeenCalled();
    }
  });
});

describe('SignerHub.listIdentities', () => {
  it('returns an empty list when no identity is registered', async () => {
    expect(await freshHub().listIdentities()).toEqual([]);
  });

  it('lists public metadata in a deterministic order', async () => {
    const hub = freshHub();
    await setMasterEncryptionKey(hub, TEST_MASTER_ENCRYPTION_KEY);
    const tied = randomKey();
    await hub.registerIdentity(SECRET_THREE_HEX, NOW - 10);
    await hub.registerIdentity(bytesToHex(tied.secretKey), NOW);
    await hub.registerIdentity(SECRET_ONE_NSEC, NOW);
    const metadata = (pubkey: string, createdAt: number) => ({
      pubkey,
      npub: npubEncode(pubkey),
      createdAt,
      updatedAt: createdAt,
    });

    // Oldest first, then by pubkey.
    expect(await hub.listIdentities()).toEqual([
      metadata(PUBKEY_THREE, NOW - 10),
      ...[tied.pubkey, PUBKEY_ONE]
        .sort()
        .map((pubkey) => metadata(pubkey, NOW)),
    ]);
  });

  it('reads neither key material nor MASTER_ENCRYPTION_KEY', async () => {
    const hub = freshHub();
    await setMasterEncryptionKey(hub, TEST_MASTER_ENCRYPTION_KEY);
    await hub.registerIdentity(SECRET_ONE_HEX, NOW);
    const reads: string[] = [];
    await replaceHubEnv(hub, (hubEnv) =>
      recordingMasterKeyReads(hubEnv, reads),
    );
    const statements: string[] = [];
    await instrumentHubSql(hub, { statements });

    const [identity] = await hub.listIdentities();
    expect(Object.keys(identity).sort()).toEqual([
      'createdAt',
      'npub',
      'pubkey',
      'updatedAt',
    ]);
    expect(reads).toEqual([]);
    expect(statements).toEqual([
      'SELECT pubkey, created_at, updated_at FROM identities ORDER BY created_at, pubkey',
    ]);
  });
});
