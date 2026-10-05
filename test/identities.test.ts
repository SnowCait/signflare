import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { npubEncode, nsecEncode } from 'nostr-tools/nip19';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { describe, expect, it } from 'vitest';
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
import { withDecryptedPrivateKey } from '../src/private-key-encryption';

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

      expect(deleteIdentity(sql, PUBKEY_ONE)).toBe(true);

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
      expect(deleteIdentity(state.storage.sql, PUBKEY_ONE)).toBe(false);
    });
  });

  it('allows the identity to be registered again after deletion', async () => {
    await runInDurableObject(freshHub(), async (_instance, state) => {
      const { sql } = state.storage;
      await registerIdentity(sql, randomMasterKey(), SECRET_ONE_HEX, NOW);
      deleteIdentity(sql, PUBKEY_ONE);
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
