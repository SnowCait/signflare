import { runInDurableObject } from 'cloudflare:test';
import { bytesToHex } from 'nostr-tools/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createPairing,
  deletePairing,
  findPairing,
  generatePairingSecret,
  hashPairingSecret,
  isPairingSecret,
  PAIRING_LIFETIME_SECONDS,
} from '../src/pairings';
import { MalformedPermissionsError } from '../src/permissions';
import {
  addIdentity,
  freshHub,
  instrumentedStorage,
  SQLITE_FULL_MESSAGE,
  valuesContainingSecret,
} from './hub-helpers';
import { randomKey } from './nostr-helpers';

const NOW = 1_700_000_000;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type PairingRow = {
  id: string;
  identity_pubkey: string;
  secret_hash: ArrayBuffer;
  permissions: string;
  expires_at: number;
  created_at: number;
};

function pairingRows(sql: SqlStorage): PairingRow[] {
  return sql
    .exec<PairingRow>('SELECT * FROM pairings ORDER BY created_at, id')
    .toArray();
}

async function sha256(text: string): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)),
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('pairing secrets', () => {
  it('are 32 random bytes encoded as lowercase hex', () => {
    const secrets = new Set(
      Array.from({ length: 16 }, () => generatePairingSecret()),
    );
    expect(secrets.size).toBe(16);
    for (const secret of secrets) {
      expect(secret).toMatch(/^[0-9a-f]{64}$/);
      expect(isPairingSecret(secret)).toBe(true);
    }
  });

  it('are hashed with SHA-256 over the exact secret string', async () => {
    const secret = generatePairingSecret();
    const hash = await hashPairingSecret(secret);
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.byteLength).toBe(32);
    expect(hash).toEqual(await sha256(secret));
    expect(await hashPairingSecret(secret)).toEqual(hash);
    expect(await hashPairingSecret(generatePairingSecret())).not.toEqual(hash);
    expect(bytesToHex(hash)).not.toContain(secret);
  });

  it.each<[string, unknown]>([
    ['an empty string', ''],
    ['uppercase hex', 'AB'.repeat(32)],
    ['mixed-case hex', `A${'b'.repeat(63)}`],
    ['a short value', 'ab'.repeat(31)],
    ['a long value', 'ab'.repeat(33)],
    ['non-hex characters', 'zz'.repeat(32)],
    ['surrounding whitespace', ` ${'ab'.repeat(32)} `],
    ['a trailing newline', `${'ab'.repeat(32)}\n`],
    ['a number', 42],
    ['null', null],
    ['undefined', undefined],
    ['bytes', new Uint8Array(32)],
  ])('rejects %s', async (_case, value) => {
    expect(isPairingSecret(value)).toBe(false);
    await expect(hashPairingSecret(value as string)).rejects.toThrow(
      new TypeError('Malformed pairing secret'),
    );
  });

  it('rejects oversized input without hashing it', async () => {
    const digest = vi.spyOn(crypto.subtle, 'digest');
    const oversized = 'a'.repeat(1_000_000);
    expect(isPairingSecret(oversized)).toBe(false);
    await expect(hashPairingSecret(oversized)).rejects.toThrow(TypeError);
    expect(digest).not.toHaveBeenCalled();

    await hashPairingSecret(generatePairingSecret());
    expect(digest).toHaveBeenCalledOnce();
  });
});

describe('createPairing', () => {
  it('creates a pairing that expires exactly 10 minutes later', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);

    const result = await hub.createPairing(
      identity,
      ['sign_event:1', 'nip44_encrypt', 'nip44_decrypt'],
      NOW,
    );

    expect(PAIRING_LIFETIME_SECONDS).toBe(600);
    expect(result).toEqual({
      status: 'created',
      pairing: {
        id: expect.stringMatching(UUID),
        identityPubkey: identity,
        permissions: ['sign_event:1', 'nip44_encrypt', 'nip44_decrypt'],
        createdAt: NOW,
        expiresAt: NOW + 600,
      },
      secret: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
  });

  it('stores the hash of the secret and the canonical permissions', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const result = await hub.createPairing(
      identity,
      ['nip44_encrypt', 'sign_event:7', 'sign_event:1', 'nip44_encrypt'],
      NOW,
    );
    if (result.status !== 'created') {
      throw new Error(result.status);
    }

    const rows = await runInDurableObject(hub, (_instance, state) =>
      pairingRows(state.storage.sql),
    );
    expect(rows).toEqual([
      {
        id: result.pairing.id,
        identity_pubkey: identity,
        secret_hash: expect.any(ArrayBuffer),
        permissions: '["sign_event:1","sign_event:7","nip44_encrypt"]',
        expires_at: NOW + 600,
        created_at: NOW,
      },
    ]);
    expect(rows[0].expires_at - rows[0].created_at).toBe(600);
    expect(new Uint8Array(rows[0].secret_hash)).toEqual(
      await sha256(result.secret),
    );
    expect(result.pairing.permissions).toEqual([
      'sign_event:1',
      'sign_event:7',
      'nip44_encrypt',
    ]);
  });

  it('expands all and never stores it', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    for (const permissions of ['all', ['all'], ['sign_event:1', 'all']]) {
      const result = await hub.createPairing(
        identity,
        permissions as 'all' | string[],
        NOW,
      );
      expect(result).toMatchObject({
        status: 'created',
        pairing: {
          permissions: [
            'sign_event',
            'nip04_encrypt',
            'nip04_decrypt',
            'nip44_encrypt',
            'nip44_decrypt',
          ],
        },
      });
    }
    const rows = await runInDurableObject(hub, (_instance, state) =>
      pairingRows(state.storage.sql),
    );
    expect(rows).toHaveLength(3);
    for (const row of rows) {
      expect(row.permissions).toBe(
        '["sign_event","nip04_encrypt","nip04_decrypt","nip44_encrypt","nip44_decrypt"]',
      );
      expect(JSON.parse(row.permissions)).not.toContain('all');
    }
  });

  it('accepts an empty permission set', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    expect(await hub.createPairing(identity, [], NOW)).toMatchObject({
      status: 'created',
      pairing: { permissions: [] },
    });
  });

  it.each<[string, unknown]>([
    ['an uppercase ALL', 'ALL'],
    ['a single permission string', 'sign_event'],
    ['a NIP-46 style list', 'sign_event,nip44_encrypt'],
    ['a control method', ['ping']],
    ['an unknown method', ['sign_event', 'nip17_encrypt']],
    ['a negative kind', ['sign_event:-1']],
    ['a kind out of range', ['sign_event:65536']],
    ['whitespace', [' nip44_encrypt']],
    ['a non-string entry', [1]],
    ['null', null],
  ])('rejects %s without storing anything', async (_case, permissions) => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    expect(
      await hub.createPairing(identity, permissions as string[], NOW),
    ).toEqual({ status: 'invalid_permissions' });
    const rows = await runInDurableObject(hub, (_instance, state) =>
      pairingRows(state.storage.sql),
    );
    expect(rows).toEqual([]);
  });

  it('refuses identities that do not exist', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);

    for (const pubkey of [
      randomKey().pubkey,
      identity.toUpperCase(),
      identity.slice(2),
      '',
    ]) {
      expect(await hub.createPairing(pubkey, 'all', NOW)).toEqual({
        status: 'identity_not_found',
      });
    }
    const rows = await runInDurableObject(hub, (_instance, state) =>
      pairingRows(state.storage.sql),
    );
    expect(rows).toEqual([]);
  });

  it('gives every pairing its own id and secret', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const results = await Promise.all(
      Array.from({ length: 8 }, () => hub.createPairing(identity, 'all', NOW)),
    );
    const created = results.map((result) => {
      if (result.status !== 'created') {
        throw new Error(result.status);
      }
      return result;
    });
    expect(new Set(created.map(({ pairing }) => pairing.id)).size).toBe(8);
    expect(new Set(created.map(({ secret }) => secret)).size).toBe(8);
    const rows = await runInDurableObject(hub, (_instance, state) =>
      pairingRows(state.storage.sql),
    );
    expect(
      new Set(rows.map((row) => bytesToHex(new Uint8Array(row.secret_hash))))
        .size,
    ).toBe(8);
  });

  it('keeps the raw secret out of the database and the pairing', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const result = await hub.createPairing(identity, 'all', NOW);
    if (result.status !== 'created') {
      throw new Error(result.status);
    }
    expect(Object.keys(result).sort()).toEqual(['pairing', 'secret', 'status']);
    expect(JSON.stringify(result.pairing)).not.toContain(result.secret);
    await runInDurableObject(hub, (_instance, state) => {
      expect(valuesContainingSecret(state.storage.sql, result.secret)).toEqual(
        [],
      );
    });
  });

  it('does not log anything', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map(
      (method) => vi.spyOn(console, method).mockImplementation(() => {}),
    );
    await runInDurableObject(hub, async (_instance, state) => {
      await createPairing(state.storage, identity, 'all', NOW);
      await createPairing(state.storage, identity, ['ping'], NOW);
      await createPairing(state.storage, randomKey().pubkey, 'all', NOW);
    });
    for (const log of logs) {
      expect(log).not.toHaveBeenCalled();
    }
  });

  it('removes expired pairings lazily', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const other = await addIdentity(hub);
    const create = async (pubkey: string, now: number) => {
      const result = await hub.createPairing(pubkey, 'all', now);
      if (result.status !== 'created') {
        throw new Error(result.status);
      }
      return result.pairing.id;
    };
    await create(identity, NOW - 601);
    await create(other, NOW - 600);
    const lastSecond = await create(other, NOW - 599);
    const current = await create(identity, NOW);

    const rows = await runInDurableObject(hub, (_instance, state) =>
      pairingRows(state.storage.sql),
    );
    expect(rows.map(({ id }) => id)).toEqual([lastSecond, current]);
  });

  it('reports full storage without storing anything', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    await runInDurableObject(hub, async (_instance, state) => {
      const storage = instrumentedStorage(state.storage, {
        failing: /INSERT INTO pairings/,
        message: SQLITE_FULL_MESSAGE,
      });
      expect(await createPairing(storage, identity, 'all', NOW)).toEqual({
        status: 'storage_full',
      });
      expect(pairingRows(state.storage.sql)).toEqual([]);
    });
  });

  it('rethrows other failures without storing anything', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    await runInDurableObject(hub, async (_instance, state) => {
      const storage = instrumentedStorage(state.storage, {
        failing: /INSERT INTO pairings/,
        message: 'unexpected',
      });
      await expect(
        createPairing(storage, identity, 'all', NOW),
      ).rejects.toThrow('unexpected');
      expect(pairingRows(state.storage.sql)).toEqual([]);
    });
  });
});

describe('findPairing and deletePairing', () => {
  it('look up a pairing by secret hash, expired or not, and delete it', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const result = await hub.createPairing(identity, ['sign_event:1'], NOW);
    if (result.status !== 'created') {
      throw new Error(result.status);
    }
    const secretHash = await hashPairingSecret(result.secret);

    await runInDurableObject(hub, (_instance, state) => {
      const { sql } = state.storage;
      expect(findPairing(sql, secretHash)).toEqual(result.pairing);
      expect(findPairing(sql, new Uint8Array(32))).toBeNull();
      expect(deletePairing(sql, result.pairing.id)).toBe(true);
      expect(deletePairing(sql, result.pairing.id)).toBe(false);
      expect(findPairing(sql, secretHash)).toBeNull();
    });
  });

  it('refuses a pairing whose stored permissions were altered', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const result = await hub.createPairing(identity, ['sign_event:1'], NOW);
    if (result.status !== 'created') {
      throw new Error(result.status);
    }
    const secretHash = await hashPairingSecret(result.secret);

    await runInDurableObject(hub, (_instance, state) => {
      const { sql } = state.storage;
      for (const permissions of ['["all"]', 'sign_event', '[]x']) {
        sql.exec('UPDATE pairings SET permissions = ?', permissions);
        expect(() => findPairing(sql, secretHash)).toThrow(
          MalformedPermissionsError,
        );
      }
    });
  });
});
