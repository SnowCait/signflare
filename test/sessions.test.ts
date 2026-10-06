import { evictDurableObject, runInDurableObject } from 'cloudflare:test';
import { bytesToHex } from 'nostr-tools/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  generatePairingSecret,
  type PairingPermissionsInput,
} from '../src/pairings';
import { MalformedPermissionsError } from '../src/permissions';
import {
  establishSession,
  type EstablishSessionResult,
  getSession,
  listSessions,
  type SessionRequest,
  touchSession,
} from '../src/sessions';
import type { SignerHub } from '../src/signer-hub';
import { StorageFullError } from '../src/storage-errors';
import {
  addIdentity,
  freshHub,
  instrumentedStorage,
  SQLITE_FULL_MESSAGE,
  valuesContainingSecret,
} from './hub-helpers';
import { randomKey } from './nostr-helpers';

type Hub = DurableObjectStub<SignerHub>;

const NOW = 1_700_000_000;
const NO_METADATA = { name: null, url: null, image: null };

type SessionRow = {
  client_pubkey: string;
  identity_pubkey: string;
  permissions: string;
  client_name: string | null;
  client_url: string | null;
  client_image: string | null;
  created_at: number;
  last_used_at: number;
};

interface Paired {
  readonly hub: Hub;
  readonly identity: string;
  readonly secret: string;
}

async function pair(
  hub: Hub,
  identity: string,
  permissions: PairingPermissionsInput = 'all',
  now = NOW,
): Promise<string> {
  const result = await hub.createPairing(identity, permissions, now);
  if (result.status !== 'created') {
    throw new Error(`pairing not created: ${result.status}`);
  }
  return result.secret;
}

async function paired(
  permissions: PairingPermissionsInput = 'all',
): Promise<Paired> {
  const hub = freshHub();
  const identity = await addIdentity(hub);
  return { hub, identity, secret: await pair(hub, identity, permissions) };
}

function connect(
  hub: Hub,
  secret: string,
  overrides: Partial<SessionRequest> = {},
): Promise<EstablishSessionResult> {
  return hub.establishSession({
    secret,
    clientPubkey: randomKey().pubkey,
    now: NOW + 1,
    ...overrides,
  });
}

function rows(hub: Hub) {
  return runInDurableObject(hub, (_instance, state) => {
    const { sql } = state.storage;
    return {
      sessions: sql
        .exec<SessionRow>('SELECT * FROM sessions ORDER BY created_at')
        .toArray(),
      pairings: sql
        .exec<{
          id: string;
          identity_pubkey: string;
        }>('SELECT id, identity_pubkey FROM pairings ORDER BY created_at')
        .toArray(),
    };
  });
}

function statuses(results: readonly EstablishSessionResult[]): string[] {
  return results.map(({ status }) => status).sort();
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('establishSession', () => {
  it('creates a persistent session with the pairing permissions', async () => {
    const { hub, identity, secret } = await paired([
      'sign_event:1',
      'nip44_encrypt',
    ]);
    const clientPubkey = randomKey().pubkey;

    const result = await connect(hub, secret, { clientPubkey, now: NOW + 5 });

    const session = {
      clientPubkey,
      identityPubkey: identity,
      permissions: ['sign_event:1', 'nip44_encrypt'],
      clientMetadata: NO_METADATA,
      createdAt: NOW + 5,
      lastUsedAt: NOW + 5,
    };
    expect(result).toEqual({ status: 'created', session });
    expect(await hub.getSession(clientPubkey)).toEqual(session);
    // Persistent: the session survives the object being evicted.
    await evictDurableObject(hub);
    expect(await hub.getSession(clientPubkey)).toEqual(session);
    expect(await rows(hub)).toEqual({
      sessions: [
        {
          client_pubkey: clientPubkey,
          identity_pubkey: identity,
          permissions: '["sign_event:1","nip44_encrypt"]',
          client_name: null,
          client_url: null,
          client_image: null,
          created_at: NOW + 5,
          last_used_at: NOW + 5,
        },
      ],
      pairings: [],
    });
  });

  it('gives omitted and empty permission requests the pairing permissions', async () => {
    for (const requestedPermissions of [undefined, '']) {
      const { hub, secret } = await paired(['sign_event', 'nip04_decrypt']);
      // Clients send an empty request when they pass metadata after it.
      const result = await connect(hub, secret, {
        requestedPermissions,
        clientMetadata: { name: 'Client' },
      });
      expect(result).toMatchObject({
        status: 'created',
        session: { permissions: ['sign_event', 'nip04_decrypt'] },
      });
    }
  });

  it.each<[string, PairingPermissionsInput, string, string[]]>([
    [
      'a kind under the wildcard',
      ['sign_event'],
      'sign_event:1',
      ['sign_event:1'],
    ],
    [
      'the wildcard over a kind',
      ['sign_event:1'],
      'sign_event',
      ['sign_event:1'],
    ],
    [
      'the wildcard on both sides',
      ['sign_event'],
      'sign_event',
      ['sign_event'],
    ],
    [
      'overlapping kinds',
      ['sign_event:1', 'sign_event:7'],
      'sign_event:7,sign_event:42',
      ['sign_event:7'],
    ],
    [
      'exact methods only',
      ['nip04_encrypt', 'nip44_encrypt', 'nip44_decrypt'],
      'nip44_encrypt,nip04_decrypt',
      ['nip44_encrypt'],
    ],
    [
      'the NIP-46 example against all',
      'all',
      'nip44_encrypt,sign_event:4',
      ['sign_event:4', 'nip44_encrypt'],
    ],
    [
      'a request listing more than the pairing',
      ['sign_event:1', 'nip44_decrypt'],
      'sign_event,nip04_encrypt,nip04_decrypt,nip44_encrypt,nip44_decrypt',
      ['sign_event:1', 'nip44_decrypt'],
    ],
  ])(
    'grants the intersection for %s',
    async (_case, pairing, requestedPermissions, expected) => {
      const { hub, secret } = await paired(pairing);
      const clientPubkey = randomKey().pubkey;
      const result = await connect(hub, secret, {
        clientPubkey,
        requestedPermissions,
      });
      expect(result).toMatchObject({
        status: 'created',
        session: { permissions: expected },
      });
      expect(await hub.getSession(clientPubkey)).toMatchObject({
        permissions: expected,
      });
    },
  );

  it('creates a session even when nothing requested is granted', async () => {
    const { hub, secret } = await paired(['nip44_encrypt']);
    const result = await connect(hub, secret, {
      requestedPermissions: 'sign_event:1,nip04_encrypt',
    });
    expect(result).toMatchObject({
      status: 'created',
      session: { permissions: [] },
    });
    const { sessions, pairings } = await rows(hub);
    expect(sessions.map(({ permissions }) => permissions)).toEqual(['[]']);
    expect(pairings).toEqual([]);
  });

  it.each([
    ['all', 'all'],
    ['all within a list', 'sign_event,all'],
    ['whitespace', 'nip44_encrypt, sign_event:1'],
    ['a control method', 'get_public_key'],
    ['a kind out of range', 'sign_event:65536'],
    ['a trailing comma', 'sign_event,'],
  ])(
    'rejects a request for %s without consuming the pairing',
    async (_case, requestedPermissions) => {
      const { hub, secret } = await paired();
      expect(await connect(hub, secret, { requestedPermissions })).toEqual({
        status: 'invalid_permissions',
      });
      expect((await rows(hub)).sessions).toEqual([]);
      expect((await connect(hub, secret)).status).toBe('created');
    },
  );

  it('rejects a wrong secret', async () => {
    const { hub, secret } = await paired();
    const before = await rows(hub);
    expect(await connect(hub, generatePairingSecret())).toEqual({
      status: 'invalid_secret',
    });
    expect(await rows(hub)).toEqual(before);
    expect((await connect(hub, secret)).status).toBe('created');
  });

  it.each<[string, (secret: string) => unknown]>([
    ['an empty secret', () => ''],
    ['a missing secret', () => undefined],
    ['the secret in uppercase', (secret) => secret.toUpperCase()],
    ['the secret with whitespace', (secret) => ` ${secret}`],
    ['the secret with a trailing newline', (secret) => `${secret}\n`],
    ['an extended secret', (secret) => `${secret}00`],
    ['a truncated secret', (secret) => secret.slice(0, -1)],
    ['an oversized value', (secret) => secret.repeat(16_384)],
    ['a number', () => 42],
  ])('rejects %s without hashing it', async (_case, presented) => {
    const { hub, secret } = await paired();
    const digest = vi.spyOn(crypto.subtle, 'digest');
    expect(await connect(hub, presented(secret) as string)).toEqual({
      status: 'invalid_secret',
    });
    expect(digest).not.toHaveBeenCalled();
    expect((await rows(hub)).pairings).toHaveLength(1);
  });

  it('accepts a pairing until exactly 10 minutes after its creation', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const secret = await pair(hub, identity, 'all', NOW);
    expect((await connect(hub, secret, { now: NOW + 599 })).status).toBe(
      'created',
    );
  });

  it('rejects an expired pairing and removes it', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const secret = await pair(hub, identity, 'all', NOW);
    const later = await pair(hub, identity, 'all', NOW + 300);

    expect(await connect(hub, secret, { now: NOW + 600 })).toEqual({
      status: 'pairing_expired',
    });
    const { sessions, pairings } = await rows(hub);
    expect(sessions).toEqual([]);
    expect(pairings).toHaveLength(1);
    // Removed, so it is now indistinguishable from a wrong secret.
    expect(await connect(hub, secret, { now: NOW + 600 })).toEqual({
      status: 'invalid_secret',
    });
    expect((await connect(hub, later, { now: NOW + 600 })).status).toBe(
      'created',
    );
  });

  it('consumes the pairing so that its secret works only once', async () => {
    const { hub, secret } = await paired();
    const clientPubkey = randomKey().pubkey;
    expect((await connect(hub, secret, { clientPubkey })).status).toBe(
      'created',
    );

    expect(await connect(hub, secret)).toEqual({ status: 'invalid_secret' });
    expect(await connect(hub, secret, { clientPubkey })).toEqual({
      status: 'invalid_secret',
    });
    const { sessions, pairings } = await rows(hub);
    expect(sessions.map(({ client_pubkey }) => client_pubkey)).toEqual([
      clientPubkey,
    ]);
    expect(pairings).toEqual([]);
  });

  it('lets at most one concurrent attempt with the same secret succeed', async () => {
    const { hub, secret } = await paired();
    const results = await Promise.all(
      Array.from({ length: 8 }, () => connect(hub, secret)),
    );
    expect(statuses(results)).toEqual([
      'created',
      ...Array<string>(7).fill('invalid_secret'),
    ]);
    const [created] = results.flatMap((result) =>
      result.status === 'created' ? [result.session] : [],
    );
    const { sessions, pairings } = await rows(hub);
    expect(sessions.map(({ client_pubkey }) => client_pubkey)).toEqual([
      created.clientPubkey,
    ]);
    expect(pairings).toEqual([]);
  });

  it('lets one client establish only one session under concurrency', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const secrets = await Promise.all(
      Array.from({ length: 4 }, () => pair(hub, identity)),
    );
    const clientPubkey = randomKey().pubkey;
    const results = await Promise.all(
      secrets.map((secret) => connect(hub, secret, { clientPubkey })),
    );
    expect(statuses(results)).toEqual([
      'already_connected',
      'already_connected',
      'already_connected',
      'created',
    ]);
    const { sessions, pairings } = await rows(hub);
    expect(sessions).toHaveLength(1);
    // Only the redeemed pairing is consumed.
    expect(pairings).toHaveLength(3);
  });

  it('does not replace the session of an already connected client', async () => {
    const hub = freshHub();
    const first = await addIdentity(hub);
    const second = await addIdentity(hub);
    const clientPubkey = randomKey().pubkey;
    await connect(hub, await pair(hub, first, ['nip44_encrypt']), {
      clientPubkey,
      clientMetadata: { name: 'Original' },
    });
    const existing = await hub.getSession(clientPubkey);
    const secret = await pair(hub, second, 'all');

    expect(
      await connect(hub, secret, {
        clientPubkey,
        now: NOW + 60,
        clientMetadata: { name: 'Replacement' },
      }),
    ).toEqual({ status: 'already_connected' });
    expect(await hub.getSession(clientPubkey)).toEqual(existing);
    expect(existing).toMatchObject({
      identityPubkey: first,
      permissions: ['nip44_encrypt'],
      clientMetadata: { name: 'Original' },
    });

    // The pairing was not consumed, so another client can still use it.
    const other = randomKey().pubkey;
    expect(await connect(hub, secret, { clientPubkey: other })).toMatchObject({
      status: 'created',
      session: { identityPubkey: second },
    });
  });

  it('keeps the pairing when the session cannot be stored', async () => {
    const { hub, identity, secret } = await paired();
    const clientPubkey = randomKey().pubkey;
    await runInDurableObject(hub, async (_instance, state) => {
      const full = instrumentedStorage(state.storage, {
        failing: /INSERT INTO sessions/,
        message: SQLITE_FULL_MESSAGE,
      });
      const request = { secret, clientPubkey, now: NOW + 1 };
      expect(await establishSession(full, request)).toEqual({
        status: 'storage_full',
      });

      const broken = instrumentedStorage(state.storage, {
        failing: /INSERT INTO sessions/,
        message: 'unexpected',
      });
      await expect(establishSession(broken, request)).rejects.toThrow(
        'unexpected',
      );
    });

    const { sessions, pairings } = await rows(hub);
    expect(sessions).toEqual([]);
    expect(pairings).toEqual([
      { id: expect.any(String), identity_pubkey: identity },
    ]);
    expect((await connect(hub, secret, { clientPubkey })).status).toBe(
      'created',
    );
  });

  it('does not keep the session when consuming the pairing fails', async () => {
    const { hub, secret } = await paired();
    const clientPubkey = randomKey().pubkey;
    await runInDurableObject(hub, async (_instance, state) => {
      const storage = instrumentedStorage(state.storage, {
        failing: /DELETE FROM pairings/,
        message: 'unexpected',
      });
      await expect(
        establishSession(storage, { secret, clientPubkey, now: NOW + 1 }),
      ).rejects.toThrow('unexpected');
    });
    const { sessions, pairings } = await rows(hub);
    expect(sessions).toEqual([]);
    expect(pairings).toHaveLength(1);
    expect(await hub.getSession(clientPubkey)).toBeNull();
  });

  it('refuses a pairing whose stored permissions were altered', async () => {
    const { hub, secret } = await paired(['sign_event:1']);
    await runInDurableObject(hub, async (_instance, state) => {
      for (const permissions of [
        '["all"]',
        '["sign_event:1","sign_event:1"]',
        '',
      ]) {
        state.storage.sql.exec(
          'UPDATE pairings SET permissions = ?',
          permissions,
        );
        await expect(
          establishSession(state.storage, {
            secret,
            clientPubkey: randomKey().pubkey,
            now: NOW + 1,
          }),
        ).rejects.toThrow(MalformedPermissionsError);
      }
    });
    const { sessions, pairings } = await rows(hub);
    expect(sessions).toEqual([]);
    expect(pairings).toHaveLength(1);
  });

  it.each([
    ['uppercase hex', (pubkey: string) => pubkey.toUpperCase()],
    ['a short key', (pubkey: string) => pubkey.slice(2)],
    ['a long key', (pubkey: string) => `${pubkey}00`],
    ['surrounding whitespace', (pubkey: string) => ` ${pubkey}`],
    ['non-hex characters', () => 'zz'.repeat(32)],
    ['an empty string', () => ''],
  ])(
    'rejects a client pubkey with %s before touching the pairing',
    async (_case, malform) => {
      const { hub, secret } = await paired();
      await runInDurableObject(hub, async (_instance, state) => {
        await expect(
          establishSession(state.storage, {
            secret,
            clientPubkey: malform(randomKey().pubkey),
            now: NOW + 1,
          }),
        ).rejects.toThrow(
          new TypeError(
            'clientPubkey must be 64 lowercase hexadecimal characters',
          ),
        );
      });
      expect(await rows(hub)).toMatchObject({
        sessions: [],
        pairings: [expect.anything()],
      });
    },
  );

  it('never returns, stores, or logs the secret', async () => {
    const { hub, identity, secret } = await paired();
    const logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map(
      (method) => vi.spyOn(console, method).mockImplementation(() => {}),
    );
    const clientPubkey = randomKey().pubkey;
    const outputs = [
      await connect(hub, generatePairingSecret()),
      await connect(hub, secret, { requestedPermissions: 'all' }),
      await connect(hub, secret, { clientPubkey }),
      await connect(hub, secret),
      await hub.getSession(clientPubkey),
      await hub.listSessions(identity),
    ];
    expect(outputs[2]).toMatchObject({ status: 'created' });
    for (const output of outputs) {
      expect(JSON.stringify(output)).not.toContain(secret);
    }
    await runInDurableObject(hub, (_instance, state) => {
      expect(valuesContainingSecret(state.storage.sql, secret)).toEqual([]);
    });
    for (const log of logs) {
      expect(log).not.toHaveBeenCalled();
    }
  });

  it('keeps the secret out of errors', async () => {
    const { hub, secret } = await paired();
    await runInDurableObject(hub, async (_instance, state) => {
      state.storage.sql.exec('UPDATE pairings SET permissions = \'["all"]\'');
      const requests: SessionRequest[] = [
        { secret, clientPubkey: randomKey().pubkey, now: NOW + 1 },
        { secret, clientPubkey: 'not a pubkey', now: NOW + 1 },
        {
          secret,
          clientPubkey: randomKey().pubkey,
          clientMetadata: { name: 1 as unknown as string },
          now: NOW + 1,
        },
      ];
      for (const request of requests) {
        let caught: unknown;
        try {
          await establishSession(state.storage, request);
        } catch (error) {
          caught = error;
        }
        expect(caught).toBeInstanceOf(Error);
        const error = caught as Error;
        expect(error.cause).toBeUndefined();
        const text = `${String(error)} ${error.stack ?? ''} ${JSON.stringify(error)}`;
        expect(text).not.toContain(secret);
      }
    });
  });
});

describe('client metadata', () => {
  it('is stored with the session as given', async () => {
    const { hub, secret } = await paired();
    const clientPubkey = randomKey().pubkey;
    const clientMetadata = {
      name: 'Nostr Client',
      url: 'https://client.example',
      image: 'https://client.example/icon.png',
    };
    const result = await connect(hub, secret, { clientPubkey, clientMetadata });
    expect(result).toMatchObject({
      status: 'created',
      session: { clientMetadata },
    });
    expect(await hub.getSession(clientPubkey)).toMatchObject({
      clientMetadata,
    });
    expect((await rows(hub)).sessions[0]).toMatchObject({
      client_name: 'Nostr Client',
      client_url: 'https://client.example',
      client_image: 'https://client.example/icon.png',
    });
  });

  it.each<[string, SessionRequest['clientMetadata'], object]>([
    ['omitted', undefined, NO_METADATA],
    ['empty', {}, NO_METADATA],
    ['partial', { name: 'Client' }, { ...NO_METADATA, name: 'Client' }],
    ['null fields', { name: null, url: null, image: null }, NO_METADATA],
    [
      'empty strings',
      { name: '', url: '', image: '' },
      { name: '', url: '', image: '' },
    ],
  ])('is stored when %s', async (_case, clientMetadata, expected) => {
    const { hub, secret } = await paired();
    const clientPubkey = randomKey().pubkey;
    await connect(hub, secret, { clientPubkey, clientMetadata });
    expect(await hub.getSession(clientPubkey)).toMatchObject({
      clientMetadata: expected,
    });
  });

  it('does not affect identity selection or permissions', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const other = await addIdentity(hub);
    const plain = await connect(
      hub,
      await pair(hub, identity, ['sign_event:1']),
    );
    const decorated = await connect(
      hub,
      await pair(hub, identity, ['sign_event:1']),
      {
        clientMetadata: {
          name: 'all',
          identity: other,
          perms: 'all',
          permissions: ['sign_event'],
        } as SessionRequest['clientMetadata'],
      },
    );
    for (const result of [plain, decorated]) {
      expect(result).toMatchObject({
        status: 'created',
        session: { identityPubkey: identity, permissions: ['sign_event:1'] },
      });
    }
  });

  it('must be strings', async () => {
    const { hub, secret } = await paired();
    await runInDurableObject(hub, async (_instance, state) => {
      for (const clientMetadata of [
        { name: 42 },
        { url: { href: 'https://client.example' } },
        { image: ['https://client.example/icon.png'] },
      ] as unknown as SessionRequest['clientMetadata'][]) {
        await expect(
          establishSession(state.storage, {
            secret,
            clientPubkey: randomKey().pubkey,
            clientMetadata,
            now: NOW + 1,
          }),
        ).rejects.toThrow(
          new TypeError('Client metadata fields must be strings'),
        );
      }
    });
    expect((await rows(hub)).pairings).toHaveLength(1);
  });
});

describe('session operations', () => {
  async function connected(hub: Hub, identity: string, now = NOW + 1) {
    const result = await connect(hub, await pair(hub, identity), { now });
    if (result.status !== 'created') {
      throw new Error(result.status);
    }
    return result.session;
  }

  it('look up a session by client pubkey', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const session = await connected(hub, identity);
    expect(await hub.getSession(session.clientPubkey)).toEqual(session);
    expect(await hub.getSession(randomKey().pubkey)).toBeNull();
    expect(await hub.getSession(session.clientPubkey.toUpperCase())).toBeNull();
  });

  it('list the sessions of one identity, oldest first', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const other = await addIdentity(hub);
    const second = await connected(hub, identity, NOW + 20);
    const first = await connected(hub, identity, NOW + 10);
    await connected(hub, other, NOW + 15);

    expect(await hub.listSessions(identity)).toEqual([first, second]);
    expect(await hub.listSessions(randomKey().pubkey)).toEqual([]);
  });

  it('tell an identity without sessions from an unknown identity', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const other = await addIdentity(hub);
    expect(await hub.listIdentitySessions(identity)).toEqual({
      status: 'found',
      sessions: [],
    });
    const second = await connected(hub, identity, NOW + 20);
    const first = await connected(hub, identity, NOW + 10);
    await connected(hub, other, NOW + 15);

    expect(await hub.listIdentitySessions(identity)).toEqual({
      status: 'found',
      sessions: [first, second],
    });
    expect(await hub.listIdentitySessions(randomKey().pubkey)).toEqual({
      status: 'identity_not_found',
    });
    expect(await hub.listIdentitySessions(first.clientPubkey)).toEqual({
      status: 'identity_not_found',
    });
  });

  it('list only public session data', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const secret = await pair(hub, identity);
    await connect(hub, secret, { clientMetadata: { name: 'Client' } });

    const sessions = await hub.listSessions(identity);
    expect(sessions).toHaveLength(1);
    expect(Object.keys(sessions[0]).sort()).toEqual([
      'clientMetadata',
      'clientPubkey',
      'createdAt',
      'identityPubkey',
      'lastUsedAt',
      'permissions',
    ]);
    const encrypted = await runInDurableObject(hub, (_instance, state) =>
      state.storage.sql
        .exec<{
          encrypted_private_key: ArrayBuffer;
          iv: ArrayBuffer;
          kdf_salt: ArrayBuffer;
        }>('SELECT encrypted_private_key, iv, kdf_salt FROM identities')
        .one(),
    );
    const serialized = JSON.stringify(sessions);
    expect(serialized).not.toContain(secret);
    for (const value of Object.values(encrypted)) {
      expect(serialized).not.toContain(bytesToHex(new Uint8Array(value)));
    }
  });

  it('revoke a session immediately', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const session = await connected(hub, identity);
    const kept = await connected(hub, identity);

    expect(await hub.revokeSession(session.clientPubkey)).toBe(true);
    expect(await hub.getSession(session.clientPubkey)).toBeNull();
    expect(await hub.listSessions(identity)).toEqual([kept]);
    expect(await hub.revokeSession(session.clientPubkey)).toBe(false);
    expect(await hub.revokeSession(randomKey().pubkey)).toBe(false);
  });

  it('require a new pairing after revocation', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const secret = await pair(hub, identity, ['nip44_encrypt']);
    const clientPubkey = randomKey().pubkey;
    await connect(hub, secret, { clientPubkey });
    await hub.revokeSession(clientPubkey);

    expect(await connect(hub, secret, { clientPubkey })).toEqual({
      status: 'invalid_secret',
    });
    const renewed = await connect(
      hub,
      await pair(hub, identity, ['sign_event']),
      {
        clientPubkey,
        now: NOW + 100,
      },
    );
    expect(renewed).toMatchObject({
      status: 'created',
      session: { permissions: ['sign_event'], createdAt: NOW + 100 },
    });
  });

  it('record use by updating last_used_at only', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const session = await connected(hub, identity, NOW + 1);
    const other = await connected(hub, identity, NOW + 2);

    expect(await hub.touchSession(session.clientPubkey, NOW + 3600)).toBe(true);
    expect(await hub.getSession(session.clientPubkey)).toEqual({
      ...session,
      lastUsedAt: NOW + 3600,
    });
    expect(await hub.getSession(other.clientPubkey)).toEqual(other);
  });

  it('never move last_used_at backwards', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const session = await connected(hub, identity, NOW + 10);
    await hub.touchSession(session.clientPubkey, NOW + 100);
    expect(await hub.touchSession(session.clientPubkey, NOW + 50)).toBe(true);
    expect(await hub.getSession(session.clientPubkey)).toMatchObject({
      createdAt: NOW + 10,
      lastUsedAt: NOW + 100,
    });
  });

  it('report a missing session when recording use', async () => {
    const hub = freshHub();
    expect(await hub.touchSession(randomKey().pubkey, NOW)).toBe(false);
    const identity = await addIdentity(hub);
    const session = await connected(hub, identity);
    await hub.revokeSession(session.clientPubkey);
    expect(await hub.touchSession(session.clientPubkey, NOW + 5)).toBe(false);
    expect(await hub.getSession(session.clientPubkey)).toBeNull();
  });

  it('report full storage when recording use', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const session = await connected(hub, identity);
    await runInDurableObject(hub, (_instance, state) => {
      const full = instrumentedStorage(state.storage, {
        failing: /UPDATE sessions/,
        message: SQLITE_FULL_MESSAGE,
      });
      expect(() =>
        touchSession(full.sql, session.clientPubkey, NOW + 5),
      ).toThrow(StorageFullError);
    });
    expect(await hub.getSession(session.clientPubkey)).toEqual(session);
  });

  it('fail safely on altered stored permissions', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const session = await connected(hub, identity);
    await runInDurableObject(hub, (_instance, state) => {
      const { sql } = state.storage;
      for (const permissions of ['sign_event', '["all"]', '[]\n']) {
        sql.exec(
          'UPDATE sessions SET permissions = ? WHERE client_pubkey = ?',
          permissions,
          session.clientPubkey,
        );
        expect(() => getSession(sql, session.clientPubkey)).toThrow(
          MalformedPermissionsError,
        );
        expect(() => listSessions(sql, identity)).toThrow(
          MalformedPermissionsError,
        );
      }
    });
    // Revocation does not need to read them.
    expect(await hub.revokeSession(session.clientPubkey)).toBe(true);
  });
});
