import { evictDurableObject, runInDurableObject } from 'cloudflare:test';
import { npubEncode } from 'nostr-tools/nip19';
import { verifyEvent } from 'nostr-tools/pure';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { PairingPermissionsInput } from '../src/pairings';
import {
  instrumentHubSql,
  SQLITE_FULL_MESSAGE,
  valuesContainingSecret,
} from './hub-helpers';
import { randomKey, unixNow } from './nostr-helpers';
import {
  configureHub,
  connectedClient,
  createPairing,
  type Nip46Payload,
  openSocket,
  type Relay,
  registerIdentity,
  relayDeployment,
  subscribedClient,
  TestClient,
} from './relay-helpers';

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

function rows(relay: Relay) {
  return runInDurableObject(relay.hub, (_instance, state) => {
    const { sql } = state.storage;
    return {
      sessions: sql
        .exec<SessionRow>('SELECT * FROM sessions ORDER BY created_at')
        .toArray(),
      pairings: sql
        .exec<{ id: string }>('SELECT id FROM pairings')
        .toArray()
        .map(({ id }) => id),
    };
  });
}

async function session(
  relay: Relay,
  clientPubkey: string,
): Promise<SessionRow | undefined> {
  return (await rows(relay)).sessions.find(
    (row) => row.client_pubkey === clientPubkey,
  );
}

function error(error: string): Nip46Payload {
  return { id: expect.any(String), result: '', error };
}

const ACK: Nip46Payload = { id: expect.any(String), result: 'ack' };

// A deployment with one identity, a pairing for it, and a subscribed client.
async function paired(permissions: PairingPermissionsInput = 'all') {
  const relay = await relayDeployment();
  const identity = await registerIdentity(relay);
  const secret = await createPairing(relay, identity.pubkey, permissions);
  const client = await subscribedClient(relay);
  return { relay, identity, secret, client };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('connect', () => {
  it('establishes a session for the identity of the pairing', async () => {
    const { relay, identity, secret, client } = await paired([
      'sign_event:1',
      'nip44_encrypt',
    ]);
    const before = unixNow();
    expect(await client.connect(secret)).toEqual(ACK);

    const row = await session(relay, client.pubkey);
    expect(row).toEqual({
      client_pubkey: client.pubkey,
      identity_pubkey: identity.pubkey,
      permissions: '["sign_event:1","nip44_encrypt"]',
      client_name: null,
      client_url: null,
      client_image: null,
      created_at: expect.any(Number),
      last_used_at: expect.any(Number),
    });
    expect(row?.created_at).toBeGreaterThanOrEqual(before);
    expect(row?.last_used_at).toBe(row?.created_at);
    expect(await client.result('get_public_key')).toBe(identity.pubkey);
  });

  it('consumes the pairing together with creating the session', async () => {
    const { relay, secret, client } = await paired();
    const { pairings } = await rows(relay);
    expect(pairings).toHaveLength(1);
    expect(await client.connect(secret)).toEqual(ACK);
    expect(await rows(relay)).toMatchObject({
      sessions: [{ client_pubkey: client.pubkey }],
      pairings: [],
    });
  });

  it('keeps the pairing when the session cannot be stored', async () => {
    const { relay, secret, client } = await paired();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    await instrumentHubSql(relay.hub, {
      failing: /INSERT INTO sessions/,
      message: SQLITE_FULL_MESSAGE,
    });
    expect(await client.connect(secret)).toEqual(error('internal error'));
    expect(log.mock.calls).toEqual([
      ['NIP-46 connect failed: storage is full'],
    ]);
    expect((await rows(relay)).pairings).toHaveLength(1);

    vi.restoreAllMocks();
    expect(await client.connect(secret)).toEqual(ACK);
  });

  it('does not let a secret establish a second session', async () => {
    const { relay, secret, client } = await paired();
    expect(await client.connect(secret)).toEqual(ACK);
    const other = await subscribedClient(relay);
    expect(await other.connect(secret)).toEqual(error('invalid secret'));
    // Not even for the client that redeemed it.
    expect(await client.connect(secret)).toEqual(error('invalid secret'));
    expect((await rows(relay)).sessions).toHaveLength(1);
  });

  it('lets at most one of concurrent attempts with one secret succeed', async () => {
    const { relay, secret } = await paired();
    const clients = await Promise.all(
      Array.from({ length: 6 }, () => subscribedClient(relay)),
    );
    const results = await Promise.all(
      clients.map((client) => client.connect(secret)),
    );
    expect(
      results.map((result) => result.result || result.error).sort(),
    ).toEqual(['ack', ...Array<string>(5).fill('invalid secret')]);
    expect((await rows(relay)).sessions).toHaveLength(1);
  });

  it('rejects a remote-signer pubkey other than the deployment one', async () => {
    const { relay, identity, secret, client } = await paired();
    for (const remoteSigner of [
      randomKey().pubkey,
      identity.pubkey,
      relay.remoteSigner.pubkey.toUpperCase(),
      npubEncode(relay.remoteSigner.pubkey),
      '',
    ]) {
      expect(await client.call('connect', [remoteSigner, secret])).toEqual(
        error('invalid request'),
      );
    }
    expect(await rows(relay)).toMatchObject({
      sessions: [],
      pairings: [expect.any(String)],
    });
    expect(await client.connect(secret)).toEqual(ACK);
  });

  it.each<[string, (secret: string) => string[]]>([
    ['a wrong secret', () => ['ab'.repeat(32)]],
    ['an empty secret', () => ['']],
    ['no secret', () => []],
    ['the secret in uppercase', (secret) => [secret.toUpperCase()]],
    ['a truncated secret', (secret) => [secret.slice(0, -1)]],
    ['the secret with whitespace', (secret) => [` ${secret}`]],
  ])('rejects %s', async (_case, secret) => {
    const { relay, secret: valid, client } = await paired();
    const remoteSigner = relay.remoteSigner.pubkey;
    expect(
      await client.call('connect', [remoteSigner, ...secret(valid)]),
    ).toEqual(error('invalid secret'));
    expect((await rows(relay)).pairings).toHaveLength(1);
    expect(await client.connect(valid)).toEqual(ACK);
  });

  it('rejects an expired pairing and removes it', async () => {
    const relay = await relayDeployment();
    const identity = await registerIdentity(relay);
    const expired = await createPairing(
      relay,
      identity.pubkey,
      'all',
      unixNow() - 601,
    );
    const client = await subscribedClient(relay);
    expect(await client.connect(expired)).toEqual(error('pairing expired'));
    expect(await rows(relay)).toEqual({ sessions: [], pairings: [] });
    expect(await client.connect(expired)).toEqual(error('invalid secret'));
  });

  it('rejects a client that is already connected and leaves both alone', async () => {
    const { relay, identity, secret, client } = await paired(['nip44_encrypt']);
    expect(await client.connect(secret, '', '{"name":"Original"}')).toEqual(
      ACK,
    );
    const other = await registerIdentity(relay);
    const another = await createPairing(relay, other.pubkey, 'all');
    await runInDurableObject(relay.hub, (_instance, state) => {
      state.storage.sql.exec('UPDATE sessions SET last_used_at = 1');
    });
    const before = await session(relay, client.pubkey);

    expect(await client.connect(another, '', '{"name":"Replacement"}')).toEqual(
      error('already connected'),
    );
    expect(await session(relay, client.pubkey)).toEqual(before);
    expect(before).toMatchObject({
      identity_pubkey: identity.pubkey,
      permissions: '["nip44_encrypt"]',
      client_name: 'Original',
      last_used_at: 1,
    });
    // The other pairing was not consumed.
    expect((await rows(relay)).pairings).toHaveLength(1);
    const newcomer = await subscribedClient(relay);
    expect(await newcomer.connect(another)).toEqual(ACK);
  });

  it.each<[string, PairingPermissionsInput, string, string]>([
    [
      'the pairing permissions when none are requested',
      ['sign_event', 'nip04_decrypt'],
      '',
      '["sign_event","nip04_decrypt"]',
    ],
    [
      'a requested subset',
      'all',
      'nip44_encrypt,sign_event:4',
      '["sign_event:4","nip44_encrypt"]',
    ],
    [
      'a kind under the sign_event wildcard',
      ['sign_event'],
      'sign_event:1',
      '["sign_event:1"]',
    ],
    [
      'the granted kind of a requested wildcard',
      ['sign_event:1'],
      'sign_event',
      '["sign_event:1"]',
    ],
    [
      'only what both allow',
      ['sign_event:1', 'nip44_decrypt'],
      'sign_event,nip04_encrypt,nip44_decrypt',
      '["sign_event:1","nip44_decrypt"]',
    ],
    [
      'nothing when nothing requested is granted',
      ['nip44_encrypt'],
      'sign_event:1,nip04_encrypt',
      '[]',
    ],
  ])('grants %s', async (_case, pairing, requested, expected) => {
    const { relay, secret, client } = await paired(pairing);
    expect(await client.connect(secret, requested)).toEqual(ACK);
    expect(await session(relay, client.pubkey)).toMatchObject({
      permissions: expected,
    });
  });

  it.each([
    ['all', 'all'],
    ['a control method', 'get_public_key'],
    ['an unknown method', 'sign_event,create_account'],
    ['a kind out of range', 'sign_event:65536'],
    ['whitespace', 'sign_event, nip44_encrypt'],
  ])(
    'rejects requested permissions with %s and keeps the pairing',
    async (_case, requested) => {
      const { relay, secret, client } = await paired();
      expect(await client.connect(secret, requested)).toEqual(
        error('invalid request'),
      );
      expect(await rows(relay)).toMatchObject({
        sessions: [],
        pairings: [expect.any(String)],
      });
      expect(await client.connect(secret)).toEqual(ACK);
    },
  );

  it('stores the client metadata as display hints', async () => {
    const { relay, secret, client } = await paired(['sign_event:1']);
    const metadata = {
      name: 'Nostr Client',
      url: 'https://client.example',
      image: 'https://client.example/icon.png',
      extra: 'ignored',
    };
    expect(await client.connect(secret, '', JSON.stringify(metadata))).toEqual(
      ACK,
    );
    expect(await session(relay, client.pubkey)).toMatchObject({
      client_name: 'Nostr Client',
      client_url: 'https://client.example',
      client_image: 'https://client.example/icon.png',
      permissions: '["sign_event:1"]',
    });
  });

  it.each<[string, string, Partial<SessionRow>]>([
    [
      'partial metadata',
      '{"name":"Client"}',
      { client_name: 'Client', client_url: null, client_image: null },
    ],
    [
      'empty metadata',
      '{}',
      { client_name: null, client_url: null, client_image: null },
    ],
    [
      'an empty string',
      '',
      { client_name: null, client_url: null, client_image: null },
    ],
    [
      'null fields',
      '{"name":null,"url":null,"image":null}',
      { client_name: null, client_url: null, client_image: null },
    ],
    [
      'empty strings',
      '{"name":"","url":"","image":""}',
      { client_name: '', client_url: '', client_image: '' },
    ],
  ])('accepts %s', async (_case, metadata, expected) => {
    const { relay, secret, client } = await paired();
    expect(await client.connect(secret, '', metadata)).toEqual(ACK);
    expect(await session(relay, client.pubkey)).toMatchObject(expected);
  });

  it.each([
    ['not JSON', 'Nostr Client'],
    ['a JSON list', '["Nostr Client"]'],
    ['a JSON string', '"Nostr Client"'],
    ['JSON null', 'null'],
    ['a numeric name', '{"name":1}'],
    ['an object url', '{"url":{"href":"https://client.example"}}'],
    ['a list image', '{"image":["https://client.example/icon.png"]}'],
  ])(
    'rejects client metadata that is %s and keeps the pairing',
    async (_case, metadata) => {
      const { relay, secret, client } = await paired();
      expect(await client.connect(secret, '', metadata)).toEqual(
        error('invalid request'),
      );
      expect(await rows(relay)).toMatchObject({
        sessions: [],
        pairings: [expect.any(String)],
      });
    },
  );

  it('does not let client metadata affect authorization', async () => {
    const { relay, identity, secret, client } = await paired(['sign_event:1']);
    const other = await registerIdentity(relay);
    const metadata = JSON.stringify({
      name: 'all',
      perms: 'all',
      permissions: ['sign_event'],
      identity: other.pubkey,
      pubkey: other.pubkey,
    });
    expect(await client.connect(secret, '', metadata)).toEqual(ACK);
    expect(await session(relay, client.pubkey)).toMatchObject({
      identity_pubkey: identity.pubkey,
      permissions: '["sign_event:1"]',
    });
  });

  it.each<[string, (relay: Relay, secret: string) => string[]]>([
    ['no params', () => []],
    [
      'too many params',
      (relay, secret) => [relay.remoteSigner.pubkey, secret, '', '{}', ''],
    ],
  ])('rejects %s', async (_case, params) => {
    const { relay, secret, client } = await paired();
    expect(await client.call('connect', params(relay, secret))).toEqual(
      error('invalid request'),
    );
    expect((await rows(relay)).pairings).toHaveLength(1);
  });

  it('answers with ack and never returns or stores the secret', async () => {
    const { relay, secret, client } = await paired();
    const logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map(
      (method) => vi.spyOn(console, method).mockImplementation(() => {}),
    );
    const request = client.request('connect', [
      relay.remoteSigner.pubkey,
      secret,
    ]);
    const { event, payload } = await client.send(request);
    expect(payload).toEqual({ id: expect.any(String), result: 'ack' });
    expect(verifyEvent(event)).toBe(true);
    expect(JSON.stringify(event)).not.toContain(secret);
    expect(JSON.stringify(payload)).not.toContain(secret);
    await runInDurableObject(relay.hub, (_instance, state) => {
      expect(valuesContainingSecret(state.storage.sql, secret)).toEqual([]);
    });
    for (const log of logs) {
      expect(log).not.toHaveBeenCalled();
    }
  });
});

describe('session authorization', () => {
  const METHODS: [string, (client: TestClient) => unknown[]][] = [
    ['ping', () => []],
    ['get_public_key', () => []],
    ['switch_relays', () => []],
    ['logout', () => []],
    [
      'sign_event',
      () => [JSON.stringify({ kind: 1, content: '', tags: [], created_at: 1 })],
    ],
    ['nip04_encrypt', () => [randomKey().pubkey, 'text']],
    ['nip04_decrypt', () => [randomKey().pubkey, 'text?iv=text']],
    ['nip44_encrypt', () => [randomKey().pubkey, 'text']],
    ['nip44_decrypt', () => [randomKey().pubkey, 'text']],
  ];

  it.each(METHODS)('requires a session for %s', async (method, params) => {
    const relay = await relayDeployment();
    const client = await subscribedClient(relay);
    expect(await client.call(method, params(client))).toEqual(
      error('not connected'),
    );
  });

  it.each(METHODS)(
    'ends for %s once the session is revoked',
    async (method, params) => {
      const relay = await relayDeployment();
      const { client } = await connectedClient(relay);
      expect(await relay.hub.revokeSession(client.pubkey)).toBe(true);
      expect(await client.call(method, params(client))).toEqual(
        error('not connected'),
      );
    },
  );

  it.each(METHODS)(
    'ends for %s once the identity is deleted',
    async (method, params) => {
      const relay = await relayDeployment();
      const { client, identity } = await connectedClient(relay);
      expect(await relay.hub.deleteIdentity(identity.pubkey)).toBe(true);
      expect(await client.call(method, params(client))).toEqual(
        error('not connected'),
      );
    },
  );

  it('comes from the client keypair, not from the WebSocket', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    // Another client keypair on the same connection is not authorized.
    const stranger = new TestClient(relay, client.socket);
    await stranger.subscribe('stranger');
    expect(await stranger.call('get_public_key')).toEqual(
      error('not connected'),
    );
    await runInDurableObject(relay.hub, (_instance, state) => {
      for (const ws of state.getWebSockets()) {
        // The attachment holds subscriptions only.
        expect(Object.keys(ws.deserializeAttachment())).toEqual([
          'subscriptions',
        ]);
      }
    });
  });

  it('survives a WebSocket reconnect without a new pairing or connect', async () => {
    const relay = await relayDeployment();
    const { client, identity } = await connectedClient(relay);
    await client.socket.close();

    const reconnected = new TestClient(
      relay,
      await openSocket(relay),
      client.key,
    );
    await reconnected.subscribe();
    expect(await reconnected.result('ping')).toBe('pong');
    expect(await reconnected.result('get_public_key')).toBe(identity.pubkey);
    const signed = JSON.parse(
      await reconnected.result('sign_event', [
        JSON.stringify({
          kind: 1,
          content: 'after reconnect',
          tags: [],
          created_at: unixNow(),
        }),
      ]),
    );
    expect(signed.pubkey).toBe(identity.pubkey);
    expect(verifyEvent(signed)).toBe(true);
    expect((await rows(relay)).sessions).toHaveLength(1);
  });

  it('survives the SignerHub restarting', async () => {
    const relay = await relayDeployment();
    const { client, identity } = await connectedClient(relay);
    await client.socket.close();
    await evictDurableObject(relay.hub);
    await configureHub(relay);

    const reconnected = new TestClient(
      relay,
      await openSocket(relay),
      client.key,
    );
    await reconnected.subscribe();
    expect(await reconnected.result('get_public_key')).toBe(identity.pubkey);
  });
});

describe('logout', () => {
  it('acknowledges first and removes the session afterwards', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const order: string[] = [];
    await instrumentHubSql(relay.hub, { statements: order });
    const send = WebSocket.prototype.send;
    vi.spyOn(WebSocket.prototype, 'send').mockImplementation(function (
      this: WebSocket,
      message,
    ) {
      if (typeof message === 'string' && message.startsWith('["EVENT","')) {
        order.push('response delivered');
      }
      send.call(this, message);
    });

    expect(await client.call('logout')).toEqual({
      id: expect.any(String),
      result: 'ack',
    });
    const delivered = order.indexOf('response delivered');
    const removed = order.findIndex((statement) =>
      statement.startsWith('DELETE FROM sessions'),
    );
    expect(delivered).toBeGreaterThanOrEqual(0);
    expect(removed).toBeGreaterThan(delivered);
    // logout is not a use of the session.
    expect(
      order.some((statement) => statement.startsWith('UPDATE sessions')),
    ).toBe(false);
    expect(await session(relay, client.pubkey)).toBeUndefined();
  });

  it('removes the session even when nobody receives the acknowledgement', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    client.socket.send(['CLOSE', 'nip46']);
    const request = client.request('logout', []);
    client.socket.send(['EVENT', request]);
    expect(await client.socket.next()).toEqual(['OK', request.id, true, '']);
    expect(await client.socket.drain()).toEqual([]);
    expect(await session(relay, client.pubkey)).toBeUndefined();
  });

  it('leaves the client unauthorized until a new pairing connects it', async () => {
    const { relay, identity, secret, client } = await paired();
    expect(await client.connect(secret)).toEqual(ACK);
    expect(await client.result('logout')).toBe('ack');

    expect(await client.call('ping')).toEqual(error('not connected'));
    expect(await client.call('logout')).toEqual(error('not connected'));
    // The old pairing is gone for good.
    expect(await client.connect(secret)).toEqual(error('invalid secret'));

    const renewed = await createPairing(relay, identity.pubkey, [
      'nip44_encrypt',
    ]);
    expect(await client.connect(renewed)).toEqual(ACK);
    expect(await client.result('ping')).toBe('pong');
    expect(await session(relay, client.pubkey)).toMatchObject({
      permissions: '["nip44_encrypt"]',
    });
  });

  it('removes only the session of the client', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const { client: other } = await connectedClient(relay);
    expect(await client.result('logout')).toBe('ack');
    expect(await other.result('ping')).toBe('pong');
    expect(
      (await rows(relay)).sessions.map(({ client_pubkey }) => client_pubkey),
    ).toEqual([other.pubkey]);
  });
});
