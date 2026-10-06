import { NostrConnect, ShortTextNote } from 'nostr-tools/kinds';
import { nsecEncode } from 'nostr-tools/nip19';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent, type NostrEvent } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MAX_PARAM_LENGTH } from '../src/nip46';
import { recordingReads, replaceHubEnv } from './hub-helpers';
import { randomKey, tamperHex, unixNow } from './nostr-helpers';
import {
  configureHub,
  connectedClient,
  type Relay,
  relayDeployment,
  subscribedClient,
  type TestClient,
} from './relay-helpers';

// The real implementations, observed: nothing may be decrypted before the
// outer event has been validated (docs/design.md §18).
vi.mock('nostr-tools/nip44', { spy: true });

function captureLogs() {
  return (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
    vi.spyOn(console, method).mockImplementation(() => {}),
  );
}

// Records the SignerHub's reads of its secrets from now on.
async function recordSecretReads(relay: Relay): Promise<string[]> {
  const reads: string[] = [];
  await replaceHubEnv(relay.hub, (hubEnv) =>
    recordingReads(
      hubEnv,
      ['REMOTE_SIGNER_PRIVATE_KEY', 'MASTER_ENCRYPTION_KEY'],
      reads,
    ),
  );
  return reads;
}

// Sends `event`, which the relay must refuse with `reason`, and checks that
// nothing else happened.
async function expectRefused(
  client: TestClient,
  event: NostrEvent,
  reason: string,
): Promise<void> {
  client.socket.send(['EVENT', event]);
  expect(await client.socket.next()).toEqual(['OK', event.id, false, reason]);
  expect(await client.socket.drain()).toEqual([]);
}

function clearNip44Calls(): void {
  vi.mocked(nip44.getConversationKey).mockClear();
  vi.mocked(nip44.decrypt).mockClear();
}

function expectNothingDecrypted(): void {
  expect(nip44.getConversationKey).not.toHaveBeenCalled();
  expect(nip44.decrypt).not.toHaveBeenCalled();
}

function without(event: NostrEvent, field: keyof NostrEvent): unknown {
  const copy: Partial<NostrEvent> = { ...event };
  delete copy[field];
  return copy;
}

function resign(
  event: NostrEvent,
  overrides: Partial<NostrEvent>,
  key: Uint8Array,
): NostrEvent {
  const { kind, created_at, tags, content } = { ...event, ...overrides };
  return JSON.parse(
    JSON.stringify(finalizeEvent({ kind, created_at, tags, content }, key)),
  );
}

beforeEach(() => {
  clearNip44Calls();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('EVENT', () => {
  it('is accepted and answered when it is a valid NIP-46 request', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const request = client.request('ping', [], 'ping-1');
    client.socket.send(['EVENT', request]);
    expect(await client.socket.next()).toEqual(['OK', request.id, true, '']);
    const [type, subscriptionId, response] = (await client.socket.next()) as [
      string,
      string,
      NostrEvent,
    ];
    expect([type, subscriptionId]).toEqual(['EVENT', 'nip46']);
    expect(client.open(response)).toEqual({ id: 'ping-1', result: 'pong' });
  });

  it.each<[string, unknown]>([
    ['a string', 'event'],
    ['a number', 24133],
    ['null', null],
    ['a list', []],
    ['an object without id', { kind: NostrConnect }],
    ['an object with an uppercase id', { id: 'AB'.repeat(32) }],
    ['an object with a short id', { id: 'ab'.repeat(31) }],
  ])(
    'without a usable id is refused with a NOTICE: %s',
    async (_case, event) => {
      const relay = await relayDeployment();
      const client = await subscribedClient(relay);
      const reads = await recordSecretReads(relay);
      client.socket.send(['EVENT', event]);
      expect(await client.socket.next()).toEqual([
        'NOTICE',
        'invalid: malformed event',
      ]);
      expect(await client.socket.drain()).toEqual([]);
      expect(reads).toEqual([]);
      expectNothingDecrypted();
    },
  );

  it.each<[string, (event: NostrEvent) => unknown]>([
    ['no pubkey', (event) => without(event, 'pubkey')],
    [
      'an uppercase pubkey',
      (event) => ({ ...event, pubkey: event.pubkey.toUpperCase() }),
    ],
    ['no sig', (event) => without(event, 'sig')],
    ['a short sig', (event) => ({ ...event, sig: event.sig.slice(2) })],
    ['a kind as a string', (event) => ({ ...event, kind: '24133' })],
    ['a fractional kind', (event) => ({ ...event, kind: 24133.5 })],
    ['a fractional created_at', (event) => ({ ...event, created_at: 1.5 })],
    ['a created_at as a string', (event) => ({ ...event, created_at: '1' })],
    ['no content', (event) => without(event, 'content')],
    ['content as an object', (event) => ({ ...event, content: {} })],
    ['tags as an object', (event) => ({ ...event, tags: {} })],
    ['a tag that is not a list', (event) => ({ ...event, tags: ['p'] })],
    ['a tag with a number', (event) => ({ ...event, tags: [['p', 1]] })],
  ])('with a usable id is refused when it has %s', async (_case, malform) => {
    const relay = await relayDeployment();
    const client = await subscribedClient(relay);
    const event = malform(client.request('ping', [])) as NostrEvent;
    const reads = await recordSecretReads(relay);
    clearNip44Calls();
    await expectRefused(client, event, 'invalid: malformed event');
    expect(reads).toEqual([]);
    expectNothingDecrypted();
  });

  it('is refused unless it is kind 24133', async () => {
    const relay = await relayDeployment();
    const client = await subscribedClient(relay);
    const request = client.request('ping', []);
    for (const kind of [ShortTextNote, NostrConnect - 1, 24134, 65_535]) {
      const event = resign(request, { kind }, client.key.secretKey);
      const reads = await recordSecretReads(relay);
      clearNip44Calls();
      await expectRefused(
        client,
        event,
        'restricted: only kind 24133 is accepted',
      );
      expect(reads).toEqual([]);
      expectNothingDecrypted();
    }
  });

  it.each<[string, (event: NostrEvent, client: TestClient) => NostrEvent]>([
    ['a tampered id', (event) => ({ ...event, id: tamperHex(event.id) })],
    [
      'a tampered signature',
      (event) => ({ ...event, sig: tamperHex(event.sig, 70) }),
    ],
    [
      'the signature of another event',
      (event, client) => ({
        ...event,
        sig: client.request('ping', []).sig,
      }),
    ],
    [
      'tampered content',
      (event) => ({ ...event, content: `${event.content.slice(0, -4)}AAA=` }),
    ],
    [
      'a tampered created_at',
      (event) => ({ ...event, created_at: event.created_at + 1 }),
    ],
    [
      'tampered tags',
      (event, client) => ({
        ...event,
        tags: [
          ['p', client.relay.remoteSigner.pubkey],
          ['t', 'x'],
        ],
      }),
    ],
    ['another pubkey', (event) => ({ ...event, pubkey: randomKey().pubkey })],
  ])(
    'is refused, before anything is decrypted, with %s',
    async (_case, tamper) => {
      const relay = await relayDeployment();
      const { client } = await connectedClient(relay);
      // The content is a valid request: only the outer event is wrong.
      const event = tamper(client.request('ping', []), client);
      const reads = await recordSecretReads(relay);
      clearNip44Calls();
      await expectRefused(client, event, 'invalid: bad event id or signature');
      expect(reads).toEqual([]);
      expectNothingDecrypted();
    },
  );

  it.each<[string, (relay: Relay, client: TestClient) => string[][]]>([
    ['no p tag', () => []],
    ['only other tags', () => [['e', 'ab'.repeat(32)]]],
    ['a p tag for another pubkey', () => [['p', randomKey().pubkey]]],
    ['a p tag for the client', (_relay, client) => [['p', client.pubkey]]],
    ['a p tag without a value', () => [['p']]],
    [
      'an uppercase p tag value',
      (relay) => [['p', relay.remoteSigner.pubkey.toUpperCase()]],
    ],
    ['a P tag', (relay) => [['P', relay.remoteSigner.pubkey]]],
    [
      'a second p tag',
      (relay) => [
        ['p', relay.remoteSigner.pubkey],
        ['p', randomKey().pubkey],
      ],
    ],
    [
      'the p tag twice',
      (relay) => [
        ['p', relay.remoteSigner.pubkey],
        ['p', relay.remoteSigner.pubkey],
      ],
    ],
  ])('is refused without decrypting it when it has %s', async (_case, tags) => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const event = resign(
      client.request('ping', []),
      { tags: tags(relay, client) },
      client.key.secretKey,
    );
    clearNip44Calls();
    await expectRefused(
      client,
      event,
      'restricted: not addressed to this remote signer',
    );
    expectNothingDecrypted();
  });

  it('accepts a p tag with a relay hint and other tags besides', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const event = resign(
      client.request('ping', [], 'hinted'),
      {
        tags: [
          ['client', 'test'],
          ['p', relay.remoteSigner.pubkey, 'wss://signflare.example/'],
        ],
      },
      client.key.secretKey,
    );
    expect((await client.send(event)).payload).toEqual({
      id: 'hinted',
      result: 'pong',
    });
  });

  it('is decrypted with the conversation key of the remote signer and its author', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const event = client.request('ping', []);
    clearNip44Calls();
    await client.send(event);
    // The SignerHub decrypted the request with the conversation key of the
    // remote signer and the event author; the client then the response.
    expect(vi.mocked(nip44.decrypt).mock.calls[0][0]).toBe(event.content);
    expect(vi.mocked(nip44.getConversationKey).mock.calls[0][1]).toBe(
      client.pubkey,
    );
  });

  it.each<[string, (client: TestClient) => string]>([
    ['not base64', () => 'not a NIP-44 payload!'],
    ['empty', () => ''],
    ['of a future version', () => `#${'A'.repeat(200)}`],
    ['too short', (client) => client.encrypt('{}').slice(0, 100)],
    [
      'of version 1',
      (client) => {
        const bytes = Uint8Array.from(atob(client.encrypt('{}')), (c) =>
          c.charCodeAt(0),
        );
        bytes[0] = 1;
        return btoa(String.fromCharCode(...bytes));
      },
    ],
    [
      'with a tampered MAC',
      (client) => {
        const payload = client.encrypt(
          '{"id":"1","method":"ping","params":[]}',
        );
        return `${payload.slice(0, -8)}AAAAAAA=`;
      },
    ],
    [
      'encrypted to another pubkey',
      (client) =>
        nip44.encrypt(
          '{"id":"1","method":"ping","params":[]}',
          nip44.getConversationKey(client.key.secretKey, randomKey().pubkey),
        ),
    ],
    [
      'from another key',
      () =>
        nip44.encrypt(
          '{"id":"1","method":"ping","params":[]}',
          nip44.getConversationKey(randomKey().secretKey, randomKey().pubkey),
        ),
    ],
  ])('is refused when its content is %s', async (_case, content) => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const logs = captureLogs();
    await expectRefused(
      client,
      client.rawRequest(content(client)),
      'invalid: content cannot be decrypted',
    );
    for (const log of logs) {
      expect(log).not.toHaveBeenCalled();
    }
  });

  it.each<[string, string]>([
    ['not JSON', 'ping'],
    ['a JSON string', '"ping"'],
    ['a JSON list', '["1", "ping", []]'],
    ['null', 'null'],
    ['without an id', '{"method":"ping","params":[]}'],
    ['with an empty id', '{"id":"","method":"ping","params":[]}'],
    ['with a numeric id', '{"id":1,"method":"ping","params":[]}'],
    ['with a null id', '{"id":null,"method":"ping","params":[]}'],
  ])(
    'is refused when its request is %s, as no response could answer it',
    async (_case, plaintext) => {
      const relay = await relayDeployment();
      const { client } = await connectedClient(relay);
      await expectRefused(
        client,
        client.rawRequest(client.encrypt(plaintext)),
        'invalid: malformed NIP-46 request',
      );
    },
  );

  it.each<[string, Record<string, unknown>]>([
    ['no method', { params: [] }],
    ['a numeric method', { method: 1, params: [] }],
    ['no params', { method: 'ping' }],
    ['params as an object', { method: 'ping', params: {} }],
    ['params as a string', { method: 'ping', params: '' }],
    [
      'a numeric param',
      { method: 'nip44_encrypt', params: ['ab'.repeat(32), 1] },
    ],
    ['a null param', { method: 'sign_event', params: [null] }],
    ['an object param', { method: 'sign_event', params: [{ kind: 1 }] }],
    [
      'an oversized param',
      {
        method: 'nip44_encrypt',
        params: ['ab'.repeat(32), 'x'.repeat(MAX_PARAM_LENGTH + 1)],
      },
    ],
  ])(
    'with an id is answered with "invalid request" when it has %s',
    async (_case, fields) => {
      const relay = await relayDeployment();
      const { client } = await connectedClient(relay);
      const event = client.rawRequest(
        client.encrypt(JSON.stringify({ id: 'bad', ...fields })),
      );
      expect((await client.send(event)).payload).toEqual({
        id: 'bad',
        result: '',
        error: 'invalid request',
      });
    },
  );

  it(`takes parameters of up to ${MAX_PARAM_LENGTH} characters`, async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    // An unknown method gets past parameter validation only.
    expect(
      await client.call('unknown_method', ['x'.repeat(MAX_PARAM_LENGTH)]),
    ).toEqual({
      id: expect.any(String),
      result: '',
      error: 'unsupported method',
    });
  });

  it('is refused while REMOTE_SIGNER_PRIVATE_KEY is invalid', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const event = client.request('ping', []);
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const invalid = bytesToHex(new Uint8Array(32));
    await configureHub(relay, { REMOTE_SIGNER_PRIVATE_KEY: invalid });
    clearNip44Calls();
    await expectRefused(client, event, 'error: server configuration error');
    expectNothingDecrypted();
    expect(log.mock.calls).toEqual([
      [
        'REMOTE_SIGNER_PRIVATE_KEY must be set to an nsec or a 64-character hex private key',
      ],
    ]);
  });

  it('never echoes the request or leaks secrets in relay messages', async () => {
    const relay = await relayDeployment();
    const { client, identity } = await connectedClient(relay);
    const logs = captureLogs();
    const secrets = [
      bytesToHex(relay.remoteSigner.secretKey),
      nsecEncode(relay.remoteSigner.secretKey),
      bytesToHex(identity.secretKey),
      nsecEncode(identity.secretKey),
      'ping',
      'tampered',
    ];
    const event = client.request('ping', [], 'tampered');
    for (const message of [
      ['EVENT', { ...event, sig: tamperHex(event.sig) }],
      ['EVENT', resign(event, { kind: 1 }, client.key.secretKey)],
      ['EVENT', resign(event, { tags: [] }, client.key.secretKey)],
      ['EVENT', client.rawRequest(client.encrypt('ping tampered'))],
      ['EVENT', client.rawRequest('ping tampered')],
      ['EVENT', { ...event, kind: 'ping tampered' }],
      ['REQ', 'sub', { kinds: [1], authors: ['ping tampered'] }],
      'ping tampered',
    ]) {
      client.socket.send(message);
    }
    const replies = await client.socket.drain();
    expect(replies).toHaveLength(8);
    const text = JSON.stringify(replies);
    for (const secret of secrets) {
      expect(text).not.toContain(secret);
    }
    for (const log of logs) {
      expect(log).not.toHaveBeenCalled();
    }
  });

  it('keeps accepting requests from a client with a clock off', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const event = resign(
      client.request('ping', [], 'old'),
      { created_at: unixNow() - 86_400 * 365 },
      client.key.secretKey,
    );
    expect((await client.send(event)).payload).toEqual({
      id: 'old',
      result: 'pong',
    });
  });
});
