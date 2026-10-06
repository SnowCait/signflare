import { runInDurableObject } from 'cloudflare:test';
import { NostrConnect } from 'nostr-tools/kinds';
import * as nip04 from 'nostr-tools/nip04';
import { nsecEncode } from 'nostr-tools/nip19';
import * as nip44 from 'nostr-tools/nip44';
import { getEventHash, type NostrEvent, verifyEvent } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MAX_PARAM_LENGTH } from '../src/nip46';
import type { PairingPermissionsInput } from '../src/pairings';
import {
  instrumentHubSql,
  recordingMasterKeyReads,
  replaceHubEnv,
  SQLITE_FULL_MESSAGE,
  TEST_MASTER_ENCRYPTION_KEY,
} from './hub-helpers';
import { randomKey, type TestKey, unixNow } from './nostr-helpers';
import {
  configureHub,
  connectedClient,
  createPairing,
  type Nip46Payload,
  type Relay,
  registerIdentity,
  relayDeployment,
  subscribedClient,
  type TestClient,
} from './relay-helpers';

function error(error: string): Nip46Payload {
  return { id: expect.any(String), result: '', error };
}

function template(overrides: Record<string, unknown> = {}) {
  return {
    kind: 1,
    content: 'Hello from Signflare',
    tags: [
      ['t', 'signflare'],
      ['p', 'ab'.repeat(32), 'wss://relay.example', 'mention'],
    ],
    created_at: 1_714_078_911,
    ...overrides,
  };
}

function signEvent(client: TestClient, value: unknown = template()) {
  return client.call('sign_event', [
    typeof value === 'string' ? value : JSON.stringify(value),
  ]);
}

// A client connected with `permissions`, reached through the session's
// identity key pair.
async function connected(
  permissions: PairingPermissionsInput = 'all',
  requested?: string,
) {
  const relay = await relayDeployment();
  const identity = await registerIdentity(relay);
  const client = await subscribedClient(relay);
  const secret = await createPairing(relay, identity.pubkey, permissions);
  const rest = requested === undefined ? [] : [requested];
  expect(await client.connect(secret, ...rest)).toEqual({
    id: expect.any(String),
    result: 'ack',
  });
  return { relay, identity, client };
}

function lastUsedAt(
  relay: Relay,
  clientPubkey: string,
): Promise<number | undefined> {
  return runInDurableObject(
    relay.hub,
    (_instance, state) =>
      state.storage.sql
        .exec<{ last_used_at: number }>(
          'SELECT last_used_at FROM sessions WHERE client_pubkey = ?',
          clientPubkey,
        )
        .toArray()[0]?.last_used_at,
  );
}

function setLastUsedAt(
  relay: Relay,
  clientPubkey: string,
  value: number,
): Promise<void> {
  return runInDurableObject(relay.hub, (_instance, state) => {
    state.storage.sql.exec(
      'UPDATE sessions SET last_used_at = ? WHERE client_pubkey = ?',
      value,
      clientPubkey,
    );
  });
}

// Spies on everything that decrypting a user private key involves.
async function watchKeyDecryption(relay: Relay) {
  const reads: string[] = [];
  await replaceHubEnv(relay.hub, (hubEnv) =>
    recordingMasterKeyReads(hubEnv, reads),
  );
  const decrypt = vi.spyOn(crypto.subtle, 'decrypt');
  return { reads, decrypt };
}

function captureLogs() {
  return (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
    vi.spyOn(console, method).mockImplementation(() => {}),
  );
}

function nip44Key(secretKey: Uint8Array, pubkey: string): Uint8Array {
  return nip44.getConversationKey(secretKey, pubkey);
}

// Valid hex that is not the x coordinate of a curve point.
const NOT_ON_CURVE = 'ff'.repeat(32);

afterEach(() => {
  vi.restoreAllMocks();
});

describe('ping', () => {
  it('answers pong', async () => {
    const { client } = await connected();
    expect(await client.call('ping')).toEqual({
      id: expect.any(String),
      result: 'pong',
    });
  });

  it('takes no params', async () => {
    const { client } = await connected();
    expect(await client.call('ping', ['ping'])).toEqual(
      error('invalid request'),
    );
  });
});

describe('get_public_key', () => {
  it('returns the user pubkey of the session, not the remote-signer pubkey', async () => {
    const { relay, identity, client } = await connected([]);
    const watched = await watchKeyDecryption(relay);
    expect(await client.result('get_public_key')).toBe(identity.pubkey);
    expect(identity.pubkey).not.toBe(relay.remoteSigner.pubkey);
    // No user private key is needed.
    expect(watched.reads).toEqual([]);
    expect(watched.decrypt).not.toHaveBeenCalled();
  });

  it('returns the identity of each session', async () => {
    const relay = await relayDeployment();
    const first = await connectedClient(relay);
    const second = await connectedClient(relay);
    expect(await first.client.result('get_public_key')).toBe(
      first.identity.pubkey,
    );
    expect(await second.client.result('get_public_key')).toBe(
      second.identity.pubkey,
    );
  });

  it('takes no params', async () => {
    const { client } = await connected();
    expect(await client.call('get_public_key', [''])).toEqual(
      error('invalid request'),
    );
  });
});

describe('switch_relays', () => {
  it('returns JSON null, as there is no other relay', async () => {
    const { client } = await connected([]);
    const result = await client.result('switch_relays');
    expect(result).toBe('null');
    expect(JSON.parse(result)).toBeNull();
  });

  it('takes no params', async () => {
    const { client } = await connected();
    expect(await client.call('switch_relays', ['wss://relay.example'])).toEqual(
      error('invalid request'),
    );
  });
});

describe('logout', () => {
  it('takes no params', async () => {
    const { relay, client } = await connected();
    expect(await client.call('logout', ['now'])).toEqual(
      error('invalid request'),
    );
    expect(await lastUsedAt(relay, client.pubkey)).toBeDefined();
  });
});

describe('unknown methods', () => {
  it.each([
    'create_account',
    'Connect',
    'PING',
    'nip04_encrypt ',
    '',
    'auth_url',
  ])('are answered with "unsupported method": %j', async (method) => {
    const { client } = await connected();
    expect(await client.call(method)).toEqual(error('unsupported method'));
  });

  it('are answered without a session as well', async () => {
    const relay = await relayDeployment();
    const client = await subscribedClient(relay);
    expect(await client.call('create_account', ['name', 'domain'])).toEqual(
      error('unsupported method'),
    );
  });
});

describe('sign_event', () => {
  it('signs the template with the session identity', async () => {
    const { identity, client } = await connected(['sign_event']);
    const signed: NostrEvent = JSON.parse(
      await client.result('sign_event', [JSON.stringify(template())]),
    );
    expect(signed).toEqual({
      ...template(),
      pubkey: identity.pubkey,
      id: getEventHash({ ...template(), pubkey: identity.pubkey }),
      sig: expect.stringMatching(/^[0-9a-f]{128}$/),
    });
    expect(verifyEvent(signed)).toBe(true);
  });

  it('ignores a pubkey, id, sig, and other fields supplied by the client', async () => {
    const { relay, identity, client } = await connected(['sign_event']);
    const other = randomKey();
    const supplied = {
      ...template(),
      pubkey: other.pubkey,
      id: 'ab'.repeat(32),
      sig: 'cd'.repeat(64),
      extra: 'field',
    };
    const signed: NostrEvent = JSON.parse(
      await client.result('sign_event', [JSON.stringify(supplied)]),
    );
    expect(Object.keys(signed).sort()).toEqual([
      'content',
      'created_at',
      'id',
      'kind',
      'pubkey',
      'sig',
      'tags',
    ]);
    expect(signed.pubkey).toBe(identity.pubkey);
    expect(signed.pubkey).not.toBe(relay.remoteSigner.pubkey);
    expect(signed.id).toBe(getEventHash(signed));
    expect(verifyEvent(signed)).toBe(true);
  });

  it.each([0, 1, 7, 30_023, 65_535])(
    'signs kind %i under the sign_event wildcard',
    async (kind) => {
      const { identity, client } = await connected(['sign_event']);
      const signed: NostrEvent = JSON.parse(
        await client.result('sign_event', [JSON.stringify(template({ kind }))]),
      );
      expect(signed).toMatchObject({ kind, pubkey: identity.pubkey });
      expect(verifyEvent(signed)).toBe(true);
    },
  );

  it('signs only the kinds of sign_event:<kind> permissions', async () => {
    const { client } = await connected(['sign_event:1', 'sign_event:7']);
    for (const kind of [1, 7]) {
      const signed = JSON.parse(
        await client.result('sign_event', [JSON.stringify(template({ kind }))]),
      );
      expect(verifyEvent(signed)).toBe(true);
    }
    for (const kind of [0, 4, 10, 17, 30_023]) {
      expect(await signEvent(client, template({ kind }))).toEqual(
        error('permission denied'),
      );
    }
  });

  it('is denied with only other permissions', async () => {
    const { client } = await connected([
      'nip04_encrypt',
      'nip04_decrypt',
      'nip44_encrypt',
      'nip44_decrypt',
    ]);
    expect(await signEvent(client)).toEqual(error('permission denied'));
  });

  it.each<[string, unknown]>([
    ['not JSON', '{"kind":1'],
    ['a JSON list', [1, '', [], 1]],
    ['a JSON string', '"event"'],
    ['JSON null', 'null'],
    ['no kind', template({ kind: undefined })],
    ['a negative kind', template({ kind: -1 })],
    ['a kind above 65535', template({ kind: 65_536 })],
    ['a fractional kind', template({ kind: 1.5 })],
    ['a kind as a string', template({ kind: '1' })],
    ['no content', template({ content: undefined })],
    ['numeric content', template({ content: 1 })],
    ['no tags', template({ tags: undefined })],
    ['tags as an object', template({ tags: {} })],
    ['a tag that is not a list', template({ tags: ['t'] })],
    ['a tag with a number', template({ tags: [['t', 1]] })],
    ['a tag with null', template({ tags: [['t', null]] })],
    ['no created_at', template({ created_at: undefined })],
    ['a negative created_at', template({ created_at: -1 })],
    ['a fractional created_at', template({ created_at: 1.5 })],
    ['a created_at as a string', template({ created_at: '1714078911' })],
    ['an unsafe created_at', template({ created_at: 2 ** 53 })],
  ])('rejects a template that is %s', async (_case, value) => {
    const { relay, client } = await connected(['sign_event']);
    const watched = await watchKeyDecryption(relay);
    expect(await signEvent(client, value)).toEqual(error('invalid request'));
    expect(watched.reads).toEqual([]);
  });

  it.each<[string, string[]]>([
    ['no template', []],
    ['a second param', [JSON.stringify(template()), '']],
  ])('rejects %s', async (_case, params) => {
    const { client } = await connected(['sign_event']);
    expect(await client.call('sign_event', params)).toEqual(
      error('invalid request'),
    );
  });

  it(`signs templates of up to ${MAX_PARAM_LENGTH} characters`, async () => {
    const { identity, client } = await connected(['sign_event']);
    const base = JSON.stringify(template({ content: '' })).length;
    const content = 'x'.repeat(MAX_PARAM_LENGTH - base);
    const largest = JSON.stringify(template({ content }));
    expect(largest).toHaveLength(MAX_PARAM_LENGTH);
    const signed = JSON.parse(await client.result('sign_event', [largest]));
    expect(signed).toMatchObject({ content, pubkey: identity.pubkey });
    expect(verifyEvent(signed)).toBe(true);

    expect(
      await signEvent(client, template({ content: `${content}x` })),
    ).toEqual(error('invalid request'));
  });
});

describe('NIP-04', () => {
  it('encrypts to a third party with the session identity', async () => {
    const { identity, client } = await connected(['nip04_encrypt']);
    const thirdParty = randomKey();
    const ciphertext = await client.result('nip04_encrypt', [
      thirdParty.pubkey,
      'Hello, NIP-04',
    ]);
    expect(ciphertext).toMatch(/^[A-Za-z0-9+/]+=*\?iv=[A-Za-z0-9+/]+=*$/);
    expect(
      nip04.decrypt(thirdParty.secretKey, identity.pubkey, ciphertext),
    ).toBe('Hello, NIP-04');
  });

  it('decrypts from a third party with the session identity', async () => {
    const { identity, client } = await connected(['nip04_decrypt']);
    const thirdParty = randomKey();
    const ciphertext = nip04.encrypt(
      thirdParty.secretKey,
      identity.pubkey,
      'Hello back',
    );
    expect(
      await client.result('nip04_decrypt', [thirdParty.pubkey, ciphertext]),
    ).toBe('Hello back');
  });

  it('round-trips an empty and a non-ASCII text', async () => {
    const { identity, client } = await connected([
      'nip04_encrypt',
      'nip04_decrypt',
    ]);
    const thirdParty = randomKey();
    for (const text of ['', 'こんにちは, Nostr ⚡']) {
      const ciphertext = await client.result('nip04_encrypt', [
        thirdParty.pubkey,
        text,
      ]);
      expect(
        nip04.decrypt(thirdParty.secretKey, identity.pubkey, ciphertext),
      ).toBe(text);
      expect(
        await client.result('nip04_decrypt', [thirdParty.pubkey, ciphertext]),
      ).toBe(text);
    }
  });

  it.each<[string, string]>([
    ['without an iv', 'aGVsbG8='],
    ['not base64', 'not base64?iv=not base64'],
    ['empty', ''],
  ])('reports a ciphertext %s as undecryptable', async (_case, ciphertext) => {
    const { client } = await connected(['nip04_decrypt']);
    expect(
      await client.call('nip04_decrypt', [randomKey().pubkey, ciphertext]),
    ).toEqual(error('decryption failed'));
  });

  it('cannot decrypt a message for another identity', async () => {
    const { client } = await connected(['nip04_decrypt']);
    const thirdParty = randomKey();
    const ciphertext = nip04.encrypt(
      thirdParty.secretKey,
      randomKey().pubkey,
      'Not for this identity',
    );
    const response = await client.call('nip04_decrypt', [
      thirdParty.pubkey,
      ciphertext,
    ]);
    expect(response.result).not.toBe('Not for this identity');
  });
});

describe('NIP-44', () => {
  it('encrypts to a third party with the session identity, not the remote signer', async () => {
    const { relay, identity, client } = await connected(['nip44_encrypt']);
    const thirdParty = randomKey();
    const payload = await client.result('nip44_encrypt', [
      thirdParty.pubkey,
      'Hello, NIP-44',
    ]);
    expect(
      nip44.decrypt(payload, nip44Key(thirdParty.secretKey, identity.pubkey)),
    ).toBe('Hello, NIP-44');
    expect(() =>
      nip44.decrypt(
        payload,
        nip44Key(thirdParty.secretKey, relay.remoteSigner.pubkey),
      ),
    ).toThrow();
  });

  it('decrypts from a third party with the session identity', async () => {
    const { identity, client } = await connected(['nip44_decrypt']);
    const thirdParty = randomKey();
    const payload = nip44.encrypt(
      'Hello back',
      nip44Key(thirdParty.secretKey, identity.pubkey),
    );
    expect(
      await client.result('nip44_decrypt', [thirdParty.pubkey, payload]),
    ).toBe('Hello back');
  });

  it('does not decrypt payloads for the remote signer', async () => {
    const { relay, client } = await connected(['nip44_decrypt']);
    const thirdParty = randomKey();
    const payload = nip44.encrypt(
      'For the transport',
      nip44Key(thirdParty.secretKey, relay.remoteSigner.pubkey),
    );
    expect(
      await client.call('nip44_decrypt', [thirdParty.pubkey, payload]),
    ).toEqual(error('decryption failed'));
  });

  it('round-trips a non-ASCII text', async () => {
    const { client } = await connected(['nip44_encrypt', 'nip44_decrypt']);
    const thirdParty = randomKey();
    const text = 'こんにちは, Nostr ⚡';
    const payload = await client.result('nip44_encrypt', [
      thirdParty.pubkey,
      text,
    ]);
    expect(
      await client.result('nip44_decrypt', [thirdParty.pubkey, payload]),
    ).toBe(text);
  });

  it('rejects an empty plaintext before decrypting any key', async () => {
    const { relay, client } = await connected(['nip44_encrypt']);
    const watched = await watchKeyDecryption(relay);
    expect(
      await client.call('nip44_encrypt', [randomKey().pubkey, '']),
    ).toEqual(error('invalid request'));
    expect(watched.reads).toEqual([]);
    expect(watched.decrypt).not.toHaveBeenCalled();
  });

  it.each<[string, string]>([
    ['not base64', 'not base64'],
    ['too short', 'AgAA'],
    ['empty', ''],
    ['of an unknown version', `#${'A'.repeat(200)}`],
  ])('reports a payload %s as undecryptable', async (_case, payload) => {
    const { client } = await connected(['nip44_decrypt']);
    expect(
      await client.call('nip44_decrypt', [randomKey().pubkey, payload]),
    ).toEqual(error('decryption failed'));
  });
});

describe('third-party pubkeys', () => {
  const methods = [
    'nip04_encrypt',
    'nip04_decrypt',
    'nip44_encrypt',
    'nip44_decrypt',
  ] as const;

  it.each(methods)(
    'are validated before any key is decrypted for %s',
    async (method) => {
      const { relay, client } = await connected('all');
      const watched = await watchKeyDecryption(relay);
      const pubkey = randomKey().pubkey;
      for (const invalid of [
        pubkey.toUpperCase(),
        pubkey.slice(2),
        `${pubkey}00`,
        `npub1${pubkey.slice(5)}`,
        '',
        ` ${pubkey}`,
      ]) {
        expect(await client.call(method, [invalid, 'text'])).toEqual(
          error('invalid request'),
        );
      }
      expect(watched.reads).toEqual([]);
      expect(watched.decrypt).not.toHaveBeenCalled();
    },
  );

  it.each(methods)('need exactly two params for %s', async (method) => {
    const { client } = await connected('all');
    const pubkey = randomKey().pubkey;
    for (const params of [[], [pubkey], [pubkey, 'text', 'text']]) {
      expect(await client.call(method, params)).toEqual(
        error('invalid request'),
      );
    }
  });

  it.each<[string, string]>([
    ['nip04_encrypt', 'invalid request'],
    ['nip44_encrypt', 'invalid request'],
    ['nip04_decrypt', 'decryption failed'],
    ['nip44_decrypt', 'decryption failed'],
  ])('that are no curve point fail %s', async (method, failure) => {
    const { client } = await connected('all');
    expect(await client.call(method, [NOT_ON_CURVE, 'text?iv=text'])).toEqual(
      error(failure),
    );
  });
});

describe('permissions', () => {
  const OPERATIONS: [string, string, () => unknown[]][] = [
    ['sign_event', 'sign_event', () => [JSON.stringify(template())]],
    ['nip04_encrypt', 'nip04_encrypt', () => [randomKey().pubkey, 'text']],
    [
      'nip04_decrypt',
      'nip04_decrypt',
      () => [randomKey().pubkey, 'text?iv=AAAAAAAAAAAAAAAAAAAAAA=='],
    ],
    ['nip44_encrypt', 'nip44_encrypt', () => [randomKey().pubkey, 'text']],
    ['nip44_decrypt', 'nip44_decrypt', () => [randomKey().pubkey, 'text']],
  ];

  it.each(OPERATIONS)(
    'deny %s by default',
    async (method, _permission, params) => {
      // Nothing requested is granted, so the session has no permissions.
      const { client } = await connected(['nip44_encrypt'], 'sign_event:1');
      expect(await client.call(method, params())).toEqual(
        error('permission denied'),
      );
    },
  );

  it('are not needed for the control methods', async () => {
    const { identity, client } = await connected(
      ['nip44_encrypt'],
      'sign_event:1',
    );
    expect(await client.result('ping')).toBe('pong');
    expect(await client.result('get_public_key')).toBe(identity.pubkey);
    expect(await client.result('switch_relays')).toBe('null');
    expect(await client.result('logout')).toBe('ack');
  });

  it.each(OPERATIONS)(
    'grant %s by its exact permission only',
    async (method, permission, params) => {
      const { client } = await connected([permission]);
      for (const [other, , otherParams] of OPERATIONS) {
        const response = await client.call(
          other,
          other === method ? params() : otherParams(),
        );
        if (other === method) {
          expect(response.error).not.toBe('permission denied');
        } else {
          expect(response).toEqual(error('permission denied'));
        }
      }
    },
  );

  it('are checked before the user private key is decrypted', async () => {
    const { relay, client } = await connected(['sign_event:1']);
    const watched = await watchKeyDecryption(relay);
    for (const [method, , params] of OPERATIONS) {
      if (method !== 'sign_event') {
        expect(await client.call(method, params())).toEqual(
          error('permission denied'),
        );
      }
    }
    expect(await signEvent(client, template({ kind: 7 }))).toEqual(
      error('permission denied'),
    );
    expect(watched.reads).toEqual([]);
    expect(watched.decrypt).not.toHaveBeenCalled();

    // A permitted operation decrypts the key, once.
    expect((await signEvent(client)).error).toBeUndefined();
    expect(watched.reads).toEqual(['MASTER_ENCRYPTION_KEY']);
    expect(watched.decrypt).toHaveBeenCalledTimes(1);
  });

  it('follow the session, not the pairing, after connect', async () => {
    const { relay, identity, client } = await connected('all', 'nip44_encrypt');
    // A later pairing with more permissions changes nothing for the session.
    await createPairing(relay, identity.pubkey, 'all');
    expect(await signEvent(client)).toEqual(error('permission denied'));
  });
});

describe('responses', () => {
  it('are kind 24133 events signed by the remote signer for the client', async () => {
    const { relay, client } = await connected();
    const before = unixNow();
    const request = client.request('ping', [], 'response-check');
    const { event, payload } = await client.send(request);
    expect(event).toEqual({
      kind: NostrConnect,
      pubkey: relay.remoteSigner.pubkey,
      created_at: expect.any(Number),
      tags: [['p', client.pubkey]],
      content: expect.any(String),
      id: getEventHash(event),
      sig: expect.stringMatching(/^[0-9a-f]{128}$/),
    });
    expect(event.created_at).toBeGreaterThanOrEqual(before);
    expect(event.created_at).toBeLessThanOrEqual(unixNow() + 1);
    expect(verifyEvent(JSON.parse(JSON.stringify(event)))).toBe(true);
    // The content is NIP-44 between the remote signer and the client.
    expect(
      JSON.parse(
        nip44.decrypt(
          event.content,
          nip44Key(client.key.secretKey, relay.remoteSigner.pubkey),
        ),
      ),
    ).toEqual({ id: 'response-check', result: 'pong' });
    expect(payload).toEqual({ id: 'response-check', result: 'pong' });
  });

  it('answer every request id with exactly a result or an error', async () => {
    const { client } = await connected([]);
    for (const [id, method, expected] of [
      ['a', 'ping', { id: 'a', result: 'pong' }],
      [
        'b-with-a-longer-id',
        'switch_relays',
        { id: 'b-with-a-longer-id', result: 'null' },
      ],
      ['c', 'sign_event', { id: 'c', result: '', error: 'invalid request' }],
      [
        'ç ⚡',
        'unknown',
        { id: 'ç ⚡', result: '', error: 'unsupported method' },
      ],
    ] as const) {
      const { payload } = await client.send(client.request(method, [], id));
      expect(payload).toStrictEqual(expected);
    }
  });

  it('carry no secrets', async () => {
    const relay = await relayDeployment();
    const identity = await registerIdentity(relay);
    const client = await subscribedClient(relay);
    const secret = await createPairing(relay, identity.pubkey, 'all');
    const logs = captureLogs();
    const thirdParty = randomKey();
    const events: unknown[] = [];
    const payloads: unknown[] = [];
    const record = async (method: string, params: unknown[]) => {
      const { event, payload } = await client.send(
        client.request(method, params),
      );
      events.push(event);
      payloads.push(payload);
    };
    await record('connect', [relay.remoteSigner.pubkey, secret]);
    await record('get_public_key', []);
    await record('sign_event', [JSON.stringify(template())]);
    await record('nip04_encrypt', [thirdParty.pubkey, 'plaintext']);
    await record('nip44_encrypt', [thirdParty.pubkey, 'plaintext']);
    await record('nip44_decrypt', [thirdParty.pubkey, 'garbage']);
    await record('logout', []);
    const text = JSON.stringify([events, payloads]);
    for (const forbidden of [
      secret,
      bytesToHex(identity.secretKey),
      nsecEncode(identity.secretKey),
      bytesToHex(relay.remoteSigner.secretKey),
      nsecEncode(relay.remoteSigner.secretKey),
      TEST_MASTER_ENCRYPTION_KEY,
      bytesToHex(thirdParty.secretKey),
    ]) {
      expect(text).not.toContain(forbidden);
    }
    // Nor library errors or stack traces.
    expect(JSON.stringify(payloads)).not.toMatch(/Error|invalid MAC|\bat\b/);
    for (const log of logs) {
      expect(log).not.toHaveBeenCalled();
    }
  });
});

describe('last_used_at', () => {
  async function stale(permissions: PairingPermissionsInput = 'all') {
    const { relay, identity, client } = await connected(permissions);
    await setLastUsedAt(relay, client.pubkey, 1);
    return { relay, identity, client };
  }

  it.each<[string, (client: TestClient, thirdParty: TestKey) => unknown[]]>([
    ['ping', () => []],
    ['get_public_key', () => []],
    ['switch_relays', () => []],
    ['sign_event', () => [JSON.stringify(template())]],
    ['nip04_encrypt', (_client, thirdParty) => [thirdParty.pubkey, 'text']],
    ['nip44_encrypt', (_client, thirdParty) => [thirdParty.pubkey, 'text']],
  ])('is updated by a successful %s', async (method, params) => {
    const { relay, client } = await stale();
    const before = unixNow();
    expect(
      (await client.call(method, params(client, randomKey()))).error,
    ).toBeUndefined();
    expect(await lastUsedAt(relay, client.pubkey)).toBeGreaterThanOrEqual(
      before,
    );
  });

  it('is updated by successful decryption', async () => {
    const { relay, identity, client } = await stale();
    const thirdParty = randomKey();
    await client.result('nip04_decrypt', [
      thirdParty.pubkey,
      nip04.encrypt(thirdParty.secretKey, identity.pubkey, 'text'),
    ]);
    expect(await lastUsedAt(relay, client.pubkey)).toBeGreaterThan(1);
    await setLastUsedAt(relay, client.pubkey, 1);
    await client.result('nip44_decrypt', [
      thirdParty.pubkey,
      nip44.encrypt('text', nip44Key(thirdParty.secretKey, identity.pubkey)),
    ]);
    expect(await lastUsedAt(relay, client.pubkey)).toBeGreaterThan(1);
  });

  it.each<[string, (client: TestClient) => unknown[], string]>([
    ['a malformed request', () => ['extra'], 'ping'],
    ['an invalid template', () => ['{}'], 'sign_event'],
    [
      'a permission denial',
      () => [JSON.stringify(template({ kind: 7 }))],
      'sign_event',
    ],
    [
      'a failed decryption',
      () => [randomKey().pubkey, 'garbage'],
      'nip44_decrypt',
    ],
    ['an unsupported method', () => [], 'create_account'],
  ])('is not updated by %s', async (_case, params, method) => {
    const { relay, client } = await stale(['sign_event:1', 'nip44_decrypt']);
    expect((await client.call(method, params(client))).error).toBeDefined();
    expect(await lastUsedAt(relay, client.pubkey)).toBe(1);
  });

  it('is not updated by requests of other clients', async () => {
    const { relay, client } = await stale();
    const stranger = await subscribedClient(relay);
    expect(await stranger.call('ping')).toEqual(error('not connected'));
    expect(await lastUsedAt(relay, client.pubkey)).toBe(1);
  });

  it('is not updated by connect', async () => {
    const { relay, identity, client } = await stale();
    const secret = await createPairing(relay, identity.pubkey, 'all');
    expect(await client.connect(secret)).toEqual(error('already connected'));
    expect(await lastUsedAt(relay, client.pubkey)).toBe(1);
  });

  it('is not updated by logout', async () => {
    const { relay, client } = await stale();
    const statements: string[] = [];
    await instrumentHubSql(relay.hub, { statements });
    expect(await client.result('logout')).toBe('ack');
    expect(
      statements.filter((statement) => statement.startsWith('UPDATE sessions')),
    ).toEqual([]);
  });

  it('never moves backwards', async () => {
    const { relay, client } = await connected();
    const future = unixNow() + 3600;
    await setLastUsedAt(relay, client.pubkey, future);
    await client.result('ping');
    expect(await lastUsedAt(relay, client.pubkey)).toBe(future);
  });

  it('is skipped on full storage without failing the operation', async () => {
    const { relay, client } = await stale();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    await instrumentHubSql(relay.hub, {
      failing: /^\s*UPDATE sessions/,
      message: SQLITE_FULL_MESSAGE,
    });
    expect(await client.result('ping')).toBe('pong');
    expect(
      await client.result('sign_event', [JSON.stringify(template())]),
    ).toBeTruthy();
    expect(log.mock.calls).toEqual([
      ['NIP-46 session use was not recorded: storage is full'],
      ['NIP-46 session use was not recorded: storage is full'],
    ]);
    vi.restoreAllMocks();
    expect(await lastUsedAt(relay, client.pubkey)).toBe(1);
  });
});

describe('a session revoked during an operation', () => {
  it('gets no result for it', async () => {
    const { relay, client } = await connected();
    const sql = await runInDurableObject(
      relay.hub,
      (_instance, state) => state.storage.sql,
    );
    // The session is revoked while the user private key is being decrypted.
    const decrypt = crypto.subtle.decrypt.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (...args) => {
      const plaintext = await decrypt(...args);
      sql.exec('DELETE FROM sessions WHERE client_pubkey = ?', client.pubkey);
      return plaintext;
    });
    expect(await signEvent(client)).toEqual(error('not connected'));
  });
});

describe('internal failures', () => {
  it('report a missing MASTER_ENCRYPTION_KEY as an internal error', async () => {
    const { relay, client } = await connected();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    await configureHub(relay, { MASTER_ENCRYPTION_KEY: undefined });
    expect(await signEvent(client)).toEqual(error('internal error'));
    expect(log.mock.calls).toEqual([
      ['MASTER_ENCRYPTION_KEY must be set to a secret of at least 32 bytes'],
    ]);
    // Methods that need no user private key keep working.
    expect(await client.result('get_public_key')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('report a wrong MASTER_ENCRYPTION_KEY as an internal error', async () => {
    const { relay, client } = await connected();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    await configureHub(relay, {
      MASTER_ENCRYPTION_KEY: `${TEST_MASTER_ENCRYPTION_KEY}, but another one`,
    });
    expect(await signEvent(client)).toEqual(error('internal error'));
    expect(log.mock.calls).toEqual([
      ['NIP-46 request failed: identity key decryption failed'],
    ]);
  });

  it('report altered stored permissions as an internal error', async () => {
    const { relay, client } = await connected();
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    await runInDurableObject(relay.hub, (_instance, state) => {
      state.storage.sql.exec('UPDATE sessions SET permissions = ?', '["all"]');
    });
    expect(await client.call('ping')).toEqual(error('internal error'));
    expect(log.mock.calls).toEqual([
      ['NIP-46 request failed:', 'MalformedPermissionsError'],
    ]);
  });

  it('never put exception messages into the response', async () => {
    const { relay, client } = await connected();
    const detail = `SQLITE_ERROR: SELECT * FROM identities ${TEST_MASTER_ENCRYPTION_KEY}`;
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    await instrumentHubSql(relay.hub, {
      failing: /FROM identities/,
      message: detail,
    });
    const { payload } = await client.send(
      client.request('sign_event', [JSON.stringify(template())]),
    );
    expect(payload).toEqual(error('internal error'));
    expect(JSON.stringify(payload)).not.toContain('SQLITE');
    expect(log.mock.calls).toEqual([['NIP-46 request failed:', 'Error']]);
  });
});
