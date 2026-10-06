import { env, exports } from 'cloudflare:workers';
import { evictDurableObject, runInDurableObject } from 'cloudflare:test';
import { NostrConnect } from 'nostr-tools/kinds';
import type { Filter } from 'nostr-tools/filter';
import { afterEach, describe, expect, it, vi } from 'vitest';
import app from '../src/index';
import {
  type ConnectionState,
  MAX_FILTER_VALUES,
  MAX_FILTERS,
  MAX_MESSAGE_LENGTH,
  MAX_SUBSCRIPTION_ID_LENGTH,
  MAX_SUBSCRIPTIONS,
} from '../src/relay';
import type { SignerHub } from '../src/signer-hub';
import { allStoredValues } from './hub-helpers';
import { ORIGIN, randomKey } from './nostr-helpers';
import {
  configureHub,
  connectedClient,
  type Hub,
  openSocket,
  type Relay,
  relayDeployment,
  responseFilter,
  type TestSocket,
} from './relay-helpers';

// Attachments of the SignerHub's WebSockets. getWebSockets() lists them in
// no particular order, so they are sorted to compare as a set.
function attachments(hub: Hub): Promise<unknown[]> {
  return runInDurableObject(hub, (_instance, state) =>
    state
      .getWebSockets()
      .map((ws) => ws.deserializeAttachment())
      .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
  );
}

function sorted(values: unknown[]): unknown[] {
  return [...values].sort((a, b) =>
    JSON.stringify(a).localeCompare(JSON.stringify(b)),
  );
}

function subscriptionsOf(
  attachment: unknown,
): ConnectionState['subscriptions'] {
  return (attachment as ConnectionState | null)?.subscriptions ?? [];
}

// The filter as the relay stores and matches it.
function storedFilter(
  relay: Relay,
  clientPubkeys: string[],
  extra: Partial<Filter> = {},
): Filter {
  return {
    kinds: [NostrConnect],
    authors: [relay.remoteSigner.pubkey],
    '#p': clientPubkeys,
    ...extra,
  };
}

async function req(
  socket: TestSocket,
  subscriptionId: string,
  ...filters: unknown[]
): Promise<unknown> {
  socket.send(['REQ', subscriptionId, ...filters]);
  return socket.next();
}

function closed(subscriptionId: string, reason: string) {
  return ['CLOSED', subscriptionId, reason];
}

function captureLogs() {
  return (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
    vi.spyOn(console, method).mockImplementation(() => {}),
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('root WebSocket upgrade', () => {
  it('connects the deployment root to the relay in the SignerHub', async () => {
    const response = await exports.default.fetch(`${ORIGIN}/`, {
      headers: { Upgrade: 'websocket' },
    });
    expect(response.status).toBe(101);
    expect(response.webSocket).not.toBeNull();
    const socket = response.webSocket as WebSocket;
    socket.accept();
    const messages: unknown[] = [];
    const answered = new Promise<void>((resolve) => {
      socket.addEventListener('message', (event) => {
        messages.push(JSON.parse(event.data as string));
        resolve();
      });
    });
    socket.send(JSON.stringify(['BARRIER']));
    await answered;
    expect(messages).toEqual([['NOTICE', 'invalid: unsupported message type']]);
    const sockets = await runInDurableObject(
      env.SIGNER_HUB.getByName('signer'),
      (_instance, state) => state.getWebSockets().length,
    );
    expect(sockets).toBeGreaterThan(0);
    socket.close(1000);
  });

  it('uses the SignerHub named "signer"', async () => {
    const relay = await relayDeployment();
    const names: string[] = [];
    const recorded = {
      ...relay.env,
      SIGNER_HUB: {
        getByName: (name: string) => {
          names.push(name);
          return relay.hub;
        },
      } as unknown as Env['SIGNER_HUB'],
    };
    const socket = await openSocket({ ...relay, env: recorded });
    expect(names).toEqual(['signer']);
    await socket.close();
  });

  it.each(['websocket', 'WebSocket', 'WEBSOCKET'])(
    'accepts Upgrade: %s',
    async (upgrade) => {
      const relay = await relayDeployment();
      const response = await app.fetch(
        new Request(`${ORIGIN}/`, { headers: { Upgrade: upgrade } }),
        relay.env,
      );
      expect(response.status).toBe(101);
      response.webSocket?.accept();
      response.webSocket?.close(1000);
    },
  );

  it('accepts the WebSocket through the Hibernation API', async () => {
    const relay = await relayDeployment();
    const first = await openSocket(relay);
    const second = await openSocket(relay);
    // getWebSockets() lists only WebSockets passed to acceptWebSocket().
    expect(
      await runInDurableObject(
        relay.hub,
        (_instance, state) => state.getWebSockets().length,
      ),
    ).toBe(2);
    await first.close();
    await second.close();
    expect(
      await runInDurableObject(
        relay.hub,
        (_instance, state) => state.getWebSockets().length,
      ),
    ).toBe(0);
  });

  it('keeps WebSockets connected while the SignerHub is evicted', async () => {
    const relay = await relayDeployment();
    const { client, identity } = await connectedClient(relay);
    await evictDurableObject(relay.hub);
    await configureHub(relay);
    expect(client.socket.ws.readyState).toBe(WebSocket.OPEN);
    expect(await client.result('get_public_key')).toBe(identity.pubkey);
  });

  it('completes the close handshake the client starts', async () => {
    const relay = await relayDeployment();
    for (const code of [1000, 1001, 4000]) {
      const socket = await openSocket(relay);
      const event = await socket.close(code);
      expect(event).toMatchObject({ code, wasClean: true });
    }
    const socket = await openSocket(relay);
    socket.ws.close();
    expect(await socket.closed).toMatchObject({ code: 1005, wasClean: true });
  });

  it('logs WebSocket errors without their details', async () => {
    const relay = await relayDeployment();
    await openSocket(relay);
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    await runInDurableObject(relay.hub, (instance, state) => {
      const hub = instance as SignerHub;
      const [ws] = state.getWebSockets();
      hub.webSocketError(ws, new TypeError(`detail ${ORIGIN}`));
      hub.webSocketError(ws, `detail ${ORIGIN}`);
    });
    expect(log.mock.calls).toEqual([
      ['Relay WebSocket error:', 'TypeError'],
      ['Relay WebSocket error:', 'string'],
    ]);
  });
});

describe('ordinary requests to the root', () => {
  it.each<[string, RequestInit]>([
    ['GET', {}],
    ['GET with another upgrade', { headers: { Upgrade: 'h2c' } }],
    ['GET with a list of upgrades', { headers: { Upgrade: 'h2c, websocket' } }],
    [
      'HEAD with Upgrade: websocket',
      { method: 'HEAD', headers: { Upgrade: 'websocket' } },
    ],
  ])('are not upgraded: %s', async (_case, init) => {
    const relay = await relayDeployment();
    const names: string[] = [];
    const recorded = {
      ...relay.env,
      SIGNER_HUB: {
        getByName: (name: string) => {
          names.push(name);
          return relay.hub;
        },
      } as unknown as Env['SIGNER_HUB'],
    };
    const response = await app.fetch(new Request(`${ORIGIN}/`, init), recorded);
    expect(response.status).toBe(200);
    expect(response.webSocket).toBeNull();
    // Answered without the SignerHub (docs/design.md §37.3).
    expect(names).toEqual([]);
  });

  it.each<[string, string, RequestInit]>([
    ['POST to the root', '/', { method: 'POST' }],
    ['GET to another path', '/relay', {}],
    ['GET to a nested path', '/admin/relay', {}],
  ])(
    'leave WebSocket upgrades of %s to other routes',
    async (_case, path, init) => {
      const relay = await relayDeployment();
      const response = await app.fetch(
        new Request(`${ORIGIN}${path}`, {
          ...init,
          headers: { Upgrade: 'websocket' },
        }),
        relay.env,
      );
      expect(response.status).toBe(404);
      expect(response.webSocket).toBeNull();
    },
  );

  it('keep the Admin API routed', async () => {
    const relay = await relayDeployment();
    const response = await app.fetch(
      new Request(`${ORIGIN}/admin/api/session`, {
        headers: { Upgrade: 'websocket' },
      }),
      { ...relay.env, ADMIN_PUBKEY: randomKey().pubkey },
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'unauthorized' });
  });

  it('are refused by the SignerHub unless they upgrade', async () => {
    const relay = await relayDeployment();
    const response = await relay.hub.fetch(`${ORIGIN}/`);
    expect(response.status).toBe(426);
    expect(response.headers.get('Upgrade')).toBe('websocket');
    expect(response.webSocket).toBeNull();
  });
});

describe('REQ', () => {
  it('accepts a NIP-46 subscription and ends stored events at once', async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const client = randomKey().pubkey;
    expect(
      await req(socket, 'sub', {
        ...responseFilter(relay, client),
        limit: 0,
      }),
    ).toEqual(['EOSE', 'sub']);
    expect(await socket.drain()).toEqual([]);
    expect(await attachments(relay.hub)).toEqual([
      {
        subscriptions: [
          { id: 'sub', filters: [storedFilter(relay, [client])] },
        ],
      },
    ]);
  });

  it('stores the filter in the WebSocket attachment, which survives eviction', async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const [first, second] = [randomKey().pubkey, randomKey().pubkey];
    expect(
      await req(
        socket,
        'responses',
        {
          ...responseFilter(relay, first),
          '#p': [first, second, first],
          kinds: [NostrConnect, NostrConnect],
          since: 1_700_000_000,
          until: 2_000_000_000,
          limit: 10,
        },
        responseFilter(relay, second),
      ),
    ).toEqual(['EOSE', 'responses']);
    const expected = {
      subscriptions: [
        {
          id: 'responses',
          filters: [
            storedFilter(relay, [first, second], {
              since: 1_700_000_000,
              until: 2_000_000_000,
            }),
            storedFilter(relay, [second]),
          ],
        },
      ],
    };
    expect(await attachments(relay.hub)).toEqual([expected]);

    await evictDurableObject(relay.hub);
    expect(await attachments(relay.hub)).toEqual([expected]);
  });

  it('keeps subscriptions apart per connection', async () => {
    const relay = await relayDeployment();
    const [one, two] = [await openSocket(relay), await openSocket(relay)];
    const [first, second] = [randomKey().pubkey, randomKey().pubkey];
    await req(one, 'sub', responseFilter(relay, first));
    await req(two, 'sub', responseFilter(relay, second));
    await req(two, 'other', responseFilter(relay, first));
    expect(await attachments(relay.hub)).toEqual(
      sorted([
        {
          subscriptions: [
            { id: 'sub', filters: [storedFilter(relay, [first])] },
          ],
        },
        {
          subscriptions: [
            { id: 'sub', filters: [storedFilter(relay, [second])] },
            { id: 'other', filters: [storedFilter(relay, [first])] },
          ],
        },
      ]),
    );
  });

  it('replaces the subscription with the same id', async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const [first, second] = [randomKey().pubkey, randomKey().pubkey];
    await req(socket, 'a', responseFilter(relay, first));
    await req(socket, 'b', responseFilter(relay, first));
    expect(await req(socket, 'a', responseFilter(relay, second))).toEqual([
      'EOSE',
      'a',
    ]);
    expect(subscriptionsOf((await attachments(relay.hub))[0])).toEqual([
      { id: 'b', filters: [storedFilter(relay, [first])] },
      { id: 'a', filters: [storedFilter(relay, [second])] },
    ]);
  });

  it('closes the subscription with the same id when refusing a REQ', async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const client = randomKey().pubkey;
    await req(socket, 'a', responseFilter(relay, client));
    await req(socket, 'b', responseFilter(relay, client));
    expect(await req(socket, 'a', { kinds: [1] })).toEqual(
      closed('a', 'restricted: filters must be limited to kind 24133'),
    );
    expect(subscriptionsOf((await attachments(relay.hub))[0])).toEqual([
      { id: 'b', filters: [storedFilter(relay, [client])] },
    ]);
  });

  const KINDS = 'restricted: filters must be limited to kind 24133';
  const AUTHORS =
    'restricted: filters must be limited to the remote-signer author';
  const CLIENT = 'restricted: filters must include a #p client pubkey';
  const MALFORMED = 'invalid: malformed filter';

  it.each<[string, (relay: Relay, client: string) => unknown, string]>([
    [
      'kinds missing',
      (r, c) => ({ ...responseFilter(r, c), kinds: undefined }),
      KINDS,
    ],
    [
      'another kind',
      (r, c) => ({ ...responseFilter(r, c), kinds: [1] }),
      KINDS,
    ],
    [
      'another kind besides 24133',
      (r, c) => ({ ...responseFilter(r, c), kinds: [NostrConnect, 1] }),
      KINDS,
    ],
    [
      'empty kinds',
      (r, c) => ({ ...responseFilter(r, c), kinds: [] }),
      MALFORMED,
    ],
    [
      'a kind as a string',
      (r, c) => ({ ...responseFilter(r, c), kinds: ['24133'] }),
      MALFORMED,
    ],
    [
      'a fractional kind',
      (r, c) => ({ ...responseFilter(r, c), kinds: [24133.5] }),
      MALFORMED,
    ],
    [
      'kinds not a list',
      (r, c) => ({ ...responseFilter(r, c), kinds: NostrConnect }),
      MALFORMED,
    ],
    [
      'authors missing',
      (r, c) => ({ ...responseFilter(r, c), authors: undefined }),
      AUTHORS,
    ],
    [
      'another author',
      (r, c) => ({ ...responseFilter(r, c), authors: [randomKey().pubkey] }),
      AUTHORS,
    ],
    [
      'another author besides the remote signer',
      (r, c) => ({
        ...responseFilter(r, c),
        authors: [r.remoteSigner.pubkey, randomKey().pubkey],
      }),
      AUTHORS,
    ],
    [
      'the client as author',
      (r, c) => ({ ...responseFilter(r, c), authors: [c] }),
      AUTHORS,
    ],
    [
      'empty authors',
      (r, c) => ({ ...responseFilter(r, c), authors: [] }),
      MALFORMED,
    ],
    [
      'an uppercase author',
      (r, c) => ({
        ...responseFilter(r, c),
        authors: [r.remoteSigner.pubkey.toUpperCase()],
      }),
      MALFORMED,
    ],
    [
      'an author prefix',
      (r, c) => ({
        ...responseFilter(r, c),
        authors: [r.remoteSigner.pubkey.slice(0, 16)],
      }),
      MALFORMED,
    ],
    [
      '#p missing',
      (r, c) => ({ ...responseFilter(r, c), '#p': undefined }),
      CLIENT,
    ],
    ['empty #p', (r, c) => ({ ...responseFilter(r, c), '#p': [] }), MALFORMED],
    [
      'a short #p',
      (r, c) => ({ ...responseFilter(r, c), '#p': [c.slice(2)] }),
      MALFORMED,
    ],
    [
      'an uppercase #p',
      (r, c) => ({ ...responseFilter(r, c), '#p': [c.toUpperCase()] }),
      MALFORMED,
    ],
    [
      'an npub-like #p',
      (r, c) => ({ ...responseFilter(r, c), '#p': [`npub1${c}`] }),
      MALFORMED,
    ],
    [
      '#p not a list',
      (r, c) => ({ ...responseFilter(r, c), '#p': c }),
      MALFORMED,
    ],
    [
      'a number in #p',
      (r, c) => ({ ...responseFilter(r, c), '#p': [c, 1] }),
      MALFORMED,
    ],
    [
      'ids',
      (r, c) => ({ ...responseFilter(r, c), ids: ['ab'.repeat(32)] }),
      'restricted: unsupported filter field',
    ],
    [
      'another tag',
      (r, c) => ({ ...responseFilter(r, c), '#e': ['ab'.repeat(32)] }),
      'restricted: unsupported filter field',
    ],
    [
      'search',
      (r, c) => ({ ...responseFilter(r, c), search: 'x' }),
      'restricted: unsupported filter field',
    ],
    [
      'a negative since',
      (r, c) => ({ ...responseFilter(r, c), since: -1 }),
      MALFORMED,
    ],
    [
      'a fractional until',
      (r, c) => ({ ...responseFilter(r, c), until: 1.5 }),
      MALFORMED,
    ],
    [
      'a string limit',
      (r, c) => ({ ...responseFilter(r, c), limit: '0' }),
      MALFORMED,
    ],
    ['null', () => null, MALFORMED],
    ['a list', () => [], MALFORMED],
    ['a string', () => 'filter', MALFORMED],
    ['an empty filter', () => ({}), KINDS],
    ['a generic subscription', () => ({ kinds: [1], limit: 10 }), KINDS],
  ])('refuses a filter with %s', async (_case, filter, reason) => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const client = randomKey().pubkey;
    expect(await req(socket, 'sub', filter(relay, client))).toEqual(
      closed('sub', reason),
    );
    expect(await socket.drain()).toEqual([]);
    // Nothing is stored for the refused REQ.
    expect(await attachments(relay.hub)).toEqual([null]);
  });

  it('refuses the whole REQ when one filter is refused', async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const client = randomKey().pubkey;
    expect(
      await req(socket, 'sub', responseFilter(relay, client), { kinds: [1] }),
    ).toEqual(closed('sub', KINDS));
    expect(await attachments(relay.hub)).toEqual([null]);
  });

  it('refuses a REQ without filters', async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    expect(await req(socket, 'sub')).toEqual(
      closed('sub', 'invalid: REQ without filters'),
    );
  });

  it(`accepts up to ${MAX_FILTERS} filters`, async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const filters = Array.from({ length: MAX_FILTERS + 1 }, () =>
      responseFilter(relay, randomKey().pubkey),
    );
    expect(await req(socket, 'sub', ...filters.slice(0, -1))).toEqual([
      'EOSE',
      'sub',
    ]);
    expect(await req(socket, 'other', ...filters)).toEqual(
      closed('other', 'restricted: too many filters'),
    );
  });

  it(`accepts up to ${MAX_FILTER_VALUES} values in each list`, async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const clients = Array.from(
      { length: MAX_FILTER_VALUES + 1 },
      () => randomKey().pubkey,
    );
    const limit = clients.slice(0, -1);
    expect(
      await req(socket, 'sub', {
        kinds: Array(MAX_FILTER_VALUES).fill(NostrConnect),
        authors: Array(MAX_FILTER_VALUES).fill(relay.remoteSigner.pubkey),
        '#p': limit,
      }),
    ).toEqual(['EOSE', 'sub']);
    for (const filter of [
      { ...responseFilter(relay, clients[0]), '#p': clients },
      {
        ...responseFilter(relay, clients[0]),
        kinds: Array(MAX_FILTER_VALUES + 1).fill(NostrConnect),
      },
      {
        ...responseFilter(relay, clients[0]),
        authors: Array(MAX_FILTER_VALUES + 1).fill(relay.remoteSigner.pubkey),
      },
    ]) {
      expect(await req(socket, 'other', filter)).toEqual(
        closed('other', 'restricted: too many filter values'),
      );
    }
    expect(subscriptionsOf((await attachments(relay.hub))[0])).toEqual([
      { id: 'sub', filters: [storedFilter(relay, limit)] },
    ]);
  });

  it(`accepts up to ${MAX_SUBSCRIPTIONS} subscriptions per connection`, async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const client = randomKey().pubkey;
    for (let i = 0; i < MAX_SUBSCRIPTIONS; i++) {
      expect(
        await req(socket, `sub-${i}`, responseFilter(relay, client)),
      ).toEqual(['EOSE', `sub-${i}`]);
    }
    expect(
      await req(socket, 'one-more', responseFilter(relay, client)),
    ).toEqual(closed('one-more', 'restricted: too many subscriptions'));
    // Replacing one does not add to the count.
    expect(await req(socket, 'sub-0', responseFilter(relay, client))).toEqual([
      'EOSE',
      'sub-0',
    ]);
    // Neither do the subscriptions of other connections.
    const other = await openSocket(relay);
    expect(await req(other, 'sub', responseFilter(relay, client))).toEqual([
      'EOSE',
      'sub',
    ]);
    expect(
      (await attachments(relay.hub)).map(
        (state) => subscriptionsOf(state).length,
      ),
    ).toEqual(expect.arrayContaining([1, MAX_SUBSCRIPTIONS]));
  });

  it('fits the largest accepted subscription state in a WebSocket attachment', async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    for (let i = 0; i < MAX_SUBSCRIPTIONS; i++) {
      // Characters outside Latin-1 take two bytes each when serialized.
      const id = `${'あ'.repeat(MAX_SUBSCRIPTION_ID_LENGTH - 1)}${i}`;
      const filters = Array.from({ length: MAX_FILTERS }, () => ({
        ...responseFilter(relay, ''),
        '#p': Array.from(
          { length: MAX_FILTER_VALUES },
          () => randomKey().pubkey,
        ),
        since: Number.MAX_SAFE_INTEGER - 1,
        until: Number.MAX_SAFE_INTEGER,
      }));
      expect(await req(socket, id, ...filters)).toEqual(['EOSE', id]);
    }
    const [state] = await attachments(relay.hub);
    expect(subscriptionsOf(state)).toHaveLength(MAX_SUBSCRIPTIONS);
    // Cloudflare refuses attachments larger than 16,384 bytes. The largest
    // state leaves room for as much again.
    await runInDurableObject(relay.hub, (_instance, hubState) => {
      const [ws] = hubState.getWebSockets();
      const attachment = ws.deserializeAttachment() as ConnectionState;
      expect(() =>
        ws.serializeAttachment({
          ...attachment,
          padding: 'x'.repeat(8 * 1024),
        }),
      ).not.toThrow();
      expect(() =>
        ws.serializeAttachment({
          ...attachment,
          padding: 'x'.repeat(16 * 1024),
        }),
      ).toThrow();
      ws.serializeAttachment(attachment);
    });
  });

  it.each<[string, unknown]>([
    ['an empty id', ''],
    ['an id that is too long', 'x'.repeat(MAX_SUBSCRIPTION_ID_LENGTH + 1)],
    ['a numeric id', 1],
    ['a missing id', undefined],
  ])('refuses %s with a NOTICE', async (_case, subscriptionId) => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const message =
      subscriptionId === undefined
        ? ['REQ']
        : ['REQ', subscriptionId, responseFilter(relay, randomKey().pubkey)];
    socket.send(message);
    expect(await socket.next()).toEqual([
      'NOTICE',
      'invalid: malformed REQ message',
    ]);
    expect(await attachments(relay.hub)).toEqual([null]);
  });

  it(`accepts subscription ids of up to ${MAX_SUBSCRIPTION_ID_LENGTH} characters`, async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const id = 'x'.repeat(MAX_SUBSCRIPTION_ID_LENGTH);
    expect(
      await req(socket, id, responseFilter(relay, randomKey().pubkey)),
    ).toEqual(['EOSE', id]);
  });

  it('refuses every REQ while REMOTE_SIGNER_PRIVATE_KEY is invalid', async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    await req(socket, 'kept', responseFilter(relay, randomKey().pubkey));
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    await configureHub(relay, { REMOTE_SIGNER_PRIVATE_KEY: 'not a key' });
    expect(
      await req(socket, 'kept', responseFilter(relay, randomKey().pubkey)),
    ).toEqual(closed('kept', 'error: server configuration error'));
    expect(log.mock.calls).toEqual([
      [
        'REMOTE_SIGNER_PRIVATE_KEY must be set to an nsec or a 64-character hex private key',
      ],
    ]);
    expect(await attachments(relay.hub)).toEqual([{ subscriptions: [] }]);
  });
});

describe('CLOSE', () => {
  it('removes only the subscription of that connection', async () => {
    const relay = await relayDeployment();
    const [one, two] = [await openSocket(relay), await openSocket(relay)];
    const client = randomKey().pubkey;
    await req(one, 'sub', responseFilter(relay, client));
    await req(one, 'kept', responseFilter(relay, client));
    await req(two, 'sub', responseFilter(relay, client));

    one.send(['CLOSE', 'sub']);
    expect(await one.drain()).toEqual([]);
    expect(await attachments(relay.hub)).toEqual(
      sorted([
        {
          subscriptions: [
            { id: 'kept', filters: [storedFilter(relay, [client])] },
          ],
        },
        {
          subscriptions: [
            { id: 'sub', filters: [storedFilter(relay, [client])] },
          ],
        },
      ]),
    );
  });

  it('ignores an unknown subscription id', async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    socket.send(['CLOSE', 'unknown']);
    expect(await socket.drain()).toEqual([]);
    expect(await attachments(relay.hub)).toEqual([null]);
  });

  it('ends delivery to the subscription', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const watcher = await openSocket(relay);
    await req(watcher, 'watch', responseFilter(relay, client.pubkey));
    watcher.send(['CLOSE', 'watch']);
    expect(await watcher.drain()).toEqual([]);
    expect(await client.result('ping')).toBe('pong');
    expect(await watcher.drain()).toEqual([]);
  });
});

describe('live delivery', () => {
  it('sends a response to every matching subscription, once each', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    await client.subscribe('second');
    const other = await openSocket(relay);
    await req(other, 'mine', responseFilter(relay, client.pubkey));
    await req(other, 'unrelated', responseFilter(relay, randomKey().pubkey));

    const request = client.request('ping', []);
    client.socket.send(['EVENT', request]);
    expect(await client.socket.next()).toEqual(['OK', request.id, true, '']);
    const delivered = [await client.socket.next(), await client.socket.next()];
    expect(delivered).toEqual([
      ['EVENT', 'nip46', expect.anything()],
      ['EVENT', 'second', expect.anything()],
    ]);
    const [, , response] = delivered[0] as [string, string, unknown];
    expect(delivered[1]).toEqual(['EVENT', 'second', response]);
    expect(await other.drain()).toEqual([['EVENT', 'mine', response]]);
    expect(await client.socket.drain()).toEqual([]);
  });

  it('sends nothing to subscriptions that do not match', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const other = await openSocket(relay);
    const now = Math.floor(Date.now() / 1000);
    await req(
      other,
      'another-client',
      responseFilter(relay, randomKey().pubkey),
    );
    await req(other, 'future', {
      ...responseFilter(relay, client.pubkey),
      since: now + 3600,
    });
    await req(other, 'past', {
      ...responseFilter(relay, client.pubkey),
      until: now - 3600,
    });
    expect(await client.result('ping')).toBe('pong');
    expect(await other.drain()).toEqual([]);
  });

  // NIP-01: an event matches when since <= created_at <= until, also when
  // either bound is 0.
  it.each<[string, Partial<Filter>, boolean]>([
    ['until before created_at', { until: 99 }, false],
    ['until at created_at', { until: 100 }, true],
    ['until after created_at', { until: 101 }, true],
    ['until 0', { until: 0 }, false],
    ['since before created_at', { since: 99 }, true],
    ['since at created_at', { since: 100 }, true],
    ['since after created_at', { since: 101 }, false],
    ['since 0', { since: 0 }, true],
  ])(
    'applies %s to a response created at 100',
    async (_case, bound, delivered) => {
      const relay = await relayDeployment();
      const { client } = await connectedClient(relay);
      const watcher = await openSocket(relay);
      await req(watcher, 'bounded', {
        ...responseFilter(relay, client.pubkey),
        ...bound,
      });
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(100_000);
      const { event } = await client.send(client.request('ping', []));
      expect(event.created_at).toBe(100);
      expect(await watcher.drain()).toEqual(
        delivered ? [['EVENT', 'bounded', event]] : [],
      );
    },
  );

  it('keeps delivering to the subscriptions of a hibernated connection', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const watcher = await openSocket(relay);
    await req(watcher, 'watch', responseFilter(relay, client.pubkey));

    await evictDurableObject(relay.hub);
    await configureHub(relay);
    const request = client.request('ping', []);
    const { event } = await client.send(request);
    expect(await watcher.drain()).toEqual([['EVENT', 'watch', event]]);
  });

  it('does not let a failing connection keep the response from others', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const broken = await openSocket(relay);
    await req(broken, 'broken', responseFilter(relay, client.pubkey));
    const isBroken = (ws: WebSocket) =>
      subscriptionsOf(ws.deserializeAttachment()).some(
        ({ id }) => id === 'broken',
      );
    // The failing connection is delivered to first.
    const ordered = await runInDurableObject(relay.hub, (_instance, state) => {
      const getWebSockets = state.getWebSockets.bind(state);
      return vi
        .spyOn(state, 'getWebSockets')
        .mockImplementation((tag) =>
          getWebSockets(tag).sort(
            (a, b) => Number(isBroken(b)) - Number(isBroken(a)),
          ),
        );
    });
    const send = WebSocket.prototype.send;
    const failed = vi
      .spyOn(WebSocket.prototype, 'send')
      .mockImplementation(function (this: WebSocket, message) {
        let fails = false;
        try {
          fails = isBroken(this);
        } catch {
          // Not a SignerHub WebSocket.
        }
        if (fails) {
          throw new Error('send failed');
        }
        send.call(this, message);
      });
    expect(await client.result('ping')).toBe('pong');
    expect(ordered).toHaveBeenCalled();
    expect(
      failed.mock.contexts.filter((ws) => {
        try {
          return isBroken(ws as WebSocket);
        } catch {
          return false;
        }
      }),
    ).toHaveLength(1);
  });

  it('never stores events', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const request = client.request('ping', []);
    const { event } = await client.send(request);
    await runInDurableObject(relay.hub, (_instance, state) => {
      const values = JSON.stringify(
        allStoredValues(state.storage.sql).map((value) =>
          value instanceof ArrayBuffer ? [...new Uint8Array(value)] : value,
        ),
      );
      for (const stored of [
        request.id,
        request.content,
        event.id,
        event.content,
      ]) {
        expect(values).not.toContain(stored);
      }
    });
    // A later subscription gets no history.
    const late = await openSocket(relay);
    expect(
      await req(late, 'late', responseFilter(relay, client.pubkey)),
    ).toEqual(['EOSE', 'late']);
    expect(await late.drain()).toEqual([]);
  });

  it('does not relay request events to subscribers', async () => {
    const relay = await relayDeployment();
    const watcher = await openSocket(relay);
    // The closest a filter may come to request events: they p-tag the remote
    // signer but are authored by clients.
    await req(
      watcher,
      'requests',
      responseFilter(relay, relay.remoteSigner.pubkey),
    );
    const { client } = await connectedClient(relay);
    expect(await client.result('ping')).toBe('pong');
    expect(await watcher.drain()).toEqual([]);
  });
});

describe('incoming messages', () => {
  it.each<[string, string | ArrayBuffer, string]>([
    [
      'binary frames',
      new TextEncoder().encode('["REQ","sub",{}]').buffer as ArrayBuffer,
      'invalid: binary messages are not supported',
    ],
    ['malformed JSON', '["REQ", "sub",', 'invalid: malformed JSON'],
    ['an empty message', '', 'invalid: malformed JSON'],
    ['a JSON object', '{"type":"REQ"}', 'invalid: malformed message'],
    ['a JSON string', '"REQ"', 'invalid: malformed message'],
    ['an empty list', '[]', 'invalid: malformed message'],
    ['a numeric type', '[1, "sub"]', 'invalid: malformed message'],
    [
      'an unknown type',
      '["COUNT", "sub", {}]',
      'invalid: unsupported message type',
    ],
    [
      'a lowercase type',
      '["req", "sub", {}]',
      'invalid: unsupported message type',
    ],
    ['AUTH', '["AUTH", "challenge"]', 'invalid: unsupported message type'],
    ['EVENT without an event', '["EVENT"]', 'invalid: malformed EVENT message'],
    [
      'EVENT with an extra element',
      '["EVENT", {}, {}]',
      'invalid: malformed EVENT message',
    ],
    ['CLOSE without an id', '["CLOSE"]', 'invalid: malformed CLOSE message'],
    [
      'CLOSE with an extra element',
      '["CLOSE", "sub", "sub"]',
      'invalid: malformed CLOSE message',
    ],
    [
      'CLOSE with a numeric id',
      '["CLOSE", 1]',
      'invalid: malformed CLOSE message',
    ],
  ])('are refused with a NOTICE: %s', async (_case, message, reason) => {
    const relay = await relayDeployment();
    const logs = captureLogs();
    const socket = await openSocket(relay);
    socket.ws.send(message);
    expect(await socket.next()).toEqual(['NOTICE', reason]);
    expect(await socket.drain()).toEqual([]);
    expect(await attachments(relay.hub)).toEqual([null]);
    // Invalid input is not logged.
    for (const log of logs) {
      expect(log).not.toHaveBeenCalled();
    }
  });

  it(`are accepted up to ${MAX_MESSAGE_LENGTH} characters`, async () => {
    const relay = await relayDeployment();
    const socket = await openSocket(relay);
    const message = (padding: number) =>
      JSON.stringify([
        'REQ',
        'sub',
        responseFilter(relay, randomKey().pubkey),
      ]).replace(/^\[/, `[${' '.repeat(padding)}`);
    const base = message(0).length;
    socket.ws.send(message(MAX_MESSAGE_LENGTH - base));
    expect(await socket.next()).toEqual(['EOSE', 'sub']);
    socket.ws.send(message(MAX_MESSAGE_LENGTH - base + 1));
    expect(await socket.next()).toEqual([
      'NOTICE',
      'invalid: message too large',
    ]);
    expect(await socket.drain()).toEqual([]);
  });

  it('refuses an oversized EVENT before decrypting it', async () => {
    const relay = await relayDeployment();
    const { client } = await connectedClient(relay);
    const event = client.rawRequest(
      client.encrypt('x'.repeat(MAX_MESSAGE_LENGTH)),
    );
    client.socket.send(['EVENT', event]);
    expect(await client.socket.next()).toEqual([
      'NOTICE',
      'invalid: message too large',
    ]);
    expect(await client.socket.drain()).toEqual([]);
  });
});
