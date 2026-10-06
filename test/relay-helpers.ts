import { env } from 'cloudflare:workers';
import { NostrConnect } from 'nostr-tools/kinds';
import { nsecEncode } from 'nostr-tools/nip19';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent, type NostrEvent } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';
import { expect } from 'vitest';
import type { SignflareBindings } from '../src/config';
import app from '../src/index';
import type { PairingPermissionsInput } from '../src/pairings';
import type { SignerHub } from '../src/signer-hub';
import { replaceHubEnv, TEST_MASTER_ENCRYPTION_KEY } from './hub-helpers';
import { ORIGIN, randomKey, type TestKey, unixNow } from './nostr-helpers';

export type Hub = DurableObjectStub<SignerHub>;

// How long a test waits for a relay message before failing.
const MESSAGE_TIMEOUT_MS = 4000;

// A message type the relay does not support, and the NOTICE it answers with.
const BARRIER = ['BARRIER'];
const BARRIER_NOTICE = ['NOTICE', 'invalid: unsupported message type'];

export interface Relay {
  readonly hub: Hub;
  // A Worker env whose SIGNER_HUB always resolves to `hub`.
  readonly env: SignflareBindings;
  // The test-only REMOTE_SIGNER_PRIVATE_KEY of the deployment, generated for
  // the test and distinct from every identity.
  readonly remoteSigner: TestKey;
}

// A deployment with a SignerHub of its own, configured with test-only
// secrets rather than anything from the local environment.
export async function relayDeployment(): Promise<Relay> {
  const hub = env.SIGNER_HUB.getByName(crypto.randomUUID());
  const relay: Relay = {
    hub,
    remoteSigner: randomKey(),
    env: {
      ...env,
      SIGNER_HUB: {
        getByName: () => hub,
      } as unknown as Env['SIGNER_HUB'],
    },
  };
  await configureHub(relay);
  return relay;
}

// The env of a SignerHub instance lasts only until the instance is evicted,
// so tests configure it again afterwards.
export function configureHub(
  relay: Relay,
  overrides: Record<string, unknown> = {},
): Promise<void> {
  return replaceHubEnv(relay.hub, (hubEnv) => ({
    ...hubEnv,
    REMOTE_SIGNER_PRIVATE_KEY: nsecEncode(relay.remoteSigner.secretKey),
    MASTER_ENCRYPTION_KEY: TEST_MASTER_ENCRYPTION_KEY,
    ...overrides,
  }));
}

// Registers a random identity through the SignerHub, encrypted with its
// configured MASTER_ENCRYPTION_KEY.
export async function registerIdentity(relay: Relay): Promise<TestKey> {
  const key = randomKey();
  const result = await relay.hub.registerIdentity(
    bytesToHex(key.secretKey),
    unixNow(),
  );
  if (result.status !== 'created') {
    throw new Error(`identity not registered: ${result.status}`);
  }
  return key;
}

export async function createPairing(
  relay: Relay,
  identity: string,
  permissions: PairingPermissionsInput = 'all',
  now = unixNow(),
): Promise<string> {
  const result = await relay.hub.createPairing(identity, permissions, now);
  if (result.status !== 'created') {
    throw new Error(`pairing not created: ${result.status}`);
  }
  return result.secret;
}

// The client end of a relay WebSocket, collecting every message it receives.
export class TestSocket {
  readonly received: unknown[] = [];
  private read = 0;
  private wake: (() => void) | null = null;
  readonly closed: Promise<CloseEvent>;

  constructor(readonly ws: WebSocket) {
    ws.accept();
    ws.addEventListener('message', (event) => {
      this.received.push(
        typeof event.data === 'string' ? JSON.parse(event.data) : event.data,
      );
      this.wake?.();
    });
    this.closed = new Promise((resolve) => {
      ws.addEventListener('close', (event) => {
        resolve(event);
        this.wake?.();
      });
    });
  }

  send(message: unknown): void {
    this.ws.send(
      typeof message === 'string' ? message : JSON.stringify(message),
    );
  }

  // The next message not returned before.
  async next(): Promise<unknown> {
    const deadline = Date.now() + MESSAGE_TIMEOUT_MS;
    while (this.read >= this.received.length) {
      if (this.ws.readyState === WebSocket.CLOSED) {
        throw new Error('socket closed');
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new Error('no relay message arrived');
      }
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, remaining);
        this.wake = () => {
          clearTimeout(timer);
          resolve();
        };
      });
      this.wake = null;
    }
    return this.received[this.read++];
  }

  // Returns, and consumes, every message the relay sent before it answered a
  // barrier message. The relay answers that without awaiting anything, so
  // the answers to earlier REQ and CLOSE messages, and events delivered by
  // requests already answered elsewhere, all come before it.
  async drain(): Promise<unknown[]> {
    this.send(BARRIER);
    const messages: unknown[] = [];
    for (;;) {
      const message = await this.next();
      if (JSON.stringify(message) === JSON.stringify(BARRIER_NOTICE)) {
        return messages;
      }
      messages.push(message);
    }
  }

  close(code = 1000): Promise<CloseEvent> {
    this.ws.close(code, 'test done');
    return this.closed;
  }
}

// Opens a WebSocket to the root of the deployment, as a client would.
export async function openSocket(relay: Relay): Promise<TestSocket> {
  const response = await app.fetch(
    new Request(`${ORIGIN}/`, { headers: { Upgrade: 'websocket' } }),
    relay.env,
  );
  expect(response.status).toBe(101);
  if (response.webSocket === null) {
    throw new Error('no WebSocket');
  }
  return new TestSocket(response.webSocket);
}

export interface Nip46Payload {
  readonly id: string;
  readonly result: string;
  readonly error?: string;
}

// The filter a NIP-46 client subscribes to its responses with.
export function responseFilter(relay: Relay, clientPubkey: string) {
  return {
    kinds: [NostrConnect],
    authors: [relay.remoteSigner.pubkey],
    '#p': [clientPubkey],
  };
}

// A NIP-46 client speaking to the relay with its own client keypair.
export class TestClient {
  readonly key: TestKey;
  // The subscription that responses are expected on.
  subscriptionId = 'nip46';
  private serial = 0;

  constructor(
    readonly relay: Relay,
    readonly socket: TestSocket,
    key: TestKey = randomKey(),
  ) {
    this.key = key;
  }

  get pubkey(): string {
    return this.key.pubkey;
  }

  async subscribe(subscriptionId = this.subscriptionId): Promise<void> {
    this.subscriptionId = subscriptionId;
    this.socket.send([
      'REQ',
      subscriptionId,
      { ...responseFilter(this.relay, this.pubkey), limit: 0 },
    ]);
    expect(await this.socket.next()).toEqual(['EOSE', subscriptionId]);
  }

  // A signed request event carrying `content` as given.
  rawRequest(
    content: string,
    overrides: Partial<Omit<NostrEvent, 'id' | 'sig' | 'pubkey'>> = {},
  ): NostrEvent {
    const event = finalizeEvent(
      {
        kind: NostrConnect,
        created_at: unixNow(),
        tags: [['p', this.relay.remoteSigner.pubkey]],
        content,
        ...overrides,
      },
      this.key.secretKey,
    );
    // Round-tripped through JSON so that it carries no verification flag.
    return JSON.parse(JSON.stringify(event));
  }

  encrypt(plaintext: string): string {
    return nip44.encrypt(
      plaintext,
      nip44.getConversationKey(
        this.key.secretKey,
        this.relay.remoteSigner.pubkey,
      ),
    );
  }

  request(
    method: string,
    params: readonly unknown[],
    id = `request-${++this.serial}`,
  ): NostrEvent {
    return this.rawRequest(
      this.encrypt(JSON.stringify({ id, method, params })),
    );
  }

  // Decrypts a response event addressed to this client.
  open(event: NostrEvent): Nip46Payload {
    return JSON.parse(
      nip44.decrypt(
        event.content,
        nip44.getConversationKey(this.key.secretKey, event.pubkey),
      ),
    );
  }

  // Publishes `event`, expects the relay to accept it, and returns the
  // response delivered to the subscription.
  async send(
    event: NostrEvent,
    subscriptionId = this.subscriptionId,
  ): Promise<{ readonly event: NostrEvent; readonly payload: Nip46Payload }> {
    this.socket.send(['EVENT', event]);
    expect(await this.socket.next()).toEqual(['OK', event.id, true, '']);
    const message = await this.socket.next();
    expect(message).toEqual(['EVENT', subscriptionId, expect.anything()]);
    const response = (message as [string, string, NostrEvent])[2];
    return { event: response, payload: this.open(response) };
  }

  async call(
    method: string,
    params: readonly unknown[] = [],
  ): Promise<Nip46Payload> {
    return (await this.send(this.request(method, params))).payload;
  }

  // Calls `method` and returns its result, failing on an error response.
  async result(
    method: string,
    params: readonly unknown[] = [],
  ): Promise<string> {
    const payload = await this.call(method, params);
    expect(payload.error).toBeUndefined();
    return payload.result;
  }

  async connect(secret: string, ...rest: string[]): Promise<Nip46Payload> {
    return this.call('connect', [
      this.relay.remoteSigner.pubkey,
      secret,
      ...rest,
    ]);
  }
}

// A client with a subscription on a new connection.
export async function subscribedClient(
  relay: Relay,
  key?: TestKey,
): Promise<TestClient> {
  const client = new TestClient(relay, await openSocket(relay), key);
  await client.subscribe();
  return client;
}

// A client with an established session for a new identity.
export async function connectedClient(
  relay: Relay,
  permissions: PairingPermissionsInput = 'all',
): Promise<{ readonly client: TestClient; readonly identity: TestKey }> {
  const identity = await registerIdentity(relay);
  const client = await subscribedClient(relay);
  const secret = await createPairing(relay, identity.pubkey, permissions);
  expect(await client.connect(secret)).toEqual({
    id: expect.any(String),
    result: 'ack',
  });
  return { client, identity };
}
