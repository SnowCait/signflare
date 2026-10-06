import { runInDurableObject } from 'cloudflare:test';
import { AbstractSimplePool } from 'nostr-tools/abstract-pool';
import { ShortTextNote } from 'nostr-tools/kinds';
import * as nip04 from 'nostr-tools/nip04';
import { nsecEncode } from 'nostr-tools/nip19';
import * as nip44 from 'nostr-tools/nip44';
import {
  BunkerSigner,
  type BunkerPointer,
  parseBunkerInput,
} from 'nostr-tools/nip46';
import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { afterEach, describe, expect, it } from 'vitest';
import app from '../src/index';
import type { PairingPermissionsInput } from '../src/pairings';
import {
  LOGIN_URL,
  nostrAuthorization,
  ORIGIN,
  randomKey,
  signHttpAuthEvent,
  type TestKey,
  unixNow,
} from './nostr-helpers';
import { type Relay, relayDeployment } from './relay-helpers';

// End-to-end compatibility with the NIP-46 client of nostr-tools
// (docs/design.md §39.12): an administrator creates a pairing through the
// Admin API, and BunkerSigner uses its bunker:// token over WebSockets to
// the Worker.

interface Deployment {
  readonly relay: Relay;
  // The Worker env, with the same REMOTE_SIGNER_PRIVATE_KEY as the SignerHub.
  readonly env: Env;
  readonly admin: TestKey;
}

async function deployment(): Promise<Deployment> {
  const relay = await relayDeployment();
  const admin = randomKey();
  return {
    relay,
    admin,
    env: {
      ...relay.env,
      ADMIN_PUBKEY: admin.pubkey,
      REMOTE_SIGNER_PRIVATE_KEY: nsecEncode(relay.remoteSigner.secretKey),
    },
  };
}

// The Admin API, as the administrator's browser uses it.
async function adminRequest(
  d: Deployment,
  path: string,
  init: RequestInit & { cookie?: string } = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set('Origin', ORIGIN);
  if (init.cookie !== undefined) {
    headers.set('Cookie', init.cookie);
  }
  return app.fetch(
    new Request(`${ORIGIN}${path}`, { ...init, headers }),
    d.env,
  );
}

async function logIn(d: Deployment): Promise<string> {
  const response = await adminRequest(d, '/admin/api/login', {
    method: 'POST',
    headers: { Authorization: nostrAuthorization(signHttpAuthEvent(d.admin)) },
  });
  expect(response.status).toBe(200);
  expect(new URL(LOGIN_URL).origin).toBe(ORIGIN);
  const [cookie] = response.headers.getSetCookie();
  return cookie.split(';')[0];
}

// Registers an identity and creates a pairing for it through the Admin API.
async function bunkerUrl(
  d: Deployment,
  identity: TestKey,
  permissions: PairingPermissionsInput = 'all',
): Promise<string> {
  const cookie = await logIn(d);
  const registered = await adminRequest(d, '/admin/api/identities', {
    method: 'POST',
    cookie,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ privateKey: nsecEncode(identity.secretKey) }),
  });
  expect(registered.status).toBe(201);
  const created = await adminRequest(
    d,
    `/admin/api/identities/${identity.pubkey}/pairings`,
    {
      method: 'POST',
      cookie,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ permissions }),
    },
  );
  expect(created.status).toBe(201);
  const { bunkerUrl } = await created.json<{ bunkerUrl: string }>();
  return bunkerUrl;
}

// The WebSocket a browser would give nostr-tools, opened by a WebSocket
// upgrade request to the Worker under test.
function workerWebSocket(workerEnv: Env) {
  return class WorkerWebSocket {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSING = 2;
    static readonly CLOSED = 3;

    readyState = WorkerWebSocket.CONNECTING;
    onopen: (() => void) | null = null;
    onmessage: ((event: MessageEvent) => void) | null = null;
    onclose: ((event: CloseEvent) => void) | null = null;
    onerror: ((event: Event) => void) | null = null;
    private socket: WebSocket | null = null;

    constructor(readonly url: string) {
      void this.open();
    }

    private async open(): Promise<void> {
      const response = await app.fetch(
        new Request(this.url.replace(/^ws/, 'http'), {
          headers: { Upgrade: 'websocket' },
        }),
        workerEnv,
      );
      const socket = response.webSocket;
      if (socket === null) {
        this.readyState = WorkerWebSocket.CLOSED;
        this.onerror?.(new Event('error'));
        return;
      }
      socket.accept();
      socket.addEventListener('message', (event) => this.onmessage?.(event));
      socket.addEventListener('close', (event) => {
        this.readyState = WorkerWebSocket.CLOSED;
        this.onclose?.(event);
      });
      this.socket = socket;
      this.readyState = WorkerWebSocket.OPEN;
      this.onopen?.();
    }

    // Like a browser, drops messages sent once the connection is closing.
    send(data: string): void {
      if (this.readyState === WorkerWebSocket.OPEN) {
        this.socket?.send(data);
      }
    }

    close(): void {
      this.readyState = WorkerWebSocket.CLOSING;
      this.socket?.close(1000);
    }
  };
}

const pools: AbstractSimplePool[] = [];

function signerFor(
  d: Deployment,
  clientSecretKey: Uint8Array,
  pointer: BunkerPointer,
): BunkerSigner {
  const pool = new AbstractSimplePool({
    verifyEvent,
    websocketImplementation: workerWebSocket(
      d.env,
    ) as unknown as typeof WebSocket,
    maxWaitForConnection: 3000,
  });
  pools.push(pool);
  return BunkerSigner.fromBunker(clientSecretKey, pointer, { pool });
}

afterEach(() => {
  for (const pool of pools.splice(0)) {
    pool.destroy();
  }
});

describe('nostr-tools BunkerSigner', () => {
  it('connects with a bunker:// token, gets the public key, signs, and logs out', async () => {
    const d = await deployment();
    const identity = randomKey();
    const pointer = await parseBunkerInput(await bunkerUrl(d, identity));
    if (pointer === null) {
      throw new Error('bunker URL not parsed');
    }
    expect(pointer.pubkey).toBe(d.relay.remoteSigner.pubkey);
    const clientSecretKey = generateSecretKey();
    const signer = signerFor(d, clientSecretKey, pointer);

    await signer.connect({
      name: 'nostr-tools',
      url: 'https://github.com/nbd-wtf/nostr-tools',
    });
    const session = await d.relay.hub.getSession(getPublicKey(clientSecretKey));
    expect(session).toMatchObject({
      identityPubkey: identity.pubkey,
      clientMetadata: {
        name: 'nostr-tools',
        url: 'https://github.com/nbd-wtf/nostr-tools',
        image: null,
      },
    });

    expect(await signer.getPublicKey()).toBe(identity.pubkey);

    const template = {
      kind: ShortTextNote,
      content: 'Signed through Signflare',
      tags: [['t', 'signflare']],
      created_at: unixNow(),
    };
    const signed = await signer.signEvent(template);
    expect(signed).toMatchObject({ ...template, pubkey: identity.pubkey });
    expect(verifyEvent(JSON.parse(JSON.stringify(signed)))).toBe(true);

    await signer.logout();
    expect(
      await d.relay.hub.getSession(getPublicKey(clientSecretKey)),
    ).toBeNull();
  });

  it('pings, switches no relays, and encrypts and decrypts with NIP-04 and NIP-44', async () => {
    const d = await deployment();
    const identity = randomKey();
    const pointer = (await parseBunkerInput(
      await bunkerUrl(d, identity),
    )) as BunkerPointer;
    const signer = signerFor(d, generateSecretKey(), pointer);
    await signer.connect();

    await expect(signer.ping()).resolves.toBeUndefined();
    expect(await signer.switchRelays()).toBe(false);

    const thirdParty = randomKey();
    const nip04Ciphertext = await signer.nip04Encrypt(
      thirdParty.pubkey,
      'NIP-04 text',
    );
    expect(
      nip04.decrypt(thirdParty.secretKey, identity.pubkey, nip04Ciphertext),
    ).toBe('NIP-04 text');
    expect(
      await signer.nip04Decrypt(
        thirdParty.pubkey,
        nip04.encrypt(thirdParty.secretKey, identity.pubkey, 'NIP-04 reply'),
      ),
    ).toBe('NIP-04 reply');

    const conversationKey = nip44.getConversationKey(
      thirdParty.secretKey,
      identity.pubkey,
    );
    const nip44Payload = await signer.nip44Encrypt(
      thirdParty.pubkey,
      'NIP-44 text',
    );
    expect(nip44.decrypt(nip44Payload, conversationKey)).toBe('NIP-44 text');
    expect(
      await signer.nip44Decrypt(
        thirdParty.pubkey,
        nip44.encrypt('NIP-44 reply', conversationKey),
      ),
    ).toBe('NIP-44 reply');
  });

  it('reuses the session after a restart without connecting again', async () => {
    const d = await deployment();
    const identity = randomKey();
    const pointer = (await parseBunkerInput(
      await bunkerUrl(d, identity),
    )) as BunkerPointer;
    const clientSecretKey = generateSecretKey();
    const first = signerFor(d, clientSecretKey, pointer);
    await first.connect();
    await first.close();
    for (const pool of pools.splice(0)) {
      pool.destroy();
    }

    // What a client persisted: its keypair, the remote-signer pubkey, and
    // the relay, but no longer the one-time secret.
    const restarted = signerFor(d, clientSecretKey, {
      ...pointer,
      secret: null,
    });
    expect(await restarted.getPublicKey()).toBe(identity.pubkey);
    const signed = await restarted.signEvent({
      kind: ShortTextNote,
      content: 'After a restart',
      tags: [],
      created_at: unixNow(),
    });
    expect(signed.pubkey).toBe(identity.pubkey);
    expect(
      await runInDurableObject(d.relay.hub, (_instance, state) =>
        state.storage.sql.exec('SELECT COUNT(*) AS count FROM sessions').one(),
      ),
    ).toEqual({ count: 1 });
  });

  it('receives NIP-46 errors as rejections', async () => {
    const d = await deployment();
    const identity = randomKey();
    const pointer = (await parseBunkerInput(
      await bunkerUrl(d, identity, ['sign_event:1']),
    )) as BunkerPointer;
    const signer = signerFor(d, generateSecretKey(), pointer);
    await signer.connect();
    await expect(
      signer.signEvent({
        kind: 7,
        content: '+',
        tags: [],
        created_at: unixNow(),
      }),
    ).rejects.toBe('permission denied');
    await expect(signer.nip44Encrypt(randomKey().pubkey, 'text')).rejects.toBe(
      'permission denied',
    );

    // Its secret was consumed by the first connect.
    const other = signerFor(d, generateSecretKey(), pointer);
    await expect(other.connect()).rejects.toBe('invalid secret');
    await expect(other.getPublicKey()).rejects.toBe('not connected');
  });
});
