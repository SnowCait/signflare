import { decode, npubEncode } from 'nostr-tools/nip19';
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import { hexToBytes } from 'nostr-tools/utils';
import type { ApiFetch, ApiRequestInit } from '../../admin/lib/api';
import type { Nip07Signer } from '../../admin/lib/nip98';
import type { ClientSession, Identity } from '../../admin/lib/types';
import { parseNip98Authorization, verifyNip98Event } from '../../src/nip98';
import { randomKey, type TestKey } from '../nostr-helpers';

// An in-memory stand-in for the Admin API (src/admin-api.ts), for testing
// the Admin SPA's logic outside a browser. Login headers are checked with
// the server's own NIP-98 validation.

export const ORIGIN = 'https://signflare.example';
export const PAGE_URL = `${ORIGIN}/admin/`;
export const LOGIN_URL = `${ORIGIN}/admin/api/login`;
export const SESSION_EXPIRES_AT = 1_800_043_200;
export const DATABASE_SIZE = 81_920;

export interface RecordedRequest extends ApiRequestInit {
  readonly url: string;
}

type Interceptor = (
  request: RecordedRequest,
) => Response | Promise<Response> | undefined;

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export function apiError(status: number, error: string): Response {
  return json({ error }, status);
}

// A NIP-07 signer for `key`, as a browser extension provides it.
export function nip07Signer(key: TestKey): Nip07Signer {
  return {
    signEvent: async (template) =>
      JSON.parse(JSON.stringify(finalizeEvent({ ...template }, key.secretKey))),
  };
}

export function clientSession(
  clientPubkey: string,
  overrides: Partial<ClientSession> = {},
): ClientSession {
  return {
    clientPubkey,
    permissions: ['sign_event:1', 'nip44_encrypt'],
    clientMetadata: { name: 'Client', url: null, image: null },
    createdAt: 1_800_000_100,
    lastUsedAt: 1_800_000_200,
    ...overrides,
  };
}

// A promise and the functions that settle it.
export function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

export class FakeAdminServer {
  readonly admin = randomKey();
  readonly requests: RecordedRequest[] = [];
  signedIn = false;
  identities: Identity[] = [];
  readonly sessions = new Map<string, ClientSession[]>();
  pairings = 0;
  now = 1_800_000_000;
  #interceptor: Interceptor | null = null;
  #pairingSecrets = 0;

  // Answers requests that `interceptor` returns a response for, instead of
  // the default behavior.
  intercept(interceptor: Interceptor | null): void {
    this.#interceptor = interceptor;
  }

  readonly fetch: ApiFetch = async (url, init) => {
    const request: RecordedRequest = { url, ...init };
    this.requests.push(request);
    return (await this.#interceptor?.(request)) ?? this.#handle(request);
  };

  // Requests matching the method and path, which is relative to ORIGIN.
  requestsTo(method: string, path: string): RecordedRequest[] {
    return this.requests.filter(
      (request) =>
        request.method === method &&
        new URL(request.url, ORIGIN).pathname === path,
    );
  }

  addIdentity(key: TestKey = randomKey()): Identity {
    const identity = identityOf(key.pubkey, this.now);
    this.identities = [...this.identities, identity];
    return identity;
  }

  async #handle(request: RecordedRequest): Promise<Response> {
    const url = new URL(request.url, ORIGIN);
    const route = `${request.method} ${url.pathname}`;
    if (route === 'POST /admin/api/login') {
      return this.#login(request);
    }
    if (!this.signedIn) {
      return apiError(401, 'unauthorized');
    }
    if (route === 'GET /admin/api/session') {
      return json({ pubkey: this.admin.pubkey, expiresAt: SESSION_EXPIRES_AT });
    }
    if (route === 'POST /admin/api/logout') {
      this.signedIn = false;
      return new Response(null, { status: 204 });
    }
    if (route === 'GET /admin/api/status') {
      return json({
        identities: this.identities.length,
        sessions: [...this.sessions.values()].flat().length,
        pairings: this.pairings,
        databaseSize: DATABASE_SIZE,
      });
    }
    if (route === 'GET /admin/api/identities') {
      return json(this.identities);
    }
    if (route === 'POST /admin/api/identities') {
      return this.#register(request.body);
    }
    const identityRoute =
      /^(GET|POST|DELETE) \/admin\/api\/identities\/([0-9a-f]{64})(\/pairings|\/sessions)?$/.exec(
        route,
      );
    if (identityRoute !== null) {
      const [, method, pubkey, resource] = identityRoute;
      if (!this.identities.some((identity) => identity.pubkey === pubkey)) {
        return apiError(404, 'not found');
      }
      if (method === 'DELETE' && resource === undefined) {
        this.identities = this.identities.filter(
          (identity) => identity.pubkey !== pubkey,
        );
        this.sessions.delete(pubkey);
        return new Response(null, { status: 204 });
      }
      if (method === 'POST' && resource === '/pairings') {
        this.pairings += 1;
        this.#pairingSecrets += 1;
        const secret = this.#pairingSecrets.toString(16).padStart(64, '0');
        return json(
          {
            bunkerUrl: `bunker://${'e'.repeat(64)}?relay=wss%3A%2F%2Fsignflare.example%2F&secret=${secret}`,
            expiresAt: this.now + 600,
          },
          201,
        );
      }
      if (method === 'GET' && resource === '/sessions') {
        return json(this.sessions.get(pubkey) ?? []);
      }
    }
    const sessionRoute = /^DELETE \/admin\/api\/sessions\/([0-9a-f]{64})$/.exec(
      route,
    );
    if (sessionRoute !== null) {
      for (const [pubkey, sessions] of this.sessions) {
        const remaining = sessions.filter(
          (session) => session.clientPubkey !== sessionRoute[1],
        );
        if (remaining.length < sessions.length) {
          this.sessions.set(pubkey, remaining);
          return new Response(null, { status: 204 });
        }
      }
      return apiError(404, 'not found');
    }
    return apiError(404, 'not found');
  }

  async #login(request: RecordedRequest): Promise<Response> {
    if (request.url !== LOGIN_URL || request.body !== undefined) {
      return apiError(401, 'unauthorized');
    }
    try {
      const event = parseNip98Authorization(request.headers.Authorization);
      await verifyNip98Event(event, {
        url: request.url,
        method: request.method,
        body: new Uint8Array(),
        pubkey: this.admin.pubkey,
        now: Math.floor(Date.now() / 1000),
      });
    } catch {
      return apiError(401, 'unauthorized');
    }
    this.signedIn = true;
    return json({ pubkey: this.admin.pubkey, expiresAt: SESSION_EXPIRES_AT });
  }

  #register(body: string | undefined): Response {
    let privateKey: unknown;
    try {
      privateKey = JSON.parse(body ?? '').privateKey;
    } catch {
      return apiError(400, 'invalid request');
    }
    const pubkey = typeof privateKey === 'string' ? pubkeyOf(privateKey) : null;
    if (pubkey === null) {
      return apiError(400, 'invalid private key');
    }
    if (this.identities.some((identity) => identity.pubkey === pubkey)) {
      return apiError(409, 'identity already exists');
    }
    const identity = identityOf(pubkey, this.now);
    this.identities = [...this.identities, identity];
    return json(identity, 201);
  }
}

function identityOf(pubkey: string, now: number): Identity {
  return { pubkey, npub: npubEncode(pubkey), createdAt: now, updatedAt: now };
}

function pubkeyOf(privateKey: string): string | null {
  const value = privateKey.trim();
  try {
    if (/^[0-9a-fA-F]{64}$/.test(value)) {
      return getPublicKey(hexToBytes(value));
    }
    const decoded = decode(value);
    return decoded.type === 'nsec' ? getPublicKey(decoded.data) : null;
  } catch {
    return null;
  }
}
