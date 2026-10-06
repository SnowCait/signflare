import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AdminApi,
  ApiError,
  type ApiFetch,
  type ApiRequestInit,
} from '../../admin/lib/api';
import { apiError, json, LOGIN_URL, ORIGIN } from './fake-server';

const PUBKEY = 'a'.repeat(64);
const CLIENT = 'c'.repeat(64);
const NPUB = `npub1${'q'.repeat(58)}`;

const SESSION = { pubkey: PUBKEY, expiresAt: 1_800_043_200 };
const STATUS = { identities: 1, sessions: 2, pairings: 3, databaseSize: 4096 };
const IDENTITY = {
  pubkey: PUBKEY,
  npub: NPUB,
  createdAt: 1_800_000_000,
  updatedAt: 1_800_000_000,
};
const CLIENT_SESSION = {
  clientPubkey: CLIENT,
  permissions: ['sign_event'],
  clientMetadata: {
    name: '<b>Client</b>',
    url: null,
    image: 'https://x.example/i.png',
  },
  createdAt: 1_800_000_100,
  lastUsedAt: 1_800_000_200,
};
const PAIRING = {
  bunkerUrl: `bunker://${'e'.repeat(64)}?relay=wss%3A%2F%2Fsignflare.example%2F&secret=${'5'.repeat(64)}`,
  expiresAt: 1_800_000_600,
};

interface Recorded extends ApiRequestInit {
  readonly url: string;
}

function client(respond: (request: Recorded) => Response | Promise<Response>) {
  const requests: Recorded[] = [];
  const onUnauthorized = vi.fn();
  const fetch: ApiFetch = async (url, init) => {
    const request = { url, ...init };
    requests.push(request);
    return respond(request);
  };
  return {
    api: new AdminApi({ fetch, onUnauthorized }),
    requests,
    onUnauthorized,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('AdminApi requests', () => {
  it.each<
    [
      string,
      (api: AdminApi) => Promise<unknown>,
      string,
      string,
      string | undefined,
      Response,
    ]
  >([
    [
      'getSession',
      (api) => api.getSession(),
      'GET',
      '/admin/api/session',
      undefined,
      json(SESSION),
    ],
    [
      'login',
      (api) => api.login(LOGIN_URL, 'Nostr e30='),
      'POST',
      LOGIN_URL,
      undefined,
      json(SESSION),
    ],
    [
      'logout',
      (api) => api.logout(),
      'POST',
      '/admin/api/logout',
      undefined,
      new Response(null, { status: 204 }),
    ],
    [
      'getStatus',
      (api) => api.getStatus(),
      'GET',
      '/admin/api/status',
      undefined,
      json(STATUS),
    ],
    [
      'listIdentities',
      (api) => api.listIdentities(),
      'GET',
      '/admin/api/identities',
      undefined,
      json([IDENTITY]),
    ],
    [
      'registerIdentity',
      (api) => api.registerIdentity('nsec1example'),
      'POST',
      '/admin/api/identities',
      '{"privateKey":"nsec1example"}',
      json(IDENTITY, 201),
    ],
    [
      'deleteIdentity',
      (api) => api.deleteIdentity(PUBKEY),
      'DELETE',
      `/admin/api/identities/${PUBKEY}`,
      undefined,
      new Response(null, { status: 204 }),
    ],
    [
      'createPairing',
      (api) => api.createPairing(PUBKEY, ['sign_event:1', 'nip44_encrypt']),
      'POST',
      `/admin/api/identities/${PUBKEY}/pairings`,
      '{"permissions":["sign_event:1","nip44_encrypt"]}',
      json(PAIRING, 201),
    ],
    [
      'createPairing with all',
      (api) => api.createPairing(PUBKEY, 'all'),
      'POST',
      `/admin/api/identities/${PUBKEY}/pairings`,
      '{"permissions":"all"}',
      json(PAIRING, 201),
    ],
    [
      'listSessions',
      (api) => api.listSessions(PUBKEY),
      'GET',
      `/admin/api/identities/${PUBKEY}/sessions`,
      undefined,
      json([CLIENT_SESSION]),
    ],
    [
      'revokeSession',
      (api) => api.revokeSession(CLIENT),
      'DELETE',
      `/admin/api/sessions/${CLIENT}`,
      undefined,
      new Response(null, { status: 204 }),
    ],
  ])('%s', async (_name, call, method, url, body, response) => {
    const { api, requests } = client(() => response);
    await call(api);
    expect(requests).toHaveLength(1);
    const [request] = requests;
    expect(request).toMatchObject({
      url,
      method,
      body,
      credentials: 'same-origin',
      cache: 'no-store',
    });
    // Relative to the page, or the absolute login URL of the page's origin.
    expect(new URL(request.url, ORIGIN).origin).toBe(ORIGIN);
    expect(request.headers['Content-Type']).toBe(
      body === undefined ? undefined : 'application/json',
    );
  });

  it('encodes path parameters', async () => {
    const { api, requests } = client(() => new Response(null, { status: 204 }));
    await api.revokeSession('../identities?x=1');
    expect(requests[0].url).toBe('/admin/api/sessions/..%2Fidentities%3Fx%3D1');
  });

  it('sends Authorization only with the login request and never a cookie', async () => {
    const { api, requests } = client((request) =>
      request.url === LOGIN_URL || request.url.endsWith('/session')
        ? json(SESSION)
        : request.url.endsWith('/status')
          ? json(STATUS)
          : json([]),
    );
    await api.login(LOGIN_URL, 'Nostr e30=');
    await api.getSession();
    await api.getStatus();
    await api.listIdentities();
    expect(requests.map((request) => request.headers.Authorization)).toEqual([
      'Nostr e30=',
      undefined,
      undefined,
      undefined,
    ]);
    for (const request of requests) {
      expect(
        Object.keys(request.headers).map((name) => name.toLowerCase()),
      ).not.toContain('cookie');
    }
  });
});

describe('AdminApi 401 handling', () => {
  it.each<[string, (api: AdminApi) => Promise<unknown>]>([
    ['getSession', (api) => api.getSession()],
    ['logout', (api) => api.logout()],
    ['getStatus', (api) => api.getStatus()],
    ['listIdentities', (api) => api.listIdentities()],
    ['registerIdentity', (api) => api.registerIdentity('nsec1example')],
    ['deleteIdentity', (api) => api.deleteIdentity(PUBKEY)],
    ['createPairing', (api) => api.createPairing(PUBKEY, 'all')],
    ['listSessions', (api) => api.listSessions(PUBKEY)],
    ['revokeSession', (api) => api.revokeSession(CLIENT)],
  ])('ends the session when %s gets 401', async (_name, call) => {
    const { api, onUnauthorized } = client(() => apiError(401, 'unauthorized'));
    await expect(call(api)).rejects.toMatchObject({
      status: 401,
      code: 'unauthorized',
    });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it('treats 401 to the login request as a rejected login only', async () => {
    const { api, onUnauthorized } = client(() => apiError(401, 'unauthorized'));
    await expect(api.login(LOGIN_URL, 'Nostr e30=')).rejects.toMatchObject({
      status: 401,
    });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it('does not end the session for other errors', async () => {
    const { api, onUnauthorized } = client(() => apiError(403, 'forbidden'));
    await expect(api.getStatus()).rejects.toMatchObject({
      status: 403,
      code: 'forbidden',
    });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});

describe('AdminApi responses', () => {
  it('keeps only the documented fields', async () => {
    const { api } = client(() =>
      json({ ...SESSION, token: 'f'.repeat(64), tokenHash: 'ab' }),
    );
    expect(await api.getSession()).toStrictEqual(SESSION);
  });

  it('keeps identity fields only', async () => {
    const { api } = client(() =>
      json([{ ...IDENTITY, encryptedPrivateKey: 'x', iv: 'y', kdfSalt: 'z' }]),
    );
    expect(await api.listIdentities()).toStrictEqual([IDENTITY]);
  });

  it('keeps client metadata as given, as text', async () => {
    const { api } = client(() => json([CLIENT_SESSION]));
    expect(await api.listSessions(PUBKEY)).toStrictEqual([CLIENT_SESSION]);
  });

  it.each<[string, () => Response]>([
    [
      'a non-JSON body',
      () =>
        new Response('<!doctype html>', {
          headers: { 'Content-Type': 'text/html' },
        }),
    ],
    [
      'JSON with another content type',
      () => new Response(JSON.stringify(STATUS)),
    ],
    [
      'malformed JSON',
      () =>
        new Response('{', { headers: { 'Content-Type': 'application/json' } }),
    ],
    ['a missing field', () => json({ ...STATUS, databaseSize: undefined })],
    ['a negative count', () => json({ ...STATUS, sessions: -1 })],
    ['a fractional size', () => json({ ...STATUS, databaseSize: 1.5 })],
  ])('rejects %s', async (_case, response) => {
    const { api } = client(response);
    const error = await api.getStatus().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 200, code: null });
  });

  it.each<[string, () => Response]>([
    [
      'a malformed pubkey',
      () => json([{ ...IDENTITY, pubkey: 'A'.repeat(64) }]),
    ],
    ['a malformed npub', () => json([{ ...IDENTITY, npub: 'nsec1x' }])],
    ['an object instead of a list', () => json(IDENTITY)],
  ])('rejects an identity list with %s', async (_case, response) => {
    const { api } = client(response);
    await expect(api.listIdentities()).rejects.toMatchObject({
      status: 200,
      code: null,
    });
  });

  it('rejects a pairing that is not a bunker URL', async () => {
    const { api } = client(() =>
      json({ ...PAIRING, bunkerUrl: 'https://x.example/' }, 201),
    );
    await expect(api.createPairing(PUBKEY, 'all')).rejects.toMatchObject({
      status: 201,
      code: null,
    });
  });

  it('resolves endpoints without content on 204', async () => {
    const { api } = client(() => new Response(null, { status: 204 }));
    await expect(api.logout()).resolves.toBeUndefined();
    await expect(api.deleteIdentity(PUBKEY)).resolves.toBeUndefined();
    await expect(api.revokeSession(CLIENT)).resolves.toBeUndefined();
  });
});

describe('AdminApi errors', () => {
  it.each([
    [400, 'invalid private key'],
    [409, 'identity already exists'],
    [413, 'payload too large'],
    [500, 'server configuration error'],
    [507, 'insufficient storage'],
  ])('reads the error code of a %i response', async (status, code) => {
    const { api } = client(() => apiError(status, code));
    await expect(api.registerIdentity('nsec1example')).rejects.toMatchObject({
      status,
      code,
    });
  });

  it.each<[string, () => Response]>([
    ['an unknown code', () => apiError(400, 'nsec1secretvalue is not valid')],
    [
      'a non-string code',
      () => json({ error: { privateKey: 'nsec1secretvalue' } }, 400),
    ],
    [
      'an HTML page',
      () => new Response('<html>nsec1secretvalue</html>', { status: 400 }),
    ],
    [
      'malformed JSON',
      () =>
        new Response('{"error": "nsec1secretvalue', {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        }),
    ],
  ])('keeps no part of %s', async (_case, response) => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map(
      (method) => vi.spyOn(console, method).mockImplementation(() => {}),
    );
    const { api } = client(response);
    const error = await api
      .registerIdentity('nsec1secretvalue')
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 400, code: null });
    expect(JSON.stringify(error)).not.toContain('nsec1secretvalue');
    expect(String(error)).not.toContain('nsec1secretvalue');
    for (const spy of spies) {
      expect(spy).not.toHaveBeenCalled();
    }
  });

  it('reports a network failure without its cause', async () => {
    const api = new AdminApi({
      fetch: () =>
        Promise.reject(new TypeError('Failed to fetch nsec1secretvalue')),
      onUnauthorized: vi.fn(),
    });
    const error = await api
      .registerIdentity('nsec1secretvalue')
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: null, code: null });
    expect((error as Error).cause).toBeUndefined();
    expect(String(error)).not.toContain('nsec1secretvalue');
  });
});
