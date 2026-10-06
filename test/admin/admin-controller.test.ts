import { nsecEncode } from 'nostr-tools/nip19';
import { bytesToHex } from 'nostr-tools/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AdminController,
  type AdminState,
} from '../../admin/lib/admin-controller';
import { NO_SIGNER_MESSAGE } from '../../admin/lib/messages';
import type { Nip07Signer } from '../../admin/lib/nip98';
import { randomKey } from '../nostr-helpers';
import {
  apiError,
  clientSession,
  DATABASE_SIZE,
  deferred,
  FakeAdminServer,
  LOGIN_URL,
  nip07Signer,
  PAGE_URL,
  SESSION_EXPIRES_AT,
} from './fake-server';

interface Setup {
  readonly server: FakeAdminServer;
  readonly admin: AdminController;
  signer: Nip07Signer | undefined;
}

function setup(): Setup {
  const server = new FakeAdminServer();
  const context: Setup = {
    server,
    signer: nip07Signer(server.admin),
    admin: new AdminController({
      fetch: server.fetch,
      signer: () => context.signer,
      pageUrl: () => PAGE_URL,
    }),
  };
  return context;
}

async function signedIn(): Promise<Setup> {
  const context = setup();
  await context.admin.start();
  await context.admin.login();
  expect(context.admin.state.auth.status).toBe('authenticated');
  return context;
}

// The state that an unauthenticated page shows: no administrative data.
function expectSignedOut(state: AdminState): void {
  expect(state.auth).toEqual({ status: 'unauthenticated' });
  expect(state.status).toBeNull();
  expect(state.identities).toBeNull();
  expect(state.sessions).toEqual({});
  expect(state.pairings).toEqual({});
  expect(state.dashboardError).toBeNull();
  expect(state.pending).toEqual({
    login: false,
    logout: false,
    refresh: false,
    register: false,
    deleting: [],
    pairing: [],
    revoking: [],
  });
}

function consoleSpies() {
  return (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
    vi.spyOn(console, method).mockImplementation(() => {}),
  );
}

// Any use of browser storage or cookies is recorded. The Workers runtime that
// runs these tests has none of these globals.
function watchBrowserStorage(): string[] {
  const uses: string[] = [];
  for (const name of [
    'localStorage',
    'sessionStorage',
    'indexedDB',
    'document',
  ]) {
    vi.stubGlobal(
      name,
      new Proxy(
        {},
        {
          get(_target, property) {
            uses.push(`${name}.${String(property)}`);
            return () => undefined;
          },
          set(_target, property) {
            uses.push(`${name}.${String(property)}=`);
            return true;
          },
        },
      ),
    );
  }
  return uses;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('session check', () => {
  it('shows the dashboard for an existing session', async () => {
    const { server, admin } = setup();
    server.signedIn = true;
    const identity = server.addIdentity();
    expect(admin.state.auth.status).toBe('loading');
    await admin.start();
    expect(admin.state.auth).toEqual({
      status: 'authenticated',
      session: { pubkey: server.admin.pubkey, expiresAt: SESSION_EXPIRES_AT },
    });
    expect(admin.state.status).toEqual({
      identities: 1,
      sessions: 0,
      pairings: 0,
      databaseSize: DATABASE_SIZE,
    });
    expect(admin.state.identities).toEqual([identity]);
    expect(server.requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      'GET /admin/api/session',
      'GET /admin/api/status',
      'GET /admin/api/identities',
    ]);
  });

  it('shows the login view without a session', async () => {
    const { server, admin } = setup();
    await admin.start();
    expectSignedOut(admin.state);
    // Nothing has expired: there was no session to begin with.
    expect(admin.state.notice).toBeNull();
    expect(server.requests).toHaveLength(1);
  });

  it('reports a server configuration error', async () => {
    const { server, admin } = setup();
    server.intercept(() => apiError(500, 'server configuration error'));
    await admin.start();
    expect(admin.state.auth.status).toBe('configuration_error');
    expect(admin.state.auth).toMatchObject({
      message: expect.stringContaining('ADMIN_PUBKEY'),
    });
  });

  it.each<[string, () => Promise<Response>]>([
    ['an internal error', async () => apiError(500, 'internal error')],
    [
      'a network failure',
      () => Promise.reject(new TypeError('Failed to fetch')),
    ],
    ['an unexpected response', async () => new Response('<!doctype html>')],
  ])('reports %s as a recoverable error', async (_case, respond) => {
    const { server, admin } = setup();
    server.signedIn = true;
    server.intercept(respond);
    await admin.start();
    expect(admin.state.auth.status).toBe('error');
    server.intercept(null);
    await admin.start();
    expect(admin.state.auth.status).toBe('authenticated');
  });
});

describe('login', () => {
  it('signs a NIP-98 event with NIP-07 and sends it to the absolute login URL', async () => {
    const { server, admin } = setup();
    await admin.start();
    await admin.login();
    expect(admin.state.auth.status).toBe('authenticated');
    const [login] = server.requestsTo('POST', '/admin/api/login');
    expect(login.url).toBe(LOGIN_URL);
    expect(login.body).toBeUndefined();
    expect(login.headers.Authorization).toMatch(/^Nostr [A-Za-z0-9+/]+={0,2}$/);
    // The dashboard is loaded with the session cookie, without credentials
    // from the page.
    expect(server.requestsTo('GET', '/admin/api/status')).toHaveLength(1);
    expect(server.requestsTo('GET', '/admin/api/identities')).toHaveLength(1);
    for (const request of server.requests.slice(2)) {
      expect(request.headers.Authorization).toBeUndefined();
    }
  });

  it('keeps neither the signed event nor the Authorization header', async () => {
    const storage = watchBrowserStorage();
    const { server, admin } = setup();
    await admin.start();
    await admin.login();
    const authorization = server.requestsTo('POST', '/admin/api/login')[0]
      .headers.Authorization;
    const event = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(atob(authorization.slice('Nostr '.length)), (c) =>
          c.charCodeAt(0),
        ),
      ),
    );
    const state = JSON.stringify(admin.state);
    expect(state).not.toContain(authorization.slice('Nostr '.length));
    expect(state).not.toContain(event.id);
    expect(state).not.toContain(event.sig);
    expect(storage).toEqual([]);
  });

  it('explains that a NIP-07 signer is required when there is none', async () => {
    const context = setup();
    context.signer = undefined;
    await context.admin.start();
    await context.admin.login();
    expect(context.admin.state.loginError).toBe(NO_SIGNER_MESSAGE);
    expect(context.admin.state.auth.status).toBe('unauthenticated');
    expect(context.admin.state.pending.login).toBe(false);
    expect(context.server.requestsTo('POST', '/admin/api/login')).toEqual([]);
  });

  it('reports a rejected signature without sending a request or logging', async () => {
    const spies = consoleSpies();
    const context = setup();
    context.signer = {
      signEvent: () => Promise.reject(new Error(`rejected ${LOGIN_URL}`)),
    };
    await context.admin.start();
    await context.admin.login();
    expect(context.admin.state.loginError).toMatch(/did not sign/);
    expect(context.admin.state.loginError).not.toContain(LOGIN_URL);
    expect(context.server.requestsTo('POST', '/admin/api/login')).toEqual([]);
    for (const spy of spies) {
      expect(spy).not.toHaveBeenCalled();
    }
  });

  it('reports a login the server rejects', async () => {
    const context = setup();
    context.signer = nip07Signer(randomKey());
    await context.admin.start();
    await context.admin.login();
    expect(context.admin.state.auth.status).toBe('unauthenticated');
    expect(context.admin.state.loginError).toMatch(/rejected.*ADMIN_PUBKEY/);
    expect(context.admin.state.notice).toBeNull();
  });

  it('sends one login at a time', async () => {
    const context = setup();
    await context.admin.start();
    const signature = deferred<unknown>();
    const signEvent = vi.fn(() => signature.promise);
    context.signer = { signEvent };
    const first = context.admin.login();
    const second = context.admin.login();
    expect(context.admin.state.pending.login).toBe(true);
    signature.resolve(undefined);
    await Promise.all([first, second]);
    expect(signEvent).toHaveBeenCalledTimes(1);
  });
});

describe('expired admin sessions', () => {
  it('return to the login view and discard all administrative data', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    server.sessions.set(identity.pubkey, [clientSession('c'.repeat(64))]);
    await admin.refresh();
    await admin.createPairing(identity.pubkey, 'all');
    await admin.loadSessions(identity.pubkey);
    expect(admin.state.pairings[identity.pubkey].bunkerUrl).toMatch(/^bunker:/);

    // The session expires, or ADMIN_PUBKEY changes, on the server.
    server.signedIn = false;
    await admin.refresh();
    expectSignedOut(admin.state);
    expect(admin.state.notice).toEqual({
      kind: 'error',
      message: expect.stringMatching(/expired or is no longer valid/),
    });
    expect(JSON.stringify(admin.state)).not.toContain('bunker:');
  });

  it.each<
    [string, (admin: AdminController, pubkey: string) => Promise<unknown>]
  >([
    ['registering an identity', (admin) => admin.registerIdentity('nsec1x')],
    ['deleting an identity', (admin, pubkey) => admin.deleteIdentity(pubkey)],
    [
      'creating a pairing',
      (admin, pubkey) => admin.createPairing(pubkey, 'all'),
    ],
    ['listing sessions', (admin, pubkey) => admin.loadSessions(pubkey)],
    [
      'revoking a session',
      (admin, pubkey) => admin.revokeSession(pubkey, 'c'.repeat(64)),
    ],
    ['signing out', (admin) => admin.logout()],
  ])('are detected while %s', async (_case, action) => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    server.signedIn = false;
    await action(admin, identity.pubkey);
    expectSignedOut(admin.state);
  });

  it('are not ended by a 401 to a request of an earlier session', async () => {
    const { server, admin } = await signedIn();
    const status = deferred<Response>();
    server.intercept((request) =>
      request.url === '/admin/api/status' ? status.promise : undefined,
    );
    const staleRefresh = admin.refresh();
    server.intercept(null);
    await admin.logout();
    await admin.login();
    expect(admin.state.auth.status).toBe('authenticated');

    status.resolve(apiError(401, 'unauthorized'));
    await staleRefresh;
    expect(admin.state.auth.status).toBe('authenticated');
    expect(admin.state.notice).toBeNull();
  });
});

describe('logout', () => {
  it('ends the session and discards all administrative data', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    server.sessions.set(identity.pubkey, [clientSession('c'.repeat(64))]);
    await admin.refresh();
    await admin.createPairing(identity.pubkey, 'all');
    await admin.loadSessions(identity.pubkey);

    await admin.logout();
    expect(server.requestsTo('POST', '/admin/api/logout')).toHaveLength(1);
    expect(
      server.requestsTo('POST', '/admin/api/logout')[0].body,
    ).toBeUndefined();
    expectSignedOut(admin.state);
    expect(admin.state.notice).toEqual({
      kind: 'success',
      message: 'Signed out.',
    });
    expect(JSON.stringify(admin.state)).not.toContain('bunker:');
  });

  it('keeps the session when the server does not log out', async () => {
    const spies = consoleSpies();
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    await admin.createPairing(identity.pubkey, 'all');
    server.intercept(() => apiError(500, 'internal error'));
    await admin.logout();
    expect(admin.state.auth.status).toBe('authenticated');
    expect(admin.state.pending.logout).toBe(false);
    expect(admin.state.notice).toMatchObject({ kind: 'error' });
    for (const spy of spies) {
      expect(spy).not.toHaveBeenCalled();
    }
  });

  it('sends one logout at a time', async () => {
    const { server, admin } = await signedIn();
    const response = deferred<Response>();
    server.intercept(() => response.promise);
    const first = admin.logout();
    const second = admin.logout();
    expect(admin.state.pending.logout).toBe(true);
    response.resolve(new Response(null, { status: 204 }));
    await Promise.all([first, second]);
    expect(server.requestsTo('POST', '/admin/api/logout')).toHaveLength(1);
  });
});

describe('identity registration', () => {
  it('sends the private key in the request body only', async () => {
    const storage = watchBrowserStorage();
    const { server, admin } = await signedIn();
    const key = randomKey();
    const nsec = nsecEncode(key.secretKey);
    const result = await admin.registerIdentity(nsec);
    expect(result).toEqual({ ok: true });

    const [registration] = server.requestsTo('POST', '/admin/api/identities');
    expect(registration.url).toBe('/admin/api/identities');
    expect(JSON.parse(registration.body ?? '')).toEqual({ privateKey: nsec });
    for (const request of server.requests) {
      expect(request.url).not.toContain(nsec);
      expect(JSON.stringify(request.headers)).not.toContain(nsec);
      if (request !== registration) {
        expect(request.body ?? '').not.toContain(nsec);
      }
    }
    expect(JSON.stringify(admin.state)).not.toContain(nsec);
    expect(storage).toEqual([]);
  });

  it('refreshes the identity list and the status', async () => {
    const { server, admin } = await signedIn();
    const key = randomKey();
    const before = server.requests.length;
    await admin.registerIdentity(bytesToHex(key.secretKey));
    expect(
      server.requests.slice(before).map((r) => `${r.method} ${r.url}`),
    ).toEqual([
      'POST /admin/api/identities',
      'GET /admin/api/status',
      'GET /admin/api/identities',
    ]);
    expect(admin.state.identities?.map((identity) => identity.pubkey)).toEqual([
      key.pubkey,
    ]);
    expect(admin.state.status?.identities).toBe(1);
    expect(admin.state.notice).toMatchObject({ kind: 'success' });
    expect(admin.state.pending.register).toBe(false);
  });

  it.each<[string, (server: FakeAdminServer) => void, RegExp]>([
    ['an invalid key', () => {}, /not a valid private key/],
    [
      'a duplicate identity',
      (server) =>
        server.intercept(() => apiError(409, 'identity already exists')),
      /already registered/,
    ],
    [
      'insufficient storage',
      (server) => server.intercept(() => apiError(507, 'insufficient storage')),
      /storage is full/,
    ],
    [
      'a server configuration error',
      (server) =>
        server.intercept(() => apiError(500, 'server configuration error')),
      /MASTER_ENCRYPTION_KEY/,
    ],
  ])('reports %s', async (_case, arrange, message) => {
    const spies = consoleSpies();
    const { server, admin } = await signedIn();
    arrange(server);
    const result = await admin.registerIdentity('nsec1invalidsecretinput');
    expect(result).toEqual({
      ok: false,
      message: expect.stringMatching(message),
    });
    if (!result.ok) {
      expect(result.message).not.toContain('nsec1invalidsecretinput');
    }
    expect(admin.state.pending.register).toBe(false);
    expect(JSON.stringify(admin.state)).not.toContain(
      'nsec1invalidsecretinput',
    );
    for (const spy of spies) {
      expect(spy).not.toHaveBeenCalled();
    }
  });

  it('sends one registration at a time', async () => {
    const { server, admin } = await signedIn();
    const response = deferred<Response>();
    server.intercept(() => response.promise);
    const first = admin.registerIdentity('a');
    expect(await admin.registerIdentity('b')).toMatchObject({ ok: false });
    expect(admin.state.pending.register).toBe(true);
    response.resolve(apiError(400, 'invalid private key'));
    await first;
    expect(server.requestsTo('POST', '/admin/api/identities')).toHaveLength(1);
  });
});

describe('identity deletion', () => {
  it('deletes the identity and refreshes the list and the status', async () => {
    const { server, admin } = await signedIn();
    const kept = server.addIdentity();
    const deleted = server.addIdentity();
    await admin.refresh();
    await admin.deleteIdentity(deleted.pubkey);
    expect(
      server.requestsTo('DELETE', `/admin/api/identities/${deleted.pubkey}`),
    ).toHaveLength(1);
    expect(admin.state.identities).toEqual([kept]);
    expect(admin.state.status?.identities).toBe(1);
    expect(admin.state.notice).toMatchObject({ kind: 'success' });
    expect(admin.state.pending.deleting).toEqual([]);
  });

  it('discards the connection token and sessions of the identity', async () => {
    const { server, admin } = await signedIn();
    const kept = server.addIdentity();
    const deleted = server.addIdentity();
    server.sessions.set(deleted.pubkey, [clientSession('c'.repeat(64))]);
    await admin.refresh();
    await admin.createPairing(kept.pubkey, 'all');
    await admin.createPairing(deleted.pubkey, 'all');
    await admin.loadSessions(deleted.pubkey);
    const keptToken = admin.state.pairings[kept.pubkey].bunkerUrl;
    const deletedToken = admin.state.pairings[deleted.pubkey].bunkerUrl ?? '';

    await admin.deleteIdentity(deleted.pubkey);
    expect(Object.keys(admin.state.pairings)).toEqual([kept.pubkey]);
    expect(admin.state.pairings[kept.pubkey].bunkerUrl).toBe(keptToken);
    expect(admin.state.sessions[deleted.pubkey]).toBeUndefined();
    expect(JSON.stringify(admin.state)).not.toContain(deletedToken);
  });

  it('treats an identity that is already gone as deleted', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    await admin.createPairing(identity.pubkey, 'all');
    server.identities = [];
    await admin.deleteIdentity(identity.pubkey);
    expect(admin.state.identities).toEqual([]);
    expect(admin.state.pairings).toEqual({});
    expect(admin.state.notice).toEqual({
      kind: 'error',
      message: 'This identity no longer exists.',
    });
  });

  it('keeps the identity when deletion fails', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    await admin.createPairing(identity.pubkey, 'all');
    server.intercept((request) =>
      request.method === 'DELETE' ? apiError(500, 'internal error') : undefined,
    );
    await admin.deleteIdentity(identity.pubkey);
    expect(admin.state.identities).toEqual([identity]);
    expect(admin.state.pairings[identity.pubkey]).toBeDefined();
    expect(admin.state.notice).toMatchObject({ kind: 'error' });
  });

  it('sends one deletion at a time and none while a pairing is created', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    const response = deferred<Response>();
    server.intercept((request) =>
      request.method === 'DELETE' ? response.promise : undefined,
    );
    const first = admin.deleteIdentity(identity.pubkey);
    await admin.deleteIdentity(identity.pubkey);
    expect(await admin.createPairing(identity.pubkey, 'all')).toMatchObject({
      ok: false,
    });
    expect(admin.state.pending.deleting).toEqual([identity.pubkey]);
    response.resolve(new Response(null, { status: 204 }));
    await first;
    expect(
      server.requestsTo('DELETE', `/admin/api/identities/${identity.pubkey}`),
    ).toHaveLength(1);
    expect(
      server.requestsTo(
        'POST',
        `/admin/api/identities/${identity.pubkey}/pairings`,
      ),
    ).toEqual([]);
  });
});

describe('pairings', () => {
  it('sends the selected permissions and keeps the token in memory', async () => {
    const storage = watchBrowserStorage();
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    const result = await admin.createPairing(identity.pubkey, [
      'sign_event:1',
      'nip44_encrypt',
    ]);
    expect(result).toEqual({ ok: true });
    const [request] = server.requestsTo(
      'POST',
      `/admin/api/identities/${identity.pubkey}/pairings`,
    );
    expect(request.url).toBe(
      `/admin/api/identities/${identity.pubkey}/pairings`,
    );
    expect(JSON.parse(request.body ?? '')).toEqual({
      permissions: ['sign_event:1', 'nip44_encrypt'],
    });
    expect(admin.state.pairings[identity.pubkey]).toEqual({
      bunkerUrl: expect.stringMatching(
        /^bunker:\/\/e{64}\?relay=.*&secret=[0-9a-f]{64}$/,
      ),
      expiresAt: server.now + 600,
    });
    // The pending pairing count comes from the server.
    expect(admin.state.status?.pairings).toBe(1);
    expect(storage).toEqual([]);
  });

  it('drops the token when it is dismissed', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    await admin.createPairing(identity.pubkey, 'all');
    admin.dismissPairing(identity.pubkey);
    expect(admin.state.pairings).toEqual({});
  });

  it('drops the token and keeps the expiry once the pairing has expired', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    await admin.createPairing(identity.pubkey, 'all');
    admin.expirePairing(identity.pubkey);
    expect(admin.state.pairings[identity.pubkey]).toEqual({
      bunkerUrl: null,
      expiresAt: server.now + 600,
    });
    expect(JSON.stringify(admin.state)).not.toContain('bunker:');
  });

  it('drops tokens of identities that are no longer listed', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    await admin.createPairing(identity.pubkey, 'all');
    // Deleted from another browser.
    server.identities = [];
    await admin.refresh();
    expect(admin.state.pairings).toEqual({});
  });

  it('drops a token that arrives after the admin session has ended', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    const response = deferred<Response>();
    server.intercept((request) =>
      request.url.endsWith('/pairings') ? response.promise : undefined,
    );
    const creation = admin.createPairing(identity.pubkey, 'all');
    server.intercept(null);
    await admin.logout();
    response.resolve(
      new Response(
        JSON.stringify({
          bunkerUrl: `bunker://${'e'.repeat(64)}?secret=late`,
          expiresAt: 1,
        }),
        { status: 201, headers: { 'Content-Type': 'application/json' } },
      ),
    );
    await creation;
    expect(admin.state.pairings).toEqual({});
    expect(JSON.stringify(admin.state)).not.toContain('bunker:');
  });

  it('reports errors without keeping a token', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    server.intercept(() => apiError(500, 'server configuration error'));
    const result = await admin.createPairing(identity.pubkey, 'all');
    expect(result).toEqual({
      ok: false,
      message: expect.stringMatching(/REMOTE_SIGNER_PRIVATE_KEY/),
    });
    expect(admin.state.pairings).toEqual({});
    expect(admin.state.pending.pairing).toEqual([]);
  });

  it('refreshes the identity list when the identity is gone', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    server.identities = [];
    const result = await admin.createPairing(identity.pubkey, 'all');
    expect(result).toEqual({
      ok: false,
      message: 'This identity no longer exists.',
    });
    expect(admin.state.identities).toEqual([]);
  });

  it('creates one pairing at a time for an identity', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    const response = deferred<Response>();
    server.intercept((request) =>
      request.url.endsWith('/pairings') ? response.promise : undefined,
    );
    const first = admin.createPairing(identity.pubkey, 'all');
    expect(await admin.createPairing(identity.pubkey, 'all')).toMatchObject({
      ok: false,
    });
    await admin.deleteIdentity(identity.pubkey);
    expect(admin.state.pending.pairing).toEqual([identity.pubkey]);
    response.resolve(apiError(507, 'insufficient storage'));
    expect(await first).toEqual({
      ok: false,
      message: expect.stringMatching(/storage is full/),
    });
    expect(
      server.requestsTo(
        'POST',
        `/admin/api/identities/${identity.pubkey}/pairings`,
      ),
    ).toHaveLength(1);
    expect(
      server.requestsTo('DELETE', `/admin/api/identities/${identity.pubkey}`),
    ).toEqual([]);
  });
});

describe('sessions', () => {
  it('lists the sessions of an identity with client metadata as given', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    const session = clientSession('c'.repeat(64), {
      clientMetadata: {
        name: '<img src=x onerror=alert(1)>',
        url: 'javascript:alert(1)',
        image: 'https://tracker.example/pixel.png',
      },
    });
    server.sessions.set(identity.pubkey, [session]);
    await admin.refresh();
    await admin.loadSessions(identity.pubkey);
    expect(
      server.requestsTo(
        'GET',
        `/admin/api/identities/${identity.pubkey}/sessions`,
      ),
    ).toHaveLength(1);
    expect(admin.state.sessions[identity.pubkey]).toEqual({
      loading: false,
      sessions: [session],
      error: null,
    });
  });

  it('revokes a session and reloads the sessions and the status', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    const revoked = clientSession('c'.repeat(64));
    const kept = clientSession('d'.repeat(64));
    server.sessions.set(identity.pubkey, [revoked, kept]);
    await admin.refresh();
    await admin.loadSessions(identity.pubkey);
    expect(admin.state.status?.sessions).toBe(2);

    await admin.revokeSession(identity.pubkey, revoked.clientPubkey);
    expect(
      server.requestsTo(
        'DELETE',
        `/admin/api/sessions/${revoked.clientPubkey}`,
      ),
    ).toHaveLength(1);
    expect(admin.state.sessions[identity.pubkey].sessions).toEqual([kept]);
    expect(admin.state.status?.sessions).toBe(1);
    expect(admin.state.notice).toEqual({
      kind: 'success',
      message: expect.stringMatching(/rejects every further request/),
    });
    expect(admin.state.pending.revoking).toEqual([]);
  });

  it('reports a session that no longer exists and reloads the list', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    await admin.revokeSession(identity.pubkey, 'c'.repeat(64));
    expect(admin.state.notice).toEqual({
      kind: 'error',
      message: 'This session no longer exists.',
    });
    expect(
      server.requestsTo(
        'GET',
        `/admin/api/identities/${identity.pubkey}/sessions`,
      ),
    ).toHaveLength(1);
  });

  it('revokes a session once at a time', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    server.sessions.set(identity.pubkey, [clientSession('c'.repeat(64))]);
    await admin.refresh();
    const response = deferred<Response>();
    server.intercept((request) =>
      request.method === 'DELETE' ? response.promise : undefined,
    );
    const first = admin.revokeSession(identity.pubkey, 'c'.repeat(64));
    await admin.revokeSession(identity.pubkey, 'c'.repeat(64));
    expect(admin.state.pending.revoking).toEqual(['c'.repeat(64)]);
    response.resolve(new Response(null, { status: 204 }));
    await first;
    expect(
      server.requestsTo('DELETE', `/admin/api/sessions/${'c'.repeat(64)}`),
    ).toHaveLength(1);
  });

  it('applies only the latest session list', async () => {
    const { server, admin } = await signedIn();
    const identity = server.addIdentity();
    await admin.refresh();
    const stale = deferred<Response>();
    server.intercept((request) =>
      request.url.endsWith('/sessions') ? stale.promise : undefined,
    );
    const first = admin.loadSessions(identity.pubkey);
    server.intercept(null);
    server.sessions.set(identity.pubkey, [clientSession('d'.repeat(64))]);
    await admin.loadSessions(identity.pubkey);
    stale.resolve(
      new Response('[]', { headers: { 'Content-Type': 'application/json' } }),
    );
    await first;
    expect(admin.state.sessions[identity.pubkey].sessions).toEqual([
      clientSession('d'.repeat(64)),
    ]);
  });
});

describe('browser storage', () => {
  it('would be noticed if it were used', () => {
    const storage = watchBrowserStorage();
    const browser = globalThis as unknown as {
      localStorage: { setItem(key: string, value: string): void };
      document: { cookie: string };
    };
    browser.localStorage.setItem('key', 'value');
    void browser.document.cookie;
    expect(storage).toEqual(['localStorage.setItem', 'document.cookie']);
  });

  it('is not used by any administrative flow', async () => {
    const storage = watchBrowserStorage();
    const { server, admin } = setup();
    await admin.start();
    await admin.login();
    const key = randomKey();
    await admin.registerIdentity(nsecEncode(key.secretKey));
    await admin.createPairing(key.pubkey, 'all');
    server.sessions.set(key.pubkey, [clientSession('c'.repeat(64))]);
    await admin.loadSessions(key.pubkey);
    await admin.revokeSession(key.pubkey, 'c'.repeat(64));
    admin.dismissPairing(key.pubkey);
    await admin.deleteIdentity(key.pubkey);
    await admin.logout();
    expect(storage).toEqual([]);
  });
});

describe('subscribe', () => {
  it('follows the Svelte store contract', async () => {
    const { admin } = setup();
    const states: AdminState[] = [];
    const unsubscribe = admin.subscribe((state) => states.push(state));
    expect(states).toEqual([admin.state]);
    await admin.start();
    expect(states.at(-1)).toBe(admin.state);
    const seen = states.length;
    unsubscribe();
    await admin.start();
    expect(states).toHaveLength(seen);
  });
});
