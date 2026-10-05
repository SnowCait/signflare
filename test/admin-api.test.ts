import { env, exports } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { npubEncode, nsecEncode } from 'nostr-tools/nip19';
import type { NostrEvent } from 'nostr-tools/pure';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MAX_LOGIN_BODY_BYTES } from '../src/admin-api';
import app from '../src/index';
import type { SignerHub } from '../src/signer-hub';
import {
  encodeBase64,
  LOGIN_URL,
  nostrAuthorization,
  ORIGIN,
  randomKey,
  sha256Hex,
  signHttpAuthEvent,
  tamperHex,
  type TestKey,
} from './nostr-helpers';

const COOKIE_NAME = '__Secure-signflare_admin_session';
const SESSION_URL = `${ORIGIN}/admin/api/session`;
const LOGOUT_URL = `${ORIGIN}/admin/api/logout`;
const TWELVE_HOURS = 12 * 60 * 60;
const T0 = 1_800_000_000;

const admin = randomKey();
const other = randomKey();

interface Deployment {
  readonly env: Env;
  readonly hub: DurableObjectStub<SignerHub>;
  readonly hubNames: string[];
}

// Each test gets its own SignerHub, reached through whatever name the Worker
// asks for. The names are recorded so tests can check which one it used.
function deployment(adminPubkey: unknown = admin.pubkey): Deployment {
  const hub = env.SIGNER_HUB.getByName(crypto.randomUUID());
  const hubNames: string[] = [];
  const namespace = {
    getByName(name: string) {
      hubNames.push(name);
      return hub;
    },
  };
  return {
    env: {
      ...env,
      ADMIN_PUBKEY: adminPubkey as string,
      SIGNER_HUB: namespace as unknown as Env['SIGNER_HUB'],
    },
    hub,
    hubNames,
  };
}

function unconfiguredDeployment(): Deployment {
  const d = deployment();
  const unconfigured: Partial<Env> = { ...d.env };
  delete unconfigured.ADMIN_PUBKEY;
  return { ...d, env: unconfigured as Env };
}

function withAdminPubkey(d: Deployment, adminPubkey: string): Deployment {
  return { ...d, env: { ...d.env, ADMIN_PUBKEY: adminPubkey } };
}

interface RequestOptions {
  readonly method?: string;
  // Defaults to the request's own origin for methods other than GET and
  // HEAD, as browsers do. null omits the header.
  readonly origin?: string | null;
  readonly authorization?: string;
  readonly token?: string;
  readonly body?: BodyInit;
  readonly headers?: Record<string, string>;
}

async function send(
  testEnv: Env,
  url: string,
  options: RequestOptions = {},
): Promise<Response> {
  const method = options.method ?? 'GET';
  const headers = new Headers(options.headers);
  const origin =
    options.origin === undefined
      ? method === 'GET' || method === 'HEAD'
        ? null
        : new URL(url).origin
      : options.origin;
  if (origin !== null) {
    headers.set('Origin', origin);
  }
  if (options.authorization !== undefined) {
    headers.set('Authorization', options.authorization);
  }
  if (options.token !== undefined) {
    headers.set('Cookie', `${COOKIE_NAME}=${options.token}`);
  }
  return app.fetch(
    new Request(url, { method, headers, body: options.body }),
    testEnv,
  );
}

function postLogin(
  d: Deployment,
  event: unknown,
  options: RequestOptions & { url?: string } = {},
): Promise<Response> {
  return send(d.env, options.url ?? LOGIN_URL, {
    method: 'POST',
    authorization: nostrAuthorization(event),
    ...options,
  });
}

function getSession(d: Deployment, token?: string): Promise<Response> {
  return send(d.env, SESSION_URL, { token });
}

function postLogout(
  d: Deployment,
  token?: string,
  options: RequestOptions = {},
): Promise<Response> {
  return send(d.env, LOGOUT_URL, { method: 'POST', token, ...options });
}

interface SetCookie {
  readonly name: string;
  readonly value: string;
  readonly attributes: string[];
}

function setCookies(response: Response): SetCookie[] {
  return response.headers.getSetCookie().map((header) => {
    const [pair, ...attributes] = header.split(';').map((part) => part.trim());
    const separator = pair.indexOf('=');
    return {
      name: pair.slice(0, separator),
      value: pair.slice(separator + 1),
      attributes,
    };
  });
}

// A fresh login event each time: events signed within the same second would
// otherwise be identical and rejected as replays.
function uniqueLoginEvent(key: TestKey): NostrEvent {
  return signHttpAuthEvent(key, {
    tags: [
      ['u', LOGIN_URL],
      ['method', 'POST'],
      ['nonce', crypto.randomUUID()],
    ],
  });
}

async function logIn(d: Deployment, key: TestKey = admin): Promise<string> {
  const response = await postLogin(d, uniqueLoginEvent(key));
  expect(response.status).toBe(200);
  const [cookie] = setCookies(response);
  return cookie.value;
}

type SessionRow = {
  token_hash: ArrayBuffer;
  admin_pubkey: string;
  expires_at: number;
  created_at: number;
};

function adminRows(hub: DurableObjectStub<SignerHub>) {
  return runInDurableObject(hub, (_instance, state) => {
    const { sql } = state.storage;
    const sessions = sql
      .exec<SessionRow>('SELECT * FROM admin_sessions ORDER BY created_at')
      .toArray();
    const events = sql
      .exec<{
        event_id: string;
        expires_at: number;
      }>('SELECT * FROM admin_auth_events ORDER BY event_id')
      .toArray();
    const values = sql
      .exec<{ name: string }>(
        "SELECT name FROM sqlite_master WHERE type = 'table'",
      )
      .toArray()
      .flatMap(({ name }) =>
        [...sql.exec(`SELECT * FROM "${name}"`).raw()].flat(),
      );
    return { sessions, events, values };
  });
}

async function tokenHash(token: string): Promise<string> {
  return sha256Hex(hexToBytes(token));
}

function setNow(seconds: number): void {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(seconds * 1000);
}

// Material that must never appear in an HTTP response.
function secretsOf(event: NostrEvent, ...extra: string[]): string[] {
  const authorization = nostrAuthorization(event);
  return [
    authorization,
    authorization.slice('Nostr '.length, 'Nostr '.length + 32),
    JSON.stringify(event),
    event.id,
    event.sig,
    bytesToHex(admin.secretKey),
    nsecEncode(admin.secretKey),
    ...extra,
  ];
}

async function expectError(
  response: Response,
  status: number,
  error: string,
  secrets: readonly string[] = [],
): Promise<void> {
  expect(response.status).toBe(status);
  expect(response.headers.getSetCookie()).toEqual([]);
  expect(response.headers.get('Content-Type')).toMatch(/^application\/json/);
  const text = await response.text();
  expect(JSON.parse(text)).toEqual({ error });
  expect(text).not.toMatch(/Error:|\n\s+at\s/);
  for (const secret of secrets) {
    expect(text).not.toContain(secret);
    for (const [, value] of response.headers) {
      expect(value).not.toContain(secret);
    }
  }
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('POST /admin/api/login', () => {
  it('logs in with an event signed by ADMIN_PUBKEY', async () => {
    setNow(T0);
    const d = deployment();
    const response = await postLogin(d, signHttpAuthEvent(admin));

    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(await response.json()).toEqual({
      pubkey: admin.pubkey,
      expiresAt: T0 + TWELVE_HOURS,
    });
    expect(setCookies(response)).toHaveLength(1);
  });

  it('issues a HttpOnly, Secure, SameSite=Strict cookie scoped to /admin', async () => {
    const d = deployment();
    const response = await postLogin(d, signHttpAuthEvent(admin));
    const [cookie] = setCookies(response);

    expect(cookie.name).toBe(COOKIE_NAME);
    expect(cookie.value).toMatch(/^[0-9a-f]{64}$/);
    expect(cookie.attributes).toEqual(
      expect.arrayContaining([
        'HttpOnly',
        'Secure',
        'SameSite=Strict',
        'Path=/admin',
        `Max-Age=${TWELVE_HOURS}`,
      ]),
    );
    expect(cookie.attributes.some((a) => /^Domain=/i.test(a))).toBe(false);
  });

  it('stores only the hash of the session token', async () => {
    const d = deployment();
    const response = await postLogin(d, signHttpAuthEvent(admin));
    const [{ value: token }] = setCookies(response);
    const body = await response.text();
    expect(body).not.toContain(token);

    const { sessions, values } = await adminRows(d.hub);
    expect(sessions).toHaveLength(1);
    expect(bytesToHex(new Uint8Array(sessions[0].token_hash))).toBe(
      await tokenHash(token),
    );
    const raw = hexToBytes(token);
    for (const value of values) {
      if (value instanceof ArrayBuffer) {
        expect(bytesToHex(new Uint8Array(value))).not.toContain(token);
        expect(new Uint8Array(value)).not.toEqual(raw);
      } else if (typeof value === 'string') {
        expect(value.toLowerCase()).not.toContain(token);
      }
    }
  });

  it('expires the session exactly 12 hours after login', async () => {
    setNow(T0);
    const d = deployment();
    const event = signHttpAuthEvent(admin);
    await postLogin(d, event);

    const { sessions, events } = await adminRows(d.hub);
    expect(sessions).toEqual([
      {
        token_hash: expect.any(ArrayBuffer),
        admin_pubkey: admin.pubkey,
        created_at: T0,
        expires_at: T0 + TWELVE_HOURS,
      },
    ]);
    expect(events).toEqual([{ event_id: event.id, expires_at: T0 + 60 }]);
  });

  it('uses the SignerHub named "signer"', async () => {
    const d = deployment();
    const token = await logIn(d);
    await getSession(d, token);
    await postLogout(d, token);
    expect(d.hubNames).toEqual(['signer', 'signer', 'signer', 'signer']);
  });

  it('persists the session in the deployment-wide SignerHub', async () => {
    const testEnv = { ...env, ADMIN_PUBKEY: admin.pubkey };
    const login = await send(testEnv, LOGIN_URL, {
      method: 'POST',
      authorization: nostrAuthorization(signHttpAuthEvent(admin)),
    });
    expect(login.status).toBe(200);
    const [{ value: token }] = setCookies(login);

    const { sessions } = await adminRows(env.SIGNER_HUB.getByName('signer'));
    const hashes = sessions.map((row) =>
      bytesToHex(new Uint8Array(row.token_hash)),
    );
    expect(hashes).toContain(await tokenHash(token));

    const session = await send(testEnv, SESSION_URL, { token });
    expect(session.status).toBe(200);
  });

  it('accepts a body covered by the SHA-256 of its raw bytes', async () => {
    const d = deployment();
    const body = '{ "client":  "signflare-admin" }\n';
    const event = signHttpAuthEvent(admin, {
      tags: [
        ['u', LOGIN_URL],
        ['method', 'POST'],
        ['payload', await sha256Hex(body)],
      ],
    });
    const response = await postLogin(d, event, {
      body,
      headers: { 'Content-Type': 'application/json' },
    });
    expect(response.status).toBe(200);
  });

  it(`accepts a body of exactly ${MAX_LOGIN_BODY_BYTES} bytes`, async () => {
    const d = deployment();
    const body = 'x'.repeat(MAX_LOGIN_BODY_BYTES);
    const event = signHttpAuthEvent(admin, {
      tags: [
        ['u', LOGIN_URL],
        ['method', 'POST'],
        ['payload', await sha256Hex(body)],
      ],
    });
    expect((await postLogin(d, event, { body })).status).toBe(200);
  });

  it('rejects a larger body without consuming the event', async () => {
    const d = deployment();
    const body = 'x'.repeat(MAX_LOGIN_BODY_BYTES + 1);
    const event = signHttpAuthEvent(admin, {
      tags: [
        ['u', LOGIN_URL],
        ['method', 'POST'],
        ['payload', await sha256Hex(body)],
      ],
    });
    await expectError(
      await postLogin(d, event, { body }),
      413,
      'payload too large',
      secretsOf(event),
    );
    const streamed = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i <= MAX_LOGIN_BODY_BYTES / 1024; i++) {
          controller.enqueue(new Uint8Array(1024));
        }
        controller.close();
      },
    });
    await expectError(
      await postLogin(d, event, { body: streamed }),
      413,
      'payload too large',
    );
    expect(await adminRows(d.hub)).toMatchObject({ sessions: [], events: [] });
  });
});

describe('POST /admin/api/login rejection', () => {
  const tags = (url = LOGIN_URL, method = 'POST') => [
    ['u', url],
    ['method', method],
  ];

  it.each<
    [string, () => Promise<[unknown, RequestOptions & { url?: string }]>]
  >([
    [
      'an invalid signature',
      async () => {
        const event = signHttpAuthEvent(admin);
        return [{ ...event, sig: tamperHex(event.sig, 7) }, {}];
      },
    ],
    [
      'an id that does not match the signed event',
      async () => {
        const event = signHttpAuthEvent(admin);
        return [{ ...event, id: tamperHex(event.id) }, {}];
      },
    ],
    [
      'content changed after signing',
      async () => [{ ...signHttpAuthEvent(admin), content: 'changed' }, {}],
    ],
    [
      'another kind',
      async () => [signHttpAuthEvent(admin, { kind: 27_236 }), {}],
    ],
    [
      'a timestamp that is too old',
      async () => [signHttpAuthEvent(admin, { created_at: T0 - 60 }), {}],
    ],
    [
      'a timestamp too far in the future',
      async () => [signHttpAuthEvent(admin, { created_at: T0 + 60 }), {}],
    ],
    [
      'a u tag for another host',
      async () => [
        signHttpAuthEvent(admin, {
          tags: tags('https://other.example/admin/api/login'),
        }),
        {},
      ],
    ],
    [
      'a u tag for another scheme',
      async () => [
        signHttpAuthEvent(admin, {
          tags: tags('http://signflare.example/admin/api/login'),
        }),
        {},
      ],
    ],
    [
      'a u tag with only the path',
      async () => [
        signHttpAuthEvent(admin, { tags: tags('/admin/api/login') }),
        {},
      ],
    ],
    [
      'a request URL with a query the u tag lacks',
      async () => [
        signHttpAuthEvent(admin),
        { url: `${LOGIN_URL}?redirect=1` },
      ],
    ],
    [
      'a u tag with a query the request URL lacks',
      async () => [
        signHttpAuthEvent(admin, { tags: tags(`${LOGIN_URL}?redirect=1`) }),
        {},
      ],
    ],
    [
      'a different query',
      async () => [
        signHttpAuthEvent(admin, { tags: tags(`${LOGIN_URL}?a=1`) }),
        { url: `${LOGIN_URL}?a=2` },
      ],
    ],
    [
      'a GET method tag',
      async () => [
        signHttpAuthEvent(admin, { tags: tags(LOGIN_URL, 'GET') }),
        {},
      ],
    ],
    [
      'a lowercase method tag',
      async () => [
        signHttpAuthEvent(admin, { tags: tags(LOGIN_URL, 'post') }),
        {},
      ],
    ],
    [
      'a missing method tag',
      async () => [signHttpAuthEvent(admin, { tags: [['u', LOGIN_URL]] }), {}],
    ],
    ['another pubkey', async () => [signHttpAuthEvent(other), {}]],
    [
      'a body without a payload tag',
      async () => [signHttpAuthEvent(admin), { body: '{}' }],
    ],
    [
      'a payload tag for another body',
      async () => [
        signHttpAuthEvent(admin, {
          tags: [...tags(), ['payload', await sha256Hex('{"a":1}')]],
        }),
        { body: '{"a":2}' },
      ],
    ],
    [
      'a payload tag over the re-serialized body',
      async () => [
        signHttpAuthEvent(admin, {
          tags: [...tags(), ['payload', await sha256Hex('{"a":1}')]],
        }),
        { body: '{ "a": 1 }' },
      ],
    ],
    [
      'a payload tag without a body',
      async () => [
        signHttpAuthEvent(admin, {
          tags: [...tags(), ['payload', await sha256Hex('{}')]],
        }),
        {},
      ],
    ],
  ])('rejects %s', async (_case, build) => {
    // A fixed clock keeps the timestamp cases on the window boundary.
    setNow(T0);
    const d = deployment();
    const [event, options] = await build();
    const response = await postLogin(d, event, options);
    await expectError(
      response,
      401,
      'unauthorized',
      secretsOf(event as NostrEvent),
    );
    expect(await adminRows(d.hub)).toMatchObject({ sessions: [], events: [] });
  });

  it.each<[string, (event: NostrEvent) => string | undefined]>([
    ['a missing Authorization header', () => undefined],
    ['an empty Authorization header', () => ''],
    [
      'another scheme',
      (event) => nostrAuthorization(event).replace('Nostr', 'Bearer'),
    ],
    ['no scheme', (event) => nostrAuthorization(event).slice('Nostr '.length)],
    [
      'malformed base64',
      (event) => `${nostrAuthorization(event).slice(0, -2)}!*`,
    ],
    [
      'base64 that is not JSON',
      () => `Nostr ${encodeBase64(new TextEncoder().encode('{"kind":'))}`,
    ],
    [
      'JSON that is not an event',
      () => `Nostr ${encodeBase64(new TextEncoder().encode('["EVENT"]'))}`,
    ],
    ['an oversized header', () => `Nostr ${'A'.repeat(8192)}`],
  ])('rejects %s', async (_case, header) => {
    const d = deployment();
    const event = signHttpAuthEvent(admin);
    const response = await send(d.env, LOGIN_URL, {
      method: 'POST',
      authorization: header(event),
    });
    await expectError(response, 401, 'unauthorized', secretsOf(event));
    expect(await adminRows(d.hub)).toMatchObject({ sessions: [], events: [] });
  });
});

describe('NIP-98 replay prevention', () => {
  it('does not accept the same event twice', async () => {
    const d = deployment();
    const event = signHttpAuthEvent(admin);
    expect((await postLogin(d, event)).status).toBe(200);

    const replay = await postLogin(d, event);
    await expectError(replay, 401, 'unauthorized', secretsOf(event));
    const { sessions, events } = await adminRows(d.hub);
    expect(sessions).toHaveLength(1);
    expect(events).toEqual([
      { event_id: event.id, expires_at: expect.any(Number) },
    ]);
  });

  it('lets only one of concurrent logins with the same event succeed', async () => {
    const d = deployment();
    const event = signHttpAuthEvent(admin);
    const responses = await Promise.all(
      Array.from({ length: 8 }, () => postLogin(d, event)),
    );

    const statuses = responses.map(({ status }) => status).sort();
    expect(statuses).toEqual([200, 401, 401, 401, 401, 401, 401, 401]);
    expect(responses.flatMap((r) => setCookies(r))).toHaveLength(1);
    const { sessions, events } = await adminRows(d.hub);
    expect(sessions).toHaveLength(1);
    expect(events).toHaveLength(1);
  });

  it('rejects a replay that carries a different body', async () => {
    const d = deployment();
    const event = signHttpAuthEvent(admin);
    await postLogin(d, event);
    const replay = await postLogin(d, event, { body: 'other' });
    expect(replay.status).toBe(401);
  });

  it('rejects a replay after logout', async () => {
    const d = deployment();
    const event = signHttpAuthEvent(admin);
    const [{ value: token }] = setCookies(await postLogin(d, event));
    expect((await postLogout(d, token)).status).toBe(204);

    await expectError(await postLogin(d, event), 401, 'unauthorized');
    expect((await adminRows(d.hub)).sessions).toEqual([]);
  });

  it('accepts a different event from the same administrator', async () => {
    const d = deployment();
    await logIn(d);
    await logIn(d);
    expect((await adminRows(d.hub)).sessions).toHaveLength(2);
  });
});

describe('GET /admin/api/session', () => {
  it('reports the administrator for a valid session cookie', async () => {
    setNow(T0);
    const d = deployment();
    const token = await logIn(d);

    const response = await getSession(d, token);
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.getSetCookie()).toEqual([]);
    const text = await response.text();
    expect(JSON.parse(text)).toEqual({
      pubkey: admin.pubkey,
      expiresAt: T0 + TWELVE_HOURS,
    });
    expect(text).not.toContain(token);
    expect(text).not.toContain(await tokenHash(token));
  });

  it('does not require an Origin header', async () => {
    const d = deployment();
    const token = await logIn(d);
    const response = await send(d.env, SESSION_URL, { token, origin: null });
    expect(response.status).toBe(200);
  });

  it.each<[string, (token: string) => string | undefined]>([
    ['no cookie', () => undefined],
    ['an unknown token', () => 'ab'.repeat(32)],
    ['a malformed token', (token) => token.slice(1)],
    ['an uppercase token', (token) => token.toUpperCase()],
    ['the token hash', () => '00'.repeat(32)],
  ])('rejects %s', async (_case, presented) => {
    const d = deployment();
    const token = await logIn(d);
    await expectError(
      await getSession(d, presented(token)),
      401,
      'unauthorized',
      [token],
    );
  });

  it('ignores the token under a cookie name without the __Secure- prefix', async () => {
    const d = deployment();
    const token = await logIn(d);
    const response = await send(d.env, SESSION_URL, {
      headers: { Cookie: `signflare_admin_session=${token}` },
    });
    await expectError(response, 401, 'unauthorized', [token]);
  });

  it('rejects an expired session and removes it', async () => {
    setNow(T0);
    const d = deployment();
    const token = await logIn(d);

    setNow(T0 + TWELVE_HOURS - 1);
    expect((await getSession(d, token)).status).toBe(200);

    setNow(T0 + TWELVE_HOURS);
    await expectError(await getSession(d, token), 401, 'unauthorized', [token]);
    expect((await adminRows(d.hub)).sessions).toEqual([]);
  });

  it('does not extend the session when it is used', async () => {
    setNow(T0);
    const d = deployment();
    const token = await logIn(d);
    const before = (await adminRows(d.hub)).sessions;

    for (const offset of [1, 60 * 60, 6 * 60 * 60, TWELVE_HOURS - 1]) {
      setNow(T0 + offset);
      const response = await getSession(d, token);
      expect(await response.json()).toEqual({
        pubkey: admin.pubkey,
        expiresAt: T0 + TWELVE_HOURS,
      });
      expect(response.headers.getSetCookie()).toEqual([]);
    }
    expect((await adminRows(d.hub)).sessions).toEqual(before);

    setNow(T0 + TWELVE_HOURS);
    expect((await getSession(d, token)).status).toBe(401);
  });

  it('rejects a session issued before ADMIN_PUBKEY changed', async () => {
    const d = deployment();
    const token = await logIn(d);
    const changed = withAdminPubkey(d, other.pubkey);

    await expectError(await getSession(changed, token), 401, 'unauthorized');
    expect((await adminRows(d.hub)).sessions).toEqual([]);
    // Reverting the configuration does not revive it.
    expect((await getSession(d, token)).status).toBe(401);

    const otherToken = await logIn(changed, other);
    expect(await (await getSession(changed, otherToken)).json()).toMatchObject({
      pubkey: other.pubkey,
    });
  });
});

describe('POST /admin/api/logout', () => {
  it('ends the session and clears the cookie', async () => {
    const d = deployment();
    const token = await logIn(d);

    const response = await postLogout(d, token);
    expect(response.status).toBe(204);
    expect(await response.text()).toBe('');
    const [cookie, ...rest] = setCookies(response);
    expect(rest).toEqual([]);
    expect(cookie.name).toBe(COOKIE_NAME);
    expect(cookie.value).toBe('');
    expect(cookie.attributes).toEqual(
      expect.arrayContaining([
        'Max-Age=0',
        'Path=/admin',
        'HttpOnly',
        'Secure',
        'SameSite=Strict',
      ]),
    );

    expect((await adminRows(d.hub)).sessions).toEqual([]);
    await expectError(await getSession(d, token), 401, 'unauthorized', [token]);
    await expectError(await postLogout(d, token), 401, 'unauthorized', [token]);
  });

  it('keeps other sessions', async () => {
    const d = deployment();
    const first = await logIn(d);
    const second = await logIn(d);
    expect((await postLogout(d, first)).status).toBe(204);
    expect((await getSession(d, second)).status).toBe(200);
    expect((await adminRows(d.hub)).sessions).toHaveLength(1);
  });

  it('requires a valid session', async () => {
    const d = deployment();
    await expectError(await postLogout(d), 401, 'unauthorized');
    await expectError(
      await postLogout(d, 'ab'.repeat(32)),
      401,
      'unauthorized',
    );
  });

  it('rejects an expired session', async () => {
    setNow(T0);
    const d = deployment();
    const token = await logIn(d);
    setNow(T0 + TWELVE_HOURS);
    await expectError(await postLogout(d, token), 401, 'unauthorized');
  });
});

describe('same-origin protection', () => {
  const mismatched = [
    ['another host', 'https://evil.example'],
    ['another scheme', 'http://signflare.example'],
    ['another port', 'https://signflare.example:8443'],
    ['a subdomain', 'https://admin.signflare.example'],
    ['an opaque origin', 'null'],
    ['a trailing slash', `${ORIGIN}/`],
    ['different letter case', ORIGIN.toUpperCase()],
  ];

  it('accepts same-origin login and logout', async () => {
    const d = deployment();
    const login = await postLogin(d, signHttpAuthEvent(admin), {
      origin: ORIGIN,
    });
    expect(login.status).toBe(200);
    const [{ value: token }] = setCookies(login);
    expect((await postLogout(d, token, { origin: ORIGIN })).status).toBe(204);
  });

  it.each(mismatched)(
    'rejects login from %s before authenticating',
    async (_case, origin) => {
      const d = deployment();
      const event = signHttpAuthEvent(admin);
      await expectError(
        await postLogin(d, event, { origin }),
        403,
        'forbidden',
        secretsOf(event),
      );
      expect(await adminRows(d.hub)).toMatchObject({
        sessions: [],
        events: [],
      });
      // The event was not consumed by the rejected request.
      expect((await postLogin(d, event)).status).toBe(200);
    },
  );

  it.each(mismatched)('rejects logout from %s', async (_case, origin) => {
    const d = deployment();
    const token = await logIn(d);
    await expectError(
      await postLogout(d, token, { origin }),
      403,
      'forbidden',
      [token],
    );
    expect((await getSession(d, token)).status).toBe(200);
  });

  it('rejects state-changing requests without an Origin header', async () => {
    const d = deployment();
    const event = signHttpAuthEvent(admin);
    await expectError(
      await postLogin(d, event, { origin: null }),
      403,
      'forbidden',
      secretsOf(event),
    );
    const token = await logIn(d);
    await expectError(
      await postLogout(d, token, { origin: null }),
      403,
      'forbidden',
      [token],
    );
    expect((await getSession(d, token)).status).toBe(200);
  });

  it('compares against the origin of the URL the Worker received', async () => {
    const d = deployment();
    const url = 'https://alt.example:8443/admin/api/login';
    const event = signHttpAuthEvent(admin, {
      tags: [
        ['u', url],
        ['method', 'POST'],
      ],
    });
    expect(
      (await postLogin(d, event, { url, origin: 'https://alt.example:8443' }))
        .status,
    ).toBe(200);
    await expectError(
      await postLogin(d, signHttpAuthEvent(admin), {
        origin: 'https://alt.example:8443',
      }),
      403,
      'forbidden',
    );
  });

  it.each(['PUT', 'PATCH', 'DELETE'])(
    'applies to %s requests as well',
    async (method) => {
      const d = deployment();
      const token = await logIn(d);
      await expectError(
        await send(d.env, SESSION_URL, {
          method,
          token,
          origin: 'https://evil.example',
        }),
        403,
        'forbidden',
      );
    },
  );
});

describe('ADMIN_PUBKEY configuration', () => {
  it.each<[string, () => Deployment]>([
    ['missing', unconfiguredDeployment],
    ['empty', () => deployment('')],
    ['uppercase', () => deployment(admin.pubkey.toUpperCase())],
    ['too short', () => deployment(admin.pubkey.slice(2))],
    ['too long', () => deployment(`${admin.pubkey}00`)],
    ['not hex', () => deployment('zz'.repeat(32))],
    ['surrounded by whitespace', () => deployment(` ${admin.pubkey} `)],
    ['an npub', () => deployment(npubEncode(admin.pubkey))],
    ['not a string', () => deployment(42)],
  ])(
    'reports a server configuration error when it is %s',
    async (_case, configure) => {
      const log = vi.spyOn(console, 'error').mockImplementation(() => {});
      const d = configure();
      const event = signHttpAuthEvent(admin);
      const configured: unknown = d.env.ADMIN_PUBKEY;
      // Neither the request nor the rejected configuration value is echoed.
      const forbidden = [
        ...secretsOf(event),
        ...(typeof configured === 'string' && configured.trim() !== ''
          ? [configured.trim()]
          : []),
      ];

      await expectError(
        await postLogin(d, event),
        500,
        'server configuration error',
        forbidden,
      );
      await expectError(
        await getSession(d, 'ab'.repeat(32)),
        500,
        'server configuration error',
        forbidden,
      );
      await expectError(
        await postLogout(d, 'ab'.repeat(32)),
        500,
        'server configuration error',
        forbidden,
      );
      expect(await adminRows(d.hub)).toMatchObject({
        sessions: [],
        events: [],
      });
      expect(log).toHaveBeenCalled();
      for (const call of log.mock.calls) {
        for (const value of forbidden) {
          expect(call.join(' ')).not.toContain(value);
        }
      }
    },
  );

  it('is not configured by the repository', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const response = await exports.default.fetch(SESSION_URL);
    await expectError(response, 500, 'server configuration error');
    const login = await exports.default.fetch(LOGIN_URL, {
      method: 'POST',
      headers: {
        Origin: ORIGIN,
        Authorization: nostrAuthorization(signHttpAuthEvent(admin)),
      },
    });
    await expectError(login, 500, 'server configuration error');
    expect(log).toHaveBeenCalled();
  });
});

describe('error responses', () => {
  it('map unexpected failures to a generic error', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const d = deployment();
    const token = 'ab'.repeat(32);
    const detail = `SQLITE internal detail for ${token}`;
    const failing = {
      ...d,
      env: {
        ...d.env,
        SIGNER_HUB: {
          getByName: () => ({
            authenticateAdminSession: () => Promise.reject(new Error(detail)),
          }),
        } as unknown as Env['SIGNER_HUB'],
      },
    };

    await expectError(await getSession(failing, token), 500, 'internal error', [
      token,
      detail,
    ]);
    expect(log.mock.calls).toEqual([['Admin API request failed:', 'Error']]);
  });

  it('never expose the authorization or session token', async () => {
    const d = deployment();
    const token = await logIn(d);
    const event = signHttpAuthEvent(admin);
    await postLogin(d, event);
    const responses = [
      await postLogin(d, event),
      await postLogin(d, { ...event, sig: tamperHex(event.sig) }),
      await postLogin(d, signHttpAuthEvent(other)),
      await send(d.env, LOGIN_URL, {
        method: 'POST',
        authorization: `${nostrAuthorization(event)}===`,
      }),
      await postLogin(d, event, { origin: 'https://evil.example', token }),
      await getSession(withAdminPubkey(d, other.pubkey), token),
      await getSession(d, token),
      await postLogout(d, token),
    ];
    for (const response of responses) {
      expect(response.status).toBeGreaterThanOrEqual(400);
      await expectError(
        response,
        response.status,
        response.status === 403 ? 'forbidden' : 'unauthorized',
        secretsOf(event, token, await tokenHash(token)),
      );
    }
  });
});
