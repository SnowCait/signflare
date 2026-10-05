import { env, exports } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { npubEncode, nsecEncode } from 'nostr-tools/nip19';
import type { NostrEvent } from 'nostr-tools/pure';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  MAX_IDENTITY_BODY_BYTES,
  MAX_LOGIN_BODY_BYTES,
} from '../src/admin-api';
import type { SignflareBindings } from '../src/config';
import app from '../src/index';
import { withDecryptedPrivateKey } from '../src/private-key-encryption';
import type { SignerHub } from '../src/signer-hub';
import {
  allStoredValues,
  instrumentHubSql,
  NON_DELETE_WRITE,
  recordingMasterKeyReads,
  replaceHubEnv,
  setMasterEncryptionKey,
  SQLITE_FULL_MESSAGE,
  TEST_MASTER_ENCRYPTION_KEY,
  valuesContainingSecret,
} from './hub-helpers';
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
  unixNow,
} from './nostr-helpers';

const COOKIE_NAME = '__Secure-signflare_admin_session';
const SESSION_URL = `${ORIGIN}/admin/api/session`;
const LOGOUT_URL = `${ORIGIN}/admin/api/logout`;
const IDENTITIES_URL = `${ORIGIN}/admin/api/identities`;
const TWELVE_HOURS = 12 * 60 * 60;
const T0 = 1_800_000_000;

// Test-only fixtures: trivially guessable scalars that must never hold funds or identity.
const SECRET_ONE_HEX = `${'00'.repeat(31)}01`;
const SECRET_ONE_NSEC =
  'nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsmhltgl';
const PUBKEY_ONE =
  '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const SECRET_THREE_HEX = `${'00'.repeat(31)}03`;
const PUBKEY_THREE =
  'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';

const admin = randomKey();
const other = randomKey();

interface Deployment {
  readonly env: SignflareBindings;
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
  const unconfigured: SignflareBindings = { ...d.env };
  delete unconfigured.ADMIN_PUBKEY;
  return { ...d, env: unconfigured };
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
  testEnv: SignflareBindings,
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

function getIdentities(
  d: Deployment,
  token?: string,
  options: RequestOptions = {},
): Promise<Response> {
  return send(d.env, IDENTITIES_URL, { token, ...options });
}

function postIdentity(
  d: Deployment,
  token: string | undefined,
  body: BodyInit,
  options: RequestOptions = {},
): Promise<Response> {
  return send(d.env, IDENTITIES_URL, {
    method: 'POST',
    token,
    body,
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
}

function deleteIdentity(
  d: Deployment,
  pubkey: string,
  token?: string,
  options: RequestOptions = {},
): Promise<Response> {
  return send(d.env, `${IDENTITIES_URL}/${pubkey}`, {
    method: 'DELETE',
    token,
    ...options,
  });
}

function registration(privateKey: unknown): string {
  return JSON.stringify({ privateKey });
}

// A deployment whose SignerHub uses the test-only MASTER_ENCRYPTION_KEY
// rather than anything from the local environment, with a logged in
// administrator.
async function signedIn(): Promise<{ d: Deployment; token: string }> {
  const d = deployment();
  await setMasterEncryptionKey(d.hub, TEST_MASTER_ENCRYPTION_KEY);
  return { d, token: await logIn(d) };
}

async function register(
  d: Deployment,
  token: string,
  privateKey: string,
): Promise<void> {
  const response = await postIdentity(d, token, registration(privateKey));
  expect(response.status).toBe(201);
}

type IdentityRow = {
  pubkey: string;
  encrypted_private_key: ArrayBuffer;
  iv: ArrayBuffer;
  kdf_salt: ArrayBuffer;
  key_version: number;
  created_at: number;
  updated_at: number;
};

function identityRows(
  hub: DurableObjectStub<SignerHub>,
): Promise<IdentityRow[]> {
  return runInDurableObject(hub, (_instance, state) =>
    state.storage.sql
      .exec<IdentityRow>('SELECT * FROM identities ORDER BY created_at, pubkey')
      .toArray(),
  );
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

// Forms in which key material could leak into a response or a log.
function privateKeyForms(secretKey: Uint8Array): string[] {
  const hex = bytesToHex(secretKey);
  return [hex, hex.toUpperCase(), nsecEncode(secretKey)];
}

const MASTER_KEY_FORMS = [
  TEST_MASTER_ENCRYPTION_KEY,
  bytesToHex(utf8(TEST_MASTER_ENCRYPTION_KEY)),
  encodeBase64(utf8(TEST_MASTER_ENCRYPTION_KEY)),
];

function envelopeForms(row: IdentityRow): string[] {
  return [row.encrypted_private_key, row.iv, row.kdf_salt].flatMap((value) => {
    const bytes = new Uint8Array(value);
    return [bytesToHex(bytes), encodeBase64(bytes)];
  });
}

const SQL_DETAILS = /SQLITE|\b(SELECT|INSERT|UPDATE|DELETE FROM)\b|identities/;

function captureLogs() {
  return (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
    vi.spyOn(console, method).mockImplementation(() => {}),
  );
}

function loggedCalls(logs: ReturnType<typeof captureLogs>): unknown[][] {
  return logs.flatMap((log) => log.mock.calls);
}

function expectSafeLogs(
  logs: ReturnType<typeof captureLogs>,
  secrets: readonly string[],
): void {
  const text = loggedCalls(logs)
    .flat()
    .map((value) => (value instanceof Error ? `${value.stack}` : String(value)))
    .join('\n');
  expect(text).not.toMatch(SQL_DETAILS);
  expect(text).not.toMatch(/\n\s+at\s/);
  for (const secret of secrets) {
    expect(text).not.toContain(secret);
  }
}

async function pairWith(
  hub: DurableObjectStub<SignerHub>,
  identity: string,
): Promise<string> {
  const result = await hub.createPairing(identity, 'all', unixNow());
  if (result.status !== 'created') {
    throw new Error(result.status);
  }
  return result.secret;
}

async function connectClient(
  hub: DurableObjectStub<SignerHub>,
  identity: string,
): Promise<string> {
  const clientPubkey = randomKey().pubkey;
  const result = await hub.establishSession({
    secret: await pairWith(hub, identity),
    clientPubkey,
    now: unixNow(),
  });
  if (result.status !== 'created') {
    throw new Error(result.status);
  }
  return clientPubkey;
}

function relatedRows(hub: DurableObjectStub<SignerHub>, ...pubkeys: string[]) {
  return runInDurableObject(hub, (_instance, state) =>
    pubkeys.map((pubkey) => {
      const count = (query: string) =>
        state.storage.sql.exec<{ count: number }>(query, pubkey).one().count;
      return {
        identities: count(
          'SELECT COUNT(*) AS count FROM identities WHERE pubkey = ?',
        ),
        pairings: count(
          'SELECT COUNT(*) AS count FROM pairings WHERE identity_pubkey = ?',
        ),
        sessions: count(
          'SELECT COUNT(*) AS count FROM sessions WHERE identity_pubkey = ?',
        ),
      };
    }),
  );
}

// A SIGNER_HUB binding whose stub records each RPC call into `calls` and
// replaces the methods in `overrides`.
function stubNamespace(
  hub: DurableObjectStub<SignerHub>,
  options: {
    calls?: [string, unknown[]][];
    overrides?: Record<string, (...args: unknown[]) => unknown>;
  } = {},
): Env['SIGNER_HUB'] {
  const rpc = hub as unknown as Record<string, (...args: unknown[]) => unknown>;
  const stub = new Proxy(
    {},
    {
      get(_target, method) {
        if (typeof method !== 'string' || method === 'then') {
          return undefined;
        }
        return (...args: unknown[]) => {
          options.calls?.push([method, args]);
          const override = options.overrides?.[method];
          return override ? override(...args) : rpc[method](...args);
        };
      },
    },
  );
  return { getByName: () => stub } as unknown as Env['SIGNER_HUB'];
}

function withSignerHub(
  d: Deployment,
  namespace: Env['SIGNER_HUB'],
): Deployment {
  return { ...d, env: { ...d.env, SIGNER_HUB: namespace } };
}

function tamperNsec(nsec: string): string {
  return `${nsec.slice(0, -1)}${nsec.endsWith('q') ? 'p' : 'q'}`;
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
    expect(env).not.toHaveProperty('ADMIN_PUBKEY');
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

describe('POST /admin/api/identities', () => {
  it('registers an identity from an nsec', async () => {
    setNow(T0);
    const { d, token } = await signedIn();
    const response = await postIdentity(
      d,
      token,
      registration(SECRET_ONE_NSEC),
    );

    expect(response.status).toBe(201);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('Content-Type')).toMatch(/^application\/json/);
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(await response.json()).toEqual({
      pubkey: PUBKEY_ONE,
      npub: npubEncode(PUBKEY_ONE),
      createdAt: T0,
      updatedAt: T0,
    });
  });

  it.each<[string, string]>([
    ['64-character hex', SECRET_THREE_HEX],
    ['uppercase hex', SECRET_THREE_HEX.toUpperCase()],
    ['hex surrounded by whitespace', ` ${SECRET_THREE_HEX}\n`],
  ])('registers an identity from %s', async (_case, privateKey) => {
    setNow(T0);
    const { d, token } = await signedIn();
    const response = await postIdentity(d, token, registration(privateKey));
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({
      pubkey: PUBKEY_THREE,
      npub: npubEncode(PUBKEY_THREE),
      createdAt: T0,
      updatedAt: T0,
    });
  });

  it('returns public identity metadata only', async () => {
    const { d, token } = await signedIn();
    const key = randomKey();
    const response = await postIdentity(
      d,
      token,
      registration(nsecEncode(key.secretKey)),
    );
    expect(response.status).toBe(201);
    const text = await response.text();
    const identity = JSON.parse(text);

    expect(Object.keys(identity).sort()).toEqual([
      'createdAt',
      'npub',
      'pubkey',
      'updatedAt',
    ]);
    expect(identity.pubkey).toBe(key.pubkey);
    expect(identity.pubkey).toMatch(/^[0-9a-f]{64}$/);
    expect(identity.npub).toBe(npubEncode(key.pubkey));
    const [row] = await identityRows(d.hub);
    for (const secret of [
      ...privateKeyForms(key.secretKey),
      ...MASTER_KEY_FORMS,
      ...envelopeForms(row),
      token,
    ]) {
      expect(text).not.toContain(secret);
    }
  });

  it('stores the private key only as an encrypted envelope', async () => {
    setNow(T0);
    const { d, token } = await signedIn();
    const key = randomKey();
    await register(d, token, nsecEncode(key.secretKey));

    const [row, ...rest] = await identityRows(d.hub);
    expect(rest).toEqual([]);
    expect(row).toMatchObject({
      pubkey: key.pubkey,
      key_version: 1,
      created_at: T0,
      updated_at: T0,
    });
    expect(row.encrypted_private_key.byteLength).toBe(48);
    expect(row.iv.byteLength).toBe(12);
    expect(row.kdf_salt.byteLength).toBe(32);
    // Encrypted under the exact bytes of the configured secret.
    const decrypted = await withDecryptedPrivateKey(
      utf8(TEST_MASTER_ENCRYPTION_KEY),
      key.pubkey,
      {
        ciphertext: new Uint8Array(row.encrypted_private_key),
        iv: new Uint8Array(row.iv),
        kdfSalt: new Uint8Array(row.kdf_salt),
        keyVersion: row.key_version,
      },
      (secretKey) => bytesToHex(secretKey),
    );
    expect(decrypted).toBe(bytesToHex(key.secretKey));

    await runInDurableObject(d.hub, (_instance, state) => {
      const { sql } = state.storage;
      expect(valuesContainingSecret(sql, bytesToHex(key.secretKey))).toEqual(
        [],
      );
      const nsec = nsecEncode(key.secretKey);
      expect(
        allStoredValues(sql).filter(
          (value) => typeof value === 'string' && value.includes(nsec),
        ),
      ).toEqual([]);
    });
  });

  it('rejects an identity that already exists with 409', async () => {
    const { d, token } = await signedIn();
    await register(d, token, SECRET_ONE_NSEC);
    const before = await identityRows(d.hub);

    for (const privateKey of [
      SECRET_ONE_NSEC,
      SECRET_ONE_HEX,
      SECRET_ONE_HEX.toUpperCase(),
    ]) {
      await expectError(
        await postIdentity(d, token, registration(privateKey)),
        409,
        'identity already exists',
        [privateKey, ...envelopeForms(before[0])],
      );
    }
    expect(await identityRows(d.hub)).toEqual(before);
  });

  it('registers concurrent requests for the same key once', async () => {
    const { d, token } = await signedIn();
    const key = randomKey();
    // Encryption waits until both requests have passed the first duplicate
    // check, so only the check next to the insert can catch the second one.
    const encrypt = crypto.subtle.encrypt.bind(crypto.subtle);
    let encrypting = 0;
    let bothEncrypting: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      bothEncrypting = resolve;
    });
    vi.spyOn(crypto.subtle, 'encrypt').mockImplementation(
      async (algorithm, cryptoKey, data) => {
        if (++encrypting === 2) {
          bothEncrypting();
        }
        await gate;
        return encrypt(algorithm, cryptoKey, data);
      },
    );

    const responses = await Promise.all(
      [nsecEncode(key.secretKey), bytesToHex(key.secretKey)].map((privateKey) =>
        postIdentity(d, token, registration(privateKey)),
      ),
    );
    expect(encrypting).toBe(2);
    expect(responses.map(({ status }) => status).sort()).toEqual([201, 409]);
    expect((await identityRows(d.hub)).map(({ pubkey }) => pubkey)).toEqual([
      key.pubkey,
    ]);
  });

  it.each<[string, string]>([
    ['an nsec with a bad checksum', tamperNsec(SECRET_ONE_NSEC)],
    ['a truncated nsec', SECRET_ONE_NSEC.slice(0, -1)],
    ['an nsec with a prefix', `nostr:${SECRET_ONE_NSEC}`],
    ['an npub', npubEncode(PUBKEY_ONE)],
    ['hex that is too short', SECRET_ONE_HEX.slice(1)],
    ['hex that is too long', `${SECRET_ONE_HEX}0`],
    ['hex with a non-hex digit', `${SECRET_ONE_HEX.slice(0, -1)}g`],
    ['hex for the zero scalar', '00'.repeat(32)],
    ['hex above the curve order', 'ff'.repeat(32)],
    ['an oversized key', 'a'.repeat(200)],
    ['an empty string', ''],
    ['whitespace', '   '],
  ])('rejects %s with 400', async (_case, privateKey) => {
    const { d, token } = await signedIn();
    await expectError(
      await postIdentity(d, token, registration(privateKey)),
      400,
      'invalid private key',
      [privateKey.trim(), SECRET_ONE_HEX, SECRET_ONE_NSEC].filter(Boolean),
    );
    expect(await identityRows(d.hub)).toEqual([]);
  });

  it.each<[string, BodyInit]>([
    ['an empty body', ''],
    ['truncated JSON', `{"privateKey": "${SECRET_ONE_NSEC}`],
    ['a bare nsec', SECRET_ONE_NSEC],
    ['a bare hex key', SECRET_ONE_HEX],
    ['a JSON string', JSON.stringify(SECRET_ONE_NSEC)],
    ['a JSON array', JSON.stringify([SECRET_ONE_NSEC])],
    ['an array of requests', JSON.stringify([{ privateKey: SECRET_ONE_NSEC }])],
    ['null', 'null'],
    ['a number', '42'],
    ['a boolean', 'true'],
    [
      'invalid UTF-8',
      new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]),
    ],
  ])('rejects %s with 400', async (_case, body) => {
    const { d, token } = await signedIn();
    await expectError(
      await postIdentity(d, token, body),
      400,
      'invalid request',
      [SECRET_ONE_NSEC, SECRET_ONE_HEX],
    );
    expect(await identityRows(d.hub)).toEqual([]);
  });

  it.each<[string, Record<string, unknown>]>([
    ['a missing privateKey', {}],
    ['a misspelled field', { private_key: SECRET_ONE_NSEC }],
    ['a numeric privateKey', { privateKey: 1 }],
    ['a null privateKey', { privateKey: null }],
    ['a boolean privateKey', { privateKey: true }],
    ['an array privateKey', { privateKey: [SECRET_ONE_NSEC] }],
    ['an object privateKey', { privateKey: { nsec: SECRET_ONE_NSEC } }],
  ])('rejects %s with 400', async (_case, request) => {
    const { d, token } = await signedIn();
    await expectError(
      await postIdentity(d, token, JSON.stringify(request)),
      400,
      'invalid request',
      [SECRET_ONE_NSEC],
    );
    expect(await identityRows(d.hub)).toEqual([]);
  });

  it(`accepts a body of exactly ${MAX_IDENTITY_BODY_BYTES} bytes`, async () => {
    const { d, token } = await signedIn();
    const body = registration(SECRET_ONE_NSEC).padEnd(
      MAX_IDENTITY_BODY_BYTES,
      ' ',
    );
    expect(utf8(body).byteLength).toBe(MAX_IDENTITY_BODY_BYTES);
    expect((await postIdentity(d, token, body)).status).toBe(201);
  });

  it('rejects a larger body before parsing it', async () => {
    const { d, token } = await signedIn();
    const body = registration(SECRET_ONE_NSEC).padEnd(
      MAX_IDENTITY_BODY_BYTES + 1,
      ' ',
    );
    await expectError(
      await postIdentity(d, token, body),
      413,
      'payload too large',
      [SECRET_ONE_NSEC],
    );
    const streamed = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(utf8(registration(SECRET_ONE_NSEC)));
        controller.enqueue(new Uint8Array(MAX_IDENTITY_BODY_BYTES));
        controller.close();
      },
    });
    await expectError(
      await postIdentity(d, token, streamed),
      413,
      'payload too large',
      [SECRET_ONE_NSEC],
    );
    expect(await identityRows(d.hub)).toEqual([]);
  });

  it('reports full storage with 507 and stores nothing', async () => {
    const log = captureLogs();
    const { d, token } = await signedIn();
    await instrumentHubSql(d.hub, {
      failing: NON_DELETE_WRITE,
      message: SQLITE_FULL_MESSAGE,
    });
    const key = randomKey();
    await expectError(
      await postIdentity(d, token, registration(nsecEncode(key.secretKey))),
      507,
      'insufficient storage',
      [...privateKeyForms(key.secretKey), ...MASTER_KEY_FORMS, token],
    );
    expect(loggedCalls(log)).toEqual([
      ['Identity registration failed: storage is full'],
    ]);
    vi.restoreAllMocks();
    expect(await identityRows(d.hub)).toEqual([]);
  });

  it.each<[string, unknown]>([
    ['missing', undefined],
    ['empty', ''],
    ['shorter than 32 bytes', 'test-only master key: 31 bytes!'],
    ['not a string', 12_345],
  ])(
    'reports a server configuration error when MASTER_ENCRYPTION_KEY is %s',
    async (_case, masterKey) => {
      const log = captureLogs();
      const { d, token } = await signedIn();
      await setMasterEncryptionKey(d.hub, masterKey);
      const key = randomKey();
      const forbidden = [
        ...privateKeyForms(key.secretKey),
        ...(typeof masterKey === 'string' && masterKey !== ''
          ? [masterKey]
          : []),
        token,
      ];

      await expectError(
        await postIdentity(d, token, registration(nsecEncode(key.secretKey))),
        500,
        'server configuration error',
        forbidden,
      );
      expect(loggedCalls(log)).toEqual([
        ['MASTER_ENCRYPTION_KEY must be set to a secret of at least 32 bytes'],
      ]);
      expectSafeLogs(log, forbidden);
      expect(await identityRows(d.hub)).toEqual([]);
    },
  );

  it('leaves MASTER_ENCRYPTION_KEY to the SignerHub', async () => {
    const { d, token } = await signedIn();
    const calls: [string, unknown[]][] = [];
    const workerReads: string[] = [];
    const hubReads: string[] = [];
    await replaceHubEnv(d.hub, (hubEnv) =>
      recordingMasterKeyReads(hubEnv, hubReads),
    );
    // The Worker is bound to the secret as well, as in a deployment.
    const recorded: Deployment = {
      ...d,
      env: recordingMasterKeyReads(
        {
          ...d.env,
          MASTER_ENCRYPTION_KEY: TEST_MASTER_ENCRYPTION_KEY,
          SIGNER_HUB: stubNamespace(d.hub, { calls }),
        },
        workerReads,
      ),
    };

    const response = await postIdentity(
      recorded,
      token,
      registration(SECRET_ONE_NSEC),
    );
    expect(response.status).toBe(201);
    expect(workerReads).toEqual([]);
    expect(hubReads).toEqual(['MASTER_ENCRYPTION_KEY']);
    expect(calls.map(([method]) => method)).toEqual([
      'authenticateAdminSession',
      'registerIdentity',
    ]);
    expect(calls[1][1]).toEqual([SECRET_ONE_NSEC, expect.any(Number)]);
    expect(JSON.stringify(calls)).not.toContain(TEST_MASTER_ENCRYPTION_KEY);
  });
});

describe('GET /admin/api/identities', () => {
  it('returns an empty list when no identity is registered', async () => {
    const { d, token } = await signedIn();
    const response = await getIdentities(d, token);
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.get('Content-Type')).toMatch(/^application\/json/);
    expect(await response.json()).toEqual([]);
  });

  it('lists identities oldest first, then by pubkey', async () => {
    setNow(T0);
    const { d, token } = await signedIn();
    const tied = randomKey();
    setNow(T0 + 20);
    await register(d, token, SECRET_THREE_HEX);
    setNow(T0 + 10);
    await register(d, token, bytesToHex(tied.secretKey));
    await register(d, token, SECRET_ONE_NSEC);
    const metadata = (pubkey: string, createdAt: number) => ({
      pubkey,
      npub: npubEncode(pubkey),
      createdAt,
      updatedAt: createdAt,
    });
    const expected = [
      ...[tied.pubkey, PUBKEY_ONE]
        .sort()
        .map((pubkey) => metadata(pubkey, T0 + 10)),
      metadata(PUBKEY_THREE, T0 + 20),
    ];

    expect(await (await getIdentities(d, token)).json()).toEqual(expected);
    expect(await (await getIdentities(d, token)).json()).toEqual(expected);
  });

  it('exposes public metadata only', async () => {
    const { d, token } = await signedIn();
    const keys = [randomKey(), randomKey()];
    for (const key of keys) {
      await register(d, token, nsecEncode(key.secretKey));
    }
    const response = await getIdentities(d, token);
    const text = await response.text();
    const identities: Record<string, unknown>[] = JSON.parse(text);

    expect(identities).toHaveLength(2);
    for (const identity of identities) {
      expect(Object.keys(identity).sort()).toEqual([
        'createdAt',
        'npub',
        'pubkey',
        'updatedAt',
      ]);
    }
    const rows = await identityRows(d.hub);
    for (const secret of [
      ...keys.flatMap((key) => privateKeyForms(key.secretKey)),
      ...rows.flatMap(envelopeForms),
      ...MASTER_KEY_FORMS,
      token,
    ]) {
      expect(text).not.toContain(secret);
    }
  });

  it('reads neither key material nor MASTER_ENCRYPTION_KEY', async () => {
    const { d, token } = await signedIn();
    await register(d, token, SECRET_ONE_NSEC);
    const reads: string[] = [];
    await replaceHubEnv(d.hub, (hubEnv) =>
      recordingMasterKeyReads(hubEnv, reads),
    );
    const statements: string[] = [];
    await instrumentHubSql(d.hub, { statements });

    expect((await getIdentities(d, token)).status).toBe(200);
    expect(reads).toEqual([]);
    expect(statements.length).toBeGreaterThan(0);
    for (const statement of statements) {
      expect(statement).toMatch(/^SELECT /);
      expect(statement).not.toMatch(
        /\*|\b(encrypted_private_key|iv|kdf_salt|key_version)\b/,
      );
    }
  });

  it('works without MASTER_ENCRYPTION_KEY', async () => {
    const { d, token } = await signedIn();
    await register(d, token, SECRET_ONE_NSEC);
    await setMasterEncryptionKey(d.hub, undefined);
    const response = await getIdentities(d, token);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject([{ pubkey: PUBKEY_ONE }]);
  });
});

describe('DELETE /admin/api/identities/:pubkey', () => {
  // The identity to delete has two sessions and two unused pairings, the
  // other identity one of each.
  async function populated() {
    const { d, token } = await signedIn();
    const targetKey = randomKey();
    const otherKey = randomKey();
    await register(d, token, bytesToHex(targetKey.secretKey));
    await register(d, token, bytesToHex(otherKey.secretKey));
    const target = targetKey.pubkey;
    const other = otherKey.pubkey;
    return {
      d,
      token,
      target,
      other,
      targetClients: [
        await connectClient(d.hub, target),
        await connectClient(d.hub, target),
      ],
      targetSecrets: [
        await pairWith(d.hub, target),
        await pairWith(d.hub, target),
      ],
      otherClient: await connectClient(d.hub, other),
      otherSecret: await pairWith(d.hub, other),
    };
  }

  it('deletes the identity with its sessions and unused pairings', async () => {
    const { d, token, target, other } = await populated();
    expect(await relatedRows(d.hub, target, other)).toEqual([
      { identities: 1, pairings: 2, sessions: 2 },
      { identities: 1, pairings: 1, sessions: 1 },
    ]);

    const response = await deleteIdentity(d, target, token);
    expect(response.status).toBe(204);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(await response.text()).toBe('');

    expect(await relatedRows(d.hub, target, other)).toEqual([
      { identities: 0, pairings: 0, sessions: 0 },
      { identities: 1, pairings: 1, sessions: 1 },
    ]);
    expect(await (await getIdentities(d, token)).json()).toMatchObject([
      { pubkey: other },
    ]);
  });

  it('leaves no client or pairing secret of the identity usable', async () => {
    const { d, token, target, targetClients, targetSecrets } =
      await populated();
    expect((await deleteIdentity(d, target, token)).status).toBe(204);

    for (const clientPubkey of targetClients) {
      expect(await d.hub.getSession(clientPubkey)).toBeNull();
    }
    for (const secret of targetSecrets) {
      expect(
        await d.hub.establishSession({
          secret,
          clientPubkey: randomKey().pubkey,
          now: unixNow(),
        }),
      ).toEqual({ status: 'invalid_secret' });
    }
  });

  it('keeps the sessions and pairings of other identities', async () => {
    const { d, token, target, other, otherClient, otherSecret } =
      await populated();
    const session = await d.hub.getSession(otherClient);
    expect((await deleteIdentity(d, target, token)).status).toBe(204);

    expect(await d.hub.getSession(otherClient)).toEqual(session);
    expect(
      await d.hub.establishSession({
        secret: otherSecret,
        clientPubkey: randomKey().pubkey,
        now: unixNow(),
      }),
    ).toMatchObject({ status: 'created', session: { identityPubkey: other } });
  });

  it('returns 404 for an identity that does not exist', async () => {
    const { d, token, target, other } = await populated();
    const before = await relatedRows(d.hub, target, other);
    await expectError(
      await deleteIdentity(d, randomKey().pubkey, token),
      404,
      'not found',
      [token],
    );
    expect(await relatedRows(d.hub, target, other)).toEqual(before);

    expect((await deleteIdentity(d, target, token)).status).toBe(204);
    await expectError(await deleteIdentity(d, target, token), 404, 'not found');
  });

  it.each<[string, (pubkey: string) => string]>([
    ['uppercase hex', (pubkey) => pubkey.toUpperCase()],
    ['63 characters', (pubkey) => pubkey.slice(1)],
    ['65 characters', (pubkey) => `${pubkey}0`],
    ['an npub', (pubkey) => npubEncode(pubkey)],
    ['non-hex characters', () => 'zz'.repeat(32)],
    ['leading whitespace', (pubkey) => `%20${pubkey}`],
    ['a trailing NUL', (pubkey) => `${pubkey}%00`],
  ])('rejects a pubkey given as %s with 400', async (_case, malformed) => {
    const { d, token, target, other } = await populated();
    const before = await relatedRows(d.hub, target, other);
    await expectError(
      await deleteIdentity(d, malformed(target), token),
      400,
      'invalid pubkey',
      [token],
    );
    expect(await relatedRows(d.hub, target, other)).toEqual(before);
  });

  it('needs no MASTER_ENCRYPTION_KEY and never reads it', async () => {
    const { d, token, target } = await populated();
    await setMasterEncryptionKey(d.hub, undefined);
    const workerReads: string[] = [];
    const hubReads: string[] = [];
    await replaceHubEnv(d.hub, (hubEnv) =>
      recordingMasterKeyReads(hubEnv, hubReads),
    );
    const recorded: Deployment = {
      ...d,
      env: recordingMasterKeyReads(d.env, workerReads),
    };

    expect((await deleteIdentity(recorded, target, token)).status).toBe(204);
    expect(workerReads).toEqual([]);
    expect(hubReads).toEqual([]);
    expect(await relatedRows(d.hub, target)).toEqual([
      { identities: 0, pairings: 0, sessions: 0 },
    ]);
  });

  it('works when every write other than DELETE fails with SQLITE_FULL', async () => {
    const { d, token, target, other } = await populated();
    const statements: string[] = [];
    await instrumentHubSql(d.hub, {
      failing: NON_DELETE_WRITE,
      message: SQLITE_FULL_MESSAGE,
      statements,
    });

    expect((await deleteIdentity(d, target, token)).status).toBe(204);
    expect(statements.length).toBeGreaterThan(0);
    for (const statement of statements) {
      expect(statement).toMatch(/^(SELECT|DELETE) /);
    }
    vi.restoreAllMocks();
    expect(await relatedRows(d.hub, target, other)).toEqual([
      { identities: 0, pairings: 0, sessions: 0 },
      { identities: 1, pairings: 1, sessions: 1 },
    ]);
  });
});

describe('identity management on full storage', () => {
  it('stays recoverable through an admin session that predates it', async () => {
    const log = captureLogs();
    const { d, token } = await signedIn();
    const kept = randomKey();
    const removed = randomKey();
    await register(d, token, bytesToHex(kept.secretKey));
    await register(d, token, bytesToHex(removed.secretKey));
    await connectClient(d.hub, removed.pubkey);
    await pairWith(d.hub, removed.pubkey);
    await instrumentHubSql(d.hub, {
      failing: NON_DELETE_WRITE,
      message: SQLITE_FULL_MESSAGE,
    });

    const added = randomKey();
    await expectError(
      await postIdentity(d, token, registration(bytesToHex(added.secretKey))),
      507,
      'insufficient storage',
      privateKeyForms(added.secretKey),
    );
    // Logging in needs a write as well, so a new session cannot be counted on.
    expect((await postLogin(d, uniqueLoginEvent(admin))).status).toBe(507);
    expect((await getSession(d, token)).status).toBe(200);
    const listed = await getIdentities(d, token);
    expect(listed.status).toBe(200);
    expect(await listed.json()).toHaveLength(2);

    expect((await deleteIdentity(d, removed.pubkey, token)).status).toBe(204);
    expect(await relatedRows(d.hub, removed.pubkey, kept.pubkey)).toEqual([
      { identities: 0, pairings: 0, sessions: 0 },
      { identities: 1, pairings: 0, sessions: 0 },
    ]);
    expect(loggedCalls(log)).toEqual([
      ['Identity registration failed: storage is full'],
    ]);
    expectSafeLogs(log, [
      ...privateKeyForms(added.secretKey),
      ...MASTER_KEY_FORMS,
      token,
    ]);

    // Once writes succeed again, the same session can register.
    vi.restoreAllMocks();
    expect(
      (await postIdentity(d, token, registration(bytesToHex(added.secretKey))))
        .status,
    ).toBe(201);
  });
});

describe('identity endpoint protection', () => {
  type IdentityRequest = (
    d: Deployment,
    token: string | undefined,
    options?: RequestOptions,
  ) => Promise<Response>;

  const endpoints: [string, IdentityRequest][] = [
    [
      'GET /admin/api/identities',
      (d, token, options) => getIdentities(d, token, options),
    ],
    [
      'POST /admin/api/identities',
      (d, token, options) =>
        postIdentity(d, token, registration(SECRET_ONE_NSEC), options),
    ],
    [
      'DELETE /admin/api/identities/:pubkey',
      (d, token, options) => deleteIdentity(d, PUBKEY_THREE, token, options),
    ],
  ];
  const stateChanging = endpoints.slice(1);

  // One identity that rejected requests must neither remove nor add to.
  async function guarded() {
    const { d, token } = await signedIn();
    await register(d, token, SECRET_THREE_HEX);
    return { d, token };
  }

  async function expectUnchanged(d: Deployment): Promise<void> {
    expect((await identityRows(d.hub)).map(({ pubkey }) => pubkey)).toEqual([
      PUBKEY_THREE,
    ]);
  }

  it.each(endpoints)(
    '%s requires a valid admin session',
    async (_name, request) => {
      const { d, token } = await guarded();
      for (const presented of [
        undefined,
        'ab'.repeat(32),
        token.slice(1),
        token.toUpperCase(),
        await tokenHash(token),
      ]) {
        await expectError(await request(d, presented), 401, 'unauthorized', [
          token,
        ]);
      }
      await expectUnchanged(d);
    },
  );

  it.each(endpoints)(
    '%s rejects an expired session',
    async (_name, request) => {
      setNow(T0);
      const { d, token } = await guarded();
      setNow(T0 + TWELVE_HOURS);
      await expectError(await request(d, token), 401, 'unauthorized', [token]);
      await expectUnchanged(d);
    },
  );

  it.each(endpoints)(
    '%s rejects a session issued before ADMIN_PUBKEY changed',
    async (_name, request) => {
      const { d, token } = await guarded();
      await expectError(
        await request(withAdminPubkey(d, other.pubkey), token),
        401,
        'unauthorized',
        [token],
      );
      expect((await adminRows(d.hub)).sessions).toEqual([]);
      // Reverting the configuration does not revive it.
      await expectError(await request(d, token), 401, 'unauthorized', [token]);
      await expectUnchanged(d);
    },
  );

  it.each(stateChanging)(
    '%s rejects cross-origin requests',
    async (_name, request) => {
      const { d, token } = await guarded();
      for (const origin of [
        'https://evil.example',
        'http://signflare.example',
        'https://signflare.example:8443',
        'null',
      ]) {
        await expectError(
          await request(d, token, { origin }),
          403,
          'forbidden',
          [token],
        );
      }
      await expectUnchanged(d);
    },
  );

  it.each(stateChanging)(
    '%s rejects requests without an Origin header',
    async (_name, request) => {
      const { d, token } = await guarded();
      await expectError(
        await request(d, token, { origin: null }),
        403,
        'forbidden',
        [token],
      );
      await expectUnchanged(d);
    },
  );

  it('does not require an Origin header for GET and adds no CORS headers', async () => {
    const { d, token } = await guarded();
    const response = await getIdentities(d, token, { origin: null });
    expect(response.status).toBe(200);
    const responses = [
      response,
      await getIdentities(d, token, { origin: 'https://evil.example' }),
      await send(d.env, IDENTITIES_URL, {
        method: 'OPTIONS',
        origin: 'https://evil.example',
        headers: { 'Access-Control-Request-Method': 'POST' },
      }),
    ];
    for (const { headers } of responses) {
      expect(
        [...headers.keys()].filter((name) =>
          name.startsWith('access-control-'),
        ),
      ).toEqual([]);
    }
  });

  it.each(endpoints)('%s responses are not cached', async (_name, request) => {
    const { d, token } = await guarded();
    const responses = [await request(d, token), await request(d, undefined)];
    expect(responses.map(({ status }) => status)).not.toContain(500);
    for (const response of responses) {
      expect(response.headers.get('Cache-Control')).toBe('no-store');
    }
  });
});

describe('identity endpoint errors', () => {
  type Scenario = (
    d: Deployment,
    token: string,
    key: TestKey,
  ) => Promise<[Response, string[]]>;

  it.each<[string, number, string, unknown[][], Scenario]>([
    [
      'malformed JSON',
      400,
      'invalid request',
      [],
      async (d, token, key) => [
        await postIdentity(
          d,
          token,
          `{"privateKey": "${nsecEncode(key.secretKey)}"`,
        ),
        [],
      ],
    ],
    [
      'an invalid private key',
      400,
      'invalid private key',
      [],
      async (d, token, key) => {
        const invalid = tamperNsec(nsecEncode(key.secretKey));
        return [await postIdentity(d, token, registration(invalid)), [invalid]];
      },
    ],
    [
      'a duplicate private key',
      409,
      'identity already exists',
      [],
      async (d, token, key) => {
        await register(d, token, nsecEncode(key.secretKey));
        const [row] = await identityRows(d.hub);
        return [
          await postIdentity(d, token, registration(bytesToHex(key.secretKey))),
          envelopeForms(row),
        ];
      },
    ],
    [
      'full storage',
      507,
      'insufficient storage',
      [['Identity registration failed: storage is full']],
      async (d, token, key) => {
        await instrumentHubSql(d.hub, {
          failing: NON_DELETE_WRITE,
          message: SQLITE_FULL_MESSAGE,
        });
        return [
          await postIdentity(d, token, registration(nsecEncode(key.secretKey))),
          [],
        ];
      },
    ],
    [
      'a MASTER_ENCRYPTION_KEY that is too short',
      500,
      'server configuration error',
      [['MASTER_ENCRYPTION_KEY must be set to a secret of at least 32 bytes']],
      async (d, token, key) => {
        const short = 'test-only short key';
        await setMasterEncryptionKey(d.hub, short);
        return [
          await postIdentity(d, token, registration(nsecEncode(key.secretKey))),
          [short],
        ];
      },
    ],
    [
      'an unexpected error',
      500,
      'internal error',
      [['Admin API request failed:', 'Error']],
      async (d, token, key) => {
        const detail = [
          'SQLITE_ERROR: INSERT INTO identities failed',
          bytesToHex(key.secretKey),
          TEST_MASTER_ENCRYPTION_KEY,
          '    at registerIdentity (src/signer-hub.ts:1:1)',
        ].join('\n');
        const failing = withSignerHub(
          d,
          stubNamespace(d.hub, {
            overrides: {
              registerIdentity: () => Promise.reject(new Error(detail)),
            },
          }),
        );
        return [
          await postIdentity(
            failing,
            token,
            registration(nsecEncode(key.secretKey)),
          ),
          [detail, 'SQLITE_ERROR'],
        ];
      },
    ],
  ])('leak nothing on %s', async (_case, status, error, logged, scenario) => {
    const { d, token } = await signedIn();
    const key = randomKey();
    const log = captureLogs();
    const [response, extra] = await scenario(d, token, key);
    const forbidden = [
      ...privateKeyForms(key.secretKey),
      ...MASTER_KEY_FORMS,
      token,
      await tokenHash(token),
      ...extra,
    ];

    expect(await response.clone().text()).not.toMatch(SQL_DETAILS);
    await expectError(response, status, error, forbidden);
    expect(loggedCalls(log)).toEqual(logged);
    expectSafeLogs(log, forbidden);
  });

  it.each<
    [string, string, (d: Deployment, token: string) => Promise<Response>]
  >([
    ['listing', 'listIdentities', (d, token) => getIdentities(d, token)],
    [
      'deletion',
      'deleteIdentity',
      (d, token) => deleteIdentity(d, PUBKEY_ONE, token),
    ],
  ])(
    'map an unexpected %s failure to a generic error',
    async (_case, method, request) => {
      const log = captureLogs();
      const { d, token } = await signedIn();
      const detail = `SQLITE_ERROR: SELECT * FROM identities ${TEST_MASTER_ENCRYPTION_KEY}`;
      const failing = withSignerHub(
        d,
        stubNamespace(d.hub, {
          overrides: { [method]: () => Promise.reject(new Error(detail)) },
        }),
      );

      await expectError(await request(failing, token), 500, 'internal error', [
        detail,
        ...MASTER_KEY_FORMS,
        token,
      ]);
      expect(loggedCalls(log)).toEqual([
        ['Admin API request failed:', 'Error'],
      ]);
      expectSafeLogs(log, [detail, ...MASTER_KEY_FORMS, token]);
    },
  );
});
