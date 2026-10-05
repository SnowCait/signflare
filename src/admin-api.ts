import { type Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { createMiddleware } from 'hono/factory';
import type { CookieOptions } from 'hono/utils/cookie';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { toBunkerURL } from 'nostr-tools/nip46';
import {
  ADMIN_SESSION_LIFETIME_SECONDS,
  type AdminSession,
  generateAdminSessionToken,
  hashAdminSessionToken,
  isAdminSessionToken,
} from './admin-sessions';
import { parseAdminPubkey, type SignflareBindings } from './config';
import type { IdentityMetadata } from './identities';
import {
  Nip98AuthError,
  nip98EventExpiresAt,
  parseNip98Authorization,
  verifyNip98Event,
} from './nip98';
import type { PairingPermissionsInput } from './pairings';
import { ALL_PERMISSIONS } from './permissions';
import { relayUrl } from './relay-url';
import {
  RemoteSignerConfigurationError,
  remoteSignerPubkey,
} from './remote-signer';
import { getSignerHub } from './signer-hub';

// Login needs no body. Anything larger is rejected before it is hashed.
export const MAX_LOGIN_BODY_BYTES = 8 * 1024;

// A registration body holds a single private key and fits well within this.
// Anything larger is rejected before it is parsed.
export const MAX_IDENTITY_BODY_BYTES = 1024;

// A pairing body holds the permissions to grant. Even a list of over 200
// sign_event:<kind> entries fits within this. Anything larger is rejected
// before it is parsed.
export const MAX_PAIRING_BODY_BYTES = 4 * 1024;

const PUBKEY = /^[0-9a-f]{64}$/;

// Sent as `__Secure-signflare_admin_session`; browsers only accept the prefix
// on cookies set with Secure from a secure origin.
const ADMIN_SESSION_COOKIE = 'signflare_admin_session';
const ADMIN_SESSION_COOKIE_OPTIONS = {
  prefix: 'secure',
  path: '/admin',
  httpOnly: true,
  secure: true,
  sameSite: 'Strict',
} as const satisfies CookieOptions;

type AdminApiEnv = {
  Bindings: SignflareBindings;
  Variables: {
    adminPubkey: string;
    adminSession: AdminSession;
    adminSessionTokenHash: Uint8Array;
  };
};

export const adminApi = new Hono<AdminApiEnv>();

adminApi.onError((error, c) => {
  if (error instanceof Nip98AuthError) {
    return unauthorized(c);
  }
  if (error instanceof RemoteSignerConfigurationError) {
    console.error(
      'REMOTE_SIGNER_PRIVATE_KEY must be set to an nsec or a 64-character hex private key',
    );
    return errorResponse(c, 500, 'server configuration error');
  }
  // Only the name is logged: messages and stacks are not needed to tell the
  // failure class and must never be able to carry request credentials.
  console.error('Admin API request failed:', error.name);
  return errorResponse(c, 500, 'internal error');
});

adminApi.use(async (c, next) => {
  await next();
  c.header('Cache-Control', 'no-store');
});

// docs/design.md §30.11. Browsers send Origin with every request whose method
// is not GET or HEAD, so a missing Origin is rejected as well.
adminApi.use(async (c, next) => {
  const method = c.req.method;
  if (
    method !== 'GET' &&
    method !== 'HEAD' &&
    c.req.header('Origin') !== new URL(c.req.url).origin
  ) {
    return errorResponse(c, 403, 'forbidden');
  }
  await next();
});

adminApi.use(async (c, next) => {
  const adminPubkey = parseAdminPubkey(c.env.ADMIN_PUBKEY);
  if (adminPubkey === null) {
    console.error(
      'ADMIN_PUBKEY must be set to a lowercase 64-character hex public key',
    );
    return errorResponse(c, 500, 'server configuration error');
  }
  c.set('adminPubkey', adminPubkey);
  await next();
});

// Required by every Admin API endpoint except login (docs/design.md §30).
const requireAdminSession = createMiddleware<AdminApiEnv>(async (c, next) => {
  const token = getCookie(c, ADMIN_SESSION_COOKIE, 'secure');
  if (token === undefined || !isAdminSessionToken(token)) {
    return unauthorized(c);
  }
  const tokenHash = await hashAdminSessionToken(token);
  const session = await getSignerHub(c.env).authenticateAdminSession(
    tokenHash,
    c.get('adminPubkey'),
    unixNow(),
  );
  if (session === null) {
    return unauthorized(c);
  }
  c.set('adminSession', session);
  c.set('adminSessionTokenHash', tokenHash);
  await next();
});

adminApi.post('/login', async (c) => {
  const adminPubkey = c.get('adminPubkey');
  const event = parseNip98Authorization(c.req.header('Authorization'));
  const body = await readBody(c.req.raw, MAX_LOGIN_BODY_BYTES);
  if (body === null) {
    return errorResponse(c, 413, 'payload too large');
  }
  const now = unixNow();
  await verifyNip98Event(event, {
    url: c.req.url,
    method: c.req.method,
    body,
    pubkey: adminPubkey,
    now,
  });

  const token = generateAdminSessionToken();
  const result = await getSignerHub(c.env).createAdminSession({
    eventId: event.id,
    eventExpiresAt: nip98EventExpiresAt(event),
    tokenHash: await hashAdminSessionToken(token),
    adminPubkey,
    now,
  });
  switch (result.status) {
    case 'replayed':
      return unauthorized(c);
    case 'storage_full':
      return errorResponse(c, 507, 'insufficient storage');
  }
  setCookie(c, ADMIN_SESSION_COOKIE, token, {
    ...ADMIN_SESSION_COOKIE_OPTIONS,
    maxAge: ADMIN_SESSION_LIFETIME_SECONDS,
  });
  return c.json(sessionResponse(result.session));
});

adminApi.get('/session', requireAdminSession, (c) =>
  c.json(sessionResponse(c.get('adminSession'))),
);

adminApi.post('/logout', requireAdminSession, async (c) => {
  await getSignerHub(c.env).deleteAdminSession(c.get('adminSessionTokenHash'));
  deleteCookie(c, ADMIN_SESSION_COOKIE, ADMIN_SESSION_COOKIE_OPTIONS);
  return c.body(null, 204);
});

adminApi.get('/identities', requireAdminSession, async (c) => {
  const identities = await getSignerHub(c.env).listIdentities();
  return c.json(identities.map(identityResponse));
});

adminApi.post('/identities', requireAdminSession, async (c) => {
  const body = await readBody(c.req.raw, MAX_IDENTITY_BODY_BYTES);
  if (body === null) {
    return errorResponse(c, 413, 'payload too large');
  }
  const privateKey = parsePrivateKeyRequest(body);
  if (privateKey === null) {
    return errorResponse(c, 400, 'invalid request');
  }
  const result = await getSignerHub(c.env).registerIdentity(
    privateKey,
    unixNow(),
  );
  switch (result.status) {
    case 'created':
      return c.json(identityResponse(result.identity), 201);
    case 'invalid_private_key':
      return errorResponse(c, 400, 'invalid private key');
    case 'duplicate':
      return errorResponse(c, 409, 'identity already exists');
    case 'storage_full':
      console.error('Identity registration failed: storage is full');
      return errorResponse(c, 507, 'insufficient storage');
    case 'configuration_error':
      console.error(
        'MASTER_ENCRYPTION_KEY must be set to a secret of at least 32 bytes',
      );
      return errorResponse(c, 500, 'server configuration error');
  }
});

adminApi.delete('/identities/:pubkey', requireAdminSession, async (c) => {
  const pubkey = c.req.param('pubkey');
  if (!PUBKEY.test(pubkey)) {
    return errorResponse(c, 400, 'invalid pubkey');
  }
  if (!(await getSignerHub(c.env).deleteIdentity(pubkey))) {
    return errorResponse(c, 404, 'not found');
  }
  return c.body(null, 204);
});

adminApi.post(
  '/identities/:pubkey/pairings',
  requireAdminSession,
  async (c) => {
    const identityPubkey = c.req.param('pubkey');
    if (!PUBKEY.test(identityPubkey)) {
      return errorResponse(c, 400, 'invalid pubkey');
    }
    const body = await readBody(c.req.raw, MAX_PAIRING_BODY_BYTES);
    if (body === null) {
      return errorResponse(c, 413, 'payload too large');
    }
    const permissions = parsePairingRequest(body);
    if (permissions === null) {
      return errorResponse(c, 400, 'invalid request');
    }
    // Both are derived before the pairing is created, so that no pairing is
    // left behind without a connection token. The relay comes from the URL
    // the Worker received, never from Host or X-Forwarded-* headers.
    const remoteSigner = remoteSignerPubkey(c.env.REMOTE_SIGNER_PRIVATE_KEY);
    const relay = relayUrl(c.req.url);

    const result = await getSignerHub(c.env).createPairing(
      identityPubkey,
      permissions,
      unixNow(),
    );
    switch (result.status) {
      case 'created':
        // The connection token is the only place where the pairing secret
        // and the remote-signer pubkey are returned (docs/design.md §30.8).
        return c.json(
          {
            bunkerUrl: toBunkerURL({
              pubkey: remoteSigner,
              relays: [relay],
              secret: result.secret,
            }),
            expiresAt: result.pairing.expiresAt,
          },
          201,
        );
      case 'invalid_permissions':
        return errorResponse(c, 400, 'invalid permissions');
      case 'identity_not_found':
        return errorResponse(c, 404, 'not found');
      case 'storage_full':
        console.error('Pairing creation failed: storage is full');
        return errorResponse(c, 507, 'insufficient storage');
    }
  },
);

// Never includes the session token.
function sessionResponse(session: AdminSession) {
  return { pubkey: session.adminPubkey, expiresAt: session.expiresAt };
}

// Public identity information only (docs/design.md §30.5, §30.6).
function identityResponse(identity: IdentityMetadata) {
  return {
    pubkey: identity.pubkey,
    npub: identity.npub,
    createdAt: identity.createdAt,
    updatedAt: identity.updatedAt,
  };
}

// Returns the privateKey string of a {"privateKey": ...} body, or null for
// any other body. The key itself is validated by the SignerHub.
function parsePrivateKeyRequest(body: Uint8Array): string | null {
  const privateKey = parseJsonObject(body)?.privateKey;
  return typeof privateKey === 'string' ? privateKey : null;
}

// Returns the permissions of a {"permissions": "all" | string[]} body, or
// null for any other body. Which permissions are valid is left to
// createPairing().
function parsePairingRequest(body: Uint8Array): PairingPermissionsInput | null {
  const permissions = parseJsonObject(body)?.permissions;
  return permissions === ALL_PERMISSIONS || isStringArray(permissions)
    ? permissions
    : null;
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === 'string')
  );
}

// The JSON object in a request body, or null for any other body. Parser
// messages can quote the input, so they are discarded.
function parseJsonObject(body: Uint8Array): Record<string, unknown> | null {
  let value: unknown;
  try {
    value = JSON.parse(
      new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(body),
    );
  } catch {
    return null;
  }
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function errorResponse(
  c: Context,
  status: ContentfulStatusCode,
  error: string,
): Response {
  return c.json({ error }, status);
}

function unauthorized(c: Context): Response {
  return errorResponse(c, 401, 'unauthorized');
}

function unixNow(): number {
  return Math.floor(Date.now() / 1000);
}

// Reads the raw body exactly once, so the NIP-98 payload hash covers the bytes
// as sent. Returns null as soon as the body exceeds maxBytes.
async function readBody(
  request: Request,
  maxBytes: number,
): Promise<Uint8Array | null> {
  if (request.body === null) {
    return new Uint8Array();
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    length += value.byteLength;
    if (length > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}
