import { type Context, Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { createMiddleware } from 'hono/factory';
import type { CookieOptions } from 'hono/utils/cookie';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import {
  ADMIN_SESSION_LIFETIME_SECONDS,
  type AdminSession,
  generateAdminSessionToken,
  hashAdminSessionToken,
  isAdminSessionToken,
} from './admin-sessions';
import { parseAdminPubkey } from './config';
import {
  Nip98AuthError,
  nip98EventExpiresAt,
  parseNip98Authorization,
  verifyNip98Event,
} from './nip98';
import { getSignerHub } from './signer-hub';

// Login needs no body. Anything larger is rejected before it is hashed.
export const MAX_LOGIN_BODY_BYTES = 8 * 1024;

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
  Bindings: Env;
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

// Never includes the session token.
function sessionResponse(session: AdminSession) {
  return { pubkey: session.adminPubkey, expiresAt: session.expiresAt };
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
