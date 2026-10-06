import { Hono } from 'hono';
import { adminApi } from './admin-api';
import { parseAdminPubkey } from './config';
import {
  LANDING_PAGE_CONTENT_SECURITY_POLICY,
  landingPage,
} from './landing-page';
import { isWebSocketUpgrade } from './relay';
import {
  acceptsRelayInformation,
  RELAY_INFORMATION_CORS_HEADERS,
  RELAY_INFORMATION_MEDIA_TYPE,
  relayInformation,
} from './relay-information';
import { relayUrl } from './relay-url';
import { getSignerHub } from './signer-hub';

export { SignerHub } from './signer-hub';

// The Admin SPA's entry page and the directory of its bundled JavaScript and
// CSS, as built by vite.config.ts.
const ADMIN_APP_PATH = '/admin/';
const ADMIN_ASSETS_PATH = '/admin/assets/';

const app = new Hono<{ Bindings: Env }>();

// The public root (docs/design.md §37). A WebSocket upgrade takes precedence
// over every other use of it: it connects to the NIP-46 relay in the
// SignerHub. Then come the NIP-11 document and the landing page, which are
// built from ADMIN_PUBKEY and the request URL alone. Neither of them reaches
// the SignerHub or reads a secret.
app.get('/', (c) => {
  if (isWebSocketUpgrade(c.req.raw)) {
    return getSignerHub(c.env).fetch(c.req.raw);
  }
  c.header('Vary', 'Accept');
  const adminPubkey = parseAdminPubkey(c.env.ADMIN_PUBKEY);
  if (adminPubkey === null) {
    console.error(
      'ADMIN_PUBKEY must be set to a lowercase 64-character hex public key',
    );
  }
  if (acceptsRelayInformation(c.req.header('Accept'))) {
    if (adminPubkey === null) {
      return c.json(
        { error: 'server configuration error' },
        500,
        RELAY_INFORMATION_CORS_HEADERS,
      );
    }
    return c.body(JSON.stringify(relayInformation(adminPubkey)), 200, {
      ...RELAY_INFORMATION_CORS_HEADERS,
      'Content-Type': RELAY_INFORMATION_MEDIA_TYPE,
    });
  }
  if (adminPubkey === null) {
    return c.text('server configuration error', 500);
  }
  // The relay URL comes from the URL the Worker received, never from Host or
  // X-Forwarded-* headers.
  return c.html(landingPage(adminPubkey, relayUrl(c.req.url)), 200, {
    'Content-Security-Policy': LANDING_PAGE_CONTENT_SECURITY_POLICY,
  });
});

// The CORS preflight of the NIP-11 document, which browsers send before a
// request with headers beyond the CORS-safelisted ones.
app.options('/', (c) =>
  c.body(null, 204, {
    ...RELAY_INFORMATION_CORS_HEADERS,
    Allow: 'GET, HEAD, OPTIONS',
  }),
);

app.route('/admin/api', adminApi);

// Unknown Admin API endpoints get an Admin API error rather than the SPA.
app.all('/admin/api/*', (c) => c.json({ error: 'not found' }, 404));

// The Admin SPA (docs/design.md §31.1). Static Assets serves its files
// without invoking the Worker, so a missing built file ends up here and is
// not found. Every other /admin path is answered with the SPA's entry page.
app.get('/admin/*', (c) => {
  if (c.req.path.startsWith(ADMIN_ASSETS_PATH)) {
    return c.notFound();
  }
  return c.env.ASSETS.fetch(
    new Request(new URL(ADMIN_APP_PATH, c.req.url), c.req.raw),
  );
});

export default app;
