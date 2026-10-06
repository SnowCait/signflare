import { Hono } from 'hono';
import { adminApi } from './admin-api';
import { isWebSocketUpgrade } from './relay';
import { getSignerHub } from './signer-hub';

export { SignerHub } from './signer-hub';

// The Admin SPA's entry page and the directory of its bundled JavaScript and
// CSS, as built by vite.config.ts.
const ADMIN_APP_PATH = '/admin/';
const ADMIN_ASSETS_PATH = '/admin/assets/';

const app = new Hono<{ Bindings: Env }>();

// A WebSocket upgrade takes precedence over every other use of the root
// (docs/design.md §37): it connects to the NIP-46 relay in the SignerHub.
app.get('/', (c) => {
  if (isWebSocketUpgrade(c.req.raw)) {
    return getSignerHub(c.env).fetch(c.req.raw);
  }
  return c.text('Signflare');
});

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
