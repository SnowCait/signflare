import { Hono } from 'hono';
import { adminApi } from './admin-api';
import { isWebSocketUpgrade } from './relay';
import { getSignerHub } from './signer-hub';

export { SignerHub } from './signer-hub';

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

export default app;
