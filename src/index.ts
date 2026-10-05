import { Hono } from 'hono';
import { adminApi } from './admin-api';

export { SignerHub } from './signer-hub';

const app = new Hono<{ Bindings: Env }>();

app.get('/', (c) => c.text('Signflare'));

app.route('/admin/api', adminApi);

export default app;
