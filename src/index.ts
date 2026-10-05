import { Hono } from 'hono';

export { SignerHub } from './signer-hub';

const app = new Hono<{ Bindings: Env }>();

app.get('/', (c) => c.text('Signflare'));

export default app;
