import { DurableObject } from 'cloudflare:workers';
import { migrate } from './migrations';

export class SignerHub extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // No request or RPC call is delivered until the schema is up to date.
    void ctx.blockConcurrencyWhile(async () => {
      migrate(ctx.storage);
    });
  }
}
