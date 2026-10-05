import { DurableObject } from 'cloudflare:workers';
import * as adminSessions from './admin-sessions';
import type {
  AdminLogin,
  AdminLoginResult,
  AdminSession,
} from './admin-sessions';
import { migrate } from './migrations';

// All signer state lives in this one instance (docs/design.md §5).
export const SIGNER_HUB_NAME = 'signer';

export function getSignerHub(env: Env): DurableObjectStub<SignerHub> {
  return env.SIGNER_HUB.getByName(SIGNER_HUB_NAME);
}

export class SignerHub extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // No request or RPC call is delivered until the schema is up to date.
    void ctx.blockConcurrencyWhile(async () => {
      migrate(ctx.storage);
    });
  }

  createAdminSession(login: AdminLogin): AdminLoginResult {
    return adminSessions.createAdminSession(this.ctx.storage, login);
  }

  authenticateAdminSession(
    tokenHash: Uint8Array,
    adminPubkey: string,
    now: number,
  ): AdminSession | null {
    return adminSessions.authenticateAdminSession(
      this.ctx.storage.sql,
      tokenHash,
      adminPubkey,
      now,
    );
  }

  deleteAdminSession(tokenHash: Uint8Array): boolean {
    return adminSessions.deleteAdminSession(this.ctx.storage.sql, tokenHash);
  }
}
