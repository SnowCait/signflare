import { DurableObject } from 'cloudflare:workers';
import * as adminSessions from './admin-sessions';
import type {
  AdminLogin,
  AdminLoginResult,
  AdminSession,
} from './admin-sessions';
import * as identities from './identities';
import { migrate } from './migrations';
import * as pairings from './pairings';
import type { CreatePairingResult, PairingPermissionsInput } from './pairings';
import * as sessions from './sessions';
import type {
  EstablishSessionResult,
  Session,
  SessionRequest,
} from './sessions';

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

  deleteIdentity(pubkey: string): boolean {
    return identities.deleteIdentity(this.ctx.storage, pubkey);
  }

  // The only method whose result contains a raw pairing secret.
  createPairing(
    identityPubkey: string,
    permissions: PairingPermissionsInput,
    now: number,
  ): Promise<CreatePairingResult> {
    return pairings.createPairing(
      this.ctx.storage,
      identityPubkey,
      permissions,
      now,
    );
  }

  establishSession(request: SessionRequest): Promise<EstablishSessionResult> {
    return sessions.establishSession(this.ctx.storage, request);
  }

  getSession(clientPubkey: string): Session | null {
    return sessions.getSession(this.ctx.storage.sql, clientPubkey);
  }

  listSessions(identityPubkey: string): Session[] {
    return sessions.listSessions(this.ctx.storage.sql, identityPubkey);
  }

  revokeSession(clientPubkey: string): boolean {
    return sessions.revokeSession(this.ctx.storage.sql, clientPubkey);
  }

  touchSession(clientPubkey: string, now: number): boolean {
    return sessions.touchSession(this.ctx.storage.sql, clientPubkey, now);
  }
}
