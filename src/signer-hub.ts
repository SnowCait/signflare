import { DurableObject } from 'cloudflare:workers';
import * as adminSessions from './admin-sessions';
import type {
  AdminLogin,
  AdminLoginResult,
  AdminSession,
} from './admin-sessions';
import { parseMasterEncryptionKey } from './config';
import * as identities from './identities';
import type { IdentityMetadata } from './identities';
import { migrate } from './migrations';
import * as pairings from './pairings';
import type { CreatePairingResult, PairingPermissionsInput } from './pairings';
import { InvalidPrivateKeyError } from './private-key';
import * as sessions from './sessions';
import type {
  EstablishSessionResult,
  Session,
  SessionRequest,
} from './sessions';
import { StorageFullError } from './storage-errors';

// All signer state lives in this one instance (docs/design.md §5).
export const SIGNER_HUB_NAME = 'signer';

export type RegisterIdentityResult =
  | { readonly status: 'created'; readonly identity: IdentityMetadata }
  | { readonly status: 'invalid_private_key' }
  | { readonly status: 'duplicate' }
  | { readonly status: 'storage_full' }
  // MASTER_ENCRYPTION_KEY is missing or shorter than 32 bytes.
  | { readonly status: 'configuration_error' };

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

  // MASTER_ENCRYPTION_KEY is read here rather than taken as an argument, so it
  // never crosses the RPC boundary. The key bytes are overwritten, as a best
  // effort, once registration ends, whatever the outcome. Expected failures
  // are returned as statuses because error classes do not survive RPC.
  async registerIdentity(
    privateKey: string,
    now: number,
  ): Promise<RegisterIdentityResult> {
    const masterKey = parseMasterEncryptionKey(this.env.MASTER_ENCRYPTION_KEY);
    if (masterKey === null) {
      return { status: 'configuration_error' };
    }
    try {
      const identity = await identities.registerIdentity(
        this.ctx.storage.sql,
        masterKey,
        privateKey,
        now,
      );
      return { status: 'created', identity };
    } catch (error) {
      if (error instanceof InvalidPrivateKeyError) {
        return { status: 'invalid_private_key' };
      }
      if (error instanceof identities.DuplicateIdentityError) {
        return { status: 'duplicate' };
      }
      if (error instanceof StorageFullError) {
        return { status: 'storage_full' };
      }
      throw error;
    } finally {
      masterKey.fill(0);
    }
  }

  listIdentities(): IdentityMetadata[] {
    return identities.listIdentities(this.ctx.storage.sql);
  }

  // The administrator's way to recover storage (docs/design.md §32), so it
  // must work without MASTER_ENCRYPTION_KEY and with only DELETE statements.
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
