import { bytesToHex } from 'nostr-tools/utils';
import { identityExists } from './identities';
import {
  deserializePermissions,
  InvalidPermissionError,
  parsePairingPermissions,
  type Permission,
  serializePermissions,
} from './permissions';
import { StorageFullError, withStorageFullDetection } from './storage-errors';

// Pairings expire exactly 10 minutes after creation (docs/design.md §13).
export const PAIRING_LIFETIME_SECONDS = 10 * 60;

const SECRET_BYTES = 32;
const SECRET = /^[0-9a-f]{64}$/;

export interface Pairing {
  readonly id: string;
  readonly identityPubkey: string;
  readonly permissions: readonly Permission[];
  readonly createdAt: number;
  readonly expiresAt: number;
}

// The permissions an administrator selects: "all", or explicit permissions.
export type PairingPermissionsInput = 'all' | readonly string[];

export type CreatePairingResult =
  | {
      readonly status: 'created';
      readonly pairing: Pairing;
      // The one-time secret for the connection token. No other operation
      // returns it, and only its hash is stored.
      readonly secret: string;
    }
  | { readonly status: 'identity_not_found' }
  | { readonly status: 'invalid_permissions' }
  | { readonly status: 'storage_full' };

type PairingRow = {
  id: string;
  identity_pubkey: string;
  permissions: string;
  created_at: number;
  expires_at: number;
};

// The raw secret may only be handed to the administrator in the connection
// token. Store hashPairingSecret(secret) instead.
export function generatePairingSecret(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(SECRET_BYTES)));
}

// Only the format generatePairingSecret() produces. The length is checked
// first, so oversized input is rejected without being scanned.
export function isPairingSecret(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length === SECRET_BYTES * 2 &&
    SECRET.test(value)
  );
}

// SHA-256 of the exact secret string. The secret is 256 bits of randomness,
// so an unsalted hash is sufficient.
export async function hashPairingSecret(secret: string): Promise<Uint8Array> {
  if (!isPairingSecret(secret)) {
    throw new TypeError('Malformed pairing secret');
  }
  return new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret)),
  );
}

// Creates a pairing for an existing identity, valid for 10 minutes. Expired
// pairings are removed on the way.
export async function createPairing(
  storage: DurableObjectStorage,
  identityPubkey: string,
  permissions: PairingPermissionsInput,
  now: number,
): Promise<CreatePairingResult> {
  let granted: Permission[];
  try {
    granted = parsePairingPermissions(permissions);
  } catch (error) {
    if (error instanceof InvalidPermissionError) {
      return { status: 'invalid_permissions' };
    }
    throw error;
  }
  const secret = generatePairingSecret();
  const secretHash = await hashPairingSecret(secret);
  const pairing: Pairing = {
    id: crypto.randomUUID(),
    identityPubkey,
    permissions: granted,
    createdAt: now,
    expiresAt: now + PAIRING_LIFETIME_SECONDS,
  };

  const { sql } = storage;
  try {
    // The identity is checked in the same transaction as the insert, so it
    // cannot be deleted in between.
    return storage.transactionSync((): CreatePairingResult => {
      sql.exec('DELETE FROM pairings WHERE expires_at <= ?', now);
      if (!identityExists(sql, identityPubkey)) {
        return { status: 'identity_not_found' };
      }
      withStorageFullDetection(() =>
        sql.exec(
          `INSERT INTO pairings (
            id,
            identity_pubkey,
            secret_hash,
            permissions,
            expires_at,
            created_at
          ) VALUES (?, ?, ?, ?, ?, ?)`,
          pairing.id,
          pairing.identityPubkey,
          secretHash,
          serializePermissions(pairing.permissions),
          pairing.expiresAt,
          pairing.createdAt,
        ),
      );
      return { status: 'created', pairing, secret };
    });
  } catch (error) {
    if (error instanceof StorageFullError) {
      return { status: 'storage_full' };
    }
    throw error;
  }
}

// Expired pairings are returned as well; the caller decides what to do.
// Throws MalformedPermissionsError if the stored permissions were altered.
export function findPairing(
  sql: SqlStorage,
  secretHash: Uint8Array,
): Pairing | null {
  const [row] = sql
    .exec<PairingRow>(
      `SELECT id, identity_pubkey, permissions, created_at, expires_at
      FROM pairings WHERE secret_hash = ?`,
      secretHash,
    )
    .toArray();
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    identityPubkey: row.identity_pubkey,
    permissions: deserializePermissions(row.permissions),
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  };
}

export function deletePairing(sql: SqlStorage, id: string): boolean {
  return (
    sql.exec('DELETE FROM pairings WHERE id = ? RETURNING id', id).toArray()
      .length > 0
  );
}
