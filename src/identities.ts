import { npubEncode } from 'nostr-tools/nip19';
import { parsePrivateKey } from './private-key';
import {
  encryptPrivateKey,
  type EncryptedPrivateKey,
} from './private-key-encryption';
import { withStorageFullDetection } from './storage-errors';

// Stored representation. Never return it from an API: use IdentityMetadata.
export interface IdentityRecord {
  readonly pubkey: string;
  readonly encryptedPrivateKey: EncryptedPrivateKey;
  readonly createdAt: number;
  readonly updatedAt: number;
}

// Public identity information, safe to expose to administrators.
export interface IdentityMetadata {
  readonly pubkey: string;
  readonly npub: string;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export class DuplicateIdentityError extends Error {
  constructor(readonly pubkey: string) {
    super('Identity already exists');
    this.name = 'DuplicateIdentityError';
  }
}

type IdentityRow = {
  pubkey: string;
  encrypted_private_key: ArrayBuffer;
  iv: ArrayBuffer;
  kdf_salt: ArrayBuffer;
  key_version: number;
  created_at: number;
  updated_at: number;
};

type IdentityMetadataRow = Pick<
  IdentityRow,
  'pubkey' | 'created_at' | 'updated_at'
>;

// Validates the private key, encrypts it, and stores only the encrypted
// envelope. Timestamps are Unix seconds.
//
// Throws InvalidPrivateKeyError, DuplicateIdentityError, or StorageFullError.
export async function registerIdentity(
  sql: SqlStorage,
  masterKey: Uint8Array,
  privateKey: unknown,
  now: number = Math.floor(Date.now() / 1000),
): Promise<IdentityMetadata> {
  const { secretKey, pubkey } = parsePrivateKey(privateKey);
  let encryptedPrivateKey: EncryptedPrivateKey;
  try {
    // Checked before encrypting to skip needless work; insertIdentity checks
    // again because other requests may run while encryption is awaited.
    if (identityExists(sql, pubkey)) {
      throw new DuplicateIdentityError(pubkey);
    }
    encryptedPrivateKey = await encryptPrivateKey(masterKey, pubkey, secretKey);
  } finally {
    secretKey.fill(0);
  }

  const record: IdentityRecord = {
    pubkey,
    encryptedPrivateKey,
    createdAt: now,
    updatedAt: now,
  };
  insertIdentity(sql, record);
  return toIdentityMetadata(record);
}

export function insertIdentity(sql: SqlStorage, record: IdentityRecord): void {
  // The check and the insert run synchronously, so no other request can
  // interleave between them inside the Durable Object.
  if (identityExists(sql, record.pubkey)) {
    throw new DuplicateIdentityError(record.pubkey);
  }
  const { ciphertext, iv, kdfSalt, keyVersion } = record.encryptedPrivateKey;
  withStorageFullDetection(() =>
    sql.exec(
      `INSERT INTO identities (
        pubkey,
        encrypted_private_key,
        iv,
        kdf_salt,
        key_version,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      record.pubkey,
      ciphertext,
      iv,
      kdfSalt,
      keyVersion,
      record.createdAt,
      record.updatedAt,
    ),
  );
}

export function identityExists(sql: SqlStorage, pubkey: string): boolean {
  return (
    sql.exec('SELECT 1 FROM identities WHERE pubkey = ?', pubkey).toArray()
      .length > 0
  );
}

export function listIdentities(sql: SqlStorage): IdentityMetadata[] {
  // Only public columns are selected; encrypted key material is never read.
  return sql
    .exec<IdentityMetadataRow>(
      'SELECT pubkey, created_at, updated_at FROM identities ORDER BY created_at, pubkey',
    )
    .toArray()
    .map((row) =>
      toIdentityMetadata({
        pubkey: row.pubkey,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }),
    );
}

export function getIdentity(
  sql: SqlStorage,
  pubkey: string,
): IdentityRecord | null {
  const [row] = sql
    .exec<IdentityRow>(
      `SELECT
        pubkey,
        encrypted_private_key,
        iv,
        kdf_salt,
        key_version,
        created_at,
        updated_at
      FROM identities WHERE pubkey = ?`,
      pubkey,
    )
    .toArray();
  if (!row) {
    return null;
  }
  return {
    pubkey: row.pubkey,
    encryptedPrivateKey: {
      ciphertext: new Uint8Array(row.encrypted_private_key),
      iv: new Uint8Array(row.iv),
      kdfSalt: new Uint8Array(row.kdf_salt),
      keyVersion: row.key_version,
    },
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// Removes the identity's sessions, its pairings, and the identity row, in that
// order and in one transaction (docs/design.md §12). Only DELETE statements
// are used, so deletion keeps working when storage is full (§32).
//
// Returns false if there was no such identity.
export function deleteIdentity(
  storage: DurableObjectStorage,
  pubkey: string,
): boolean {
  const { sql } = storage;
  return storage.transactionSync(() => {
    sql.exec('DELETE FROM sessions WHERE identity_pubkey = ?', pubkey);
    sql.exec('DELETE FROM pairings WHERE identity_pubkey = ?', pubkey);
    return (
      sql
        .exec(
          'DELETE FROM identities WHERE pubkey = ? RETURNING pubkey',
          pubkey,
        )
        .toArray().length > 0
    );
  });
}

export function toIdentityMetadata(
  identity: Pick<IdentityRecord, 'pubkey' | 'createdAt' | 'updatedAt'>,
): IdentityMetadata {
  return {
    pubkey: identity.pubkey,
    npub: npubEncode(identity.pubkey),
    createdAt: identity.createdAt,
    updatedAt: identity.updatedAt,
  };
}
