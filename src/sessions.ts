import {
  deletePairing,
  findPairing,
  hashPairingSecret,
  isPairingSecret,
} from './pairings';
import {
  deserializePermissions,
  intersectPermissions,
  InvalidPermissionError,
  parseRequestedPermissions,
  type Permission,
  serializePermissions,
} from './permissions';
import { StorageFullError, withStorageFullDetection } from './storage-errors';

// NIP-46 sessions (docs/design.md §14). A session is identified by the client
// public key and stays valid until logout, revocation, or identity deletion.

const PUBKEY = /^[0-9a-f]{64}$/;

// Unauthenticated display hints from the client (docs/design.md §15). They
// play no part in identity selection, permissions, or pairing validation.
export interface ClientMetadata {
  readonly name: string | null;
  readonly url: string | null;
  readonly image: string | null;
}

export interface Session {
  readonly clientPubkey: string;
  readonly identityPubkey: string;
  readonly permissions: readonly Permission[];
  readonly clientMetadata: ClientMetadata;
  readonly createdAt: number;
  readonly lastUsedAt: number;
}

// What a NIP-46 connect request supplies.
export interface SessionRequest {
  readonly secret: string;
  // The pubkey of the request event.
  readonly clientPubkey: string;
  // optional_requested_perms as received. Omitted or empty, the session
  // receives the pairing permissions.
  readonly requestedPermissions?: string;
  readonly clientMetadata?: Partial<ClientMetadata>;
  readonly now: number;
}

export type EstablishSessionResult =
  | { readonly status: 'created'; readonly session: Session }
  | { readonly status: 'invalid_permissions' }
  | { readonly status: 'invalid_secret' }
  | { readonly status: 'pairing_expired' }
  | { readonly status: 'already_connected' }
  | { readonly status: 'storage_full' };

type SessionRow = {
  client_pubkey: string;
  identity_pubkey: string;
  permissions: string;
  client_name: string | null;
  client_url: string | null;
  client_image: string | null;
  created_at: number;
  last_used_at: number;
};

const SESSION_COLUMNS = `
  client_pubkey,
  identity_pubkey,
  permissions,
  client_name,
  client_url,
  client_image,
  created_at,
  last_used_at
`;

// Redeems a pairing secret for a new session (docs/design.md §20). Checking
// the pairing, inserting the session, and deleting the pairing happen in one
// transaction, so a secret establishes at most one session, also under
// concurrent attempts, and a failed insert leaves the pairing usable.
//
// A client that already has a session gets already_connected; neither that
// session nor the pairing is changed.
//
// Throws TypeError for a malformed clientPubkey or non-string metadata, which
// the NIP-46 layer validates before calling this.
export async function establishSession(
  storage: DurableObjectStorage,
  request: SessionRequest,
): Promise<EstablishSessionResult> {
  const { clientPubkey, now } = request;
  if (typeof clientPubkey !== 'string' || !PUBKEY.test(clientPubkey)) {
    throw new TypeError(
      'clientPubkey must be 64 lowercase hexadecimal characters',
    );
  }
  const clientMetadata = toClientMetadata(request.clientMetadata);
  let requested: Permission[] | null;
  try {
    requested = parseRequestedPermissions(request.requestedPermissions);
  } catch (error) {
    if (error instanceof InvalidPermissionError) {
      return { status: 'invalid_permissions' };
    }
    throw error;
  }
  if (!isPairingSecret(request.secret)) {
    return { status: 'invalid_secret' };
  }
  const secretHash = await hashPairingSecret(request.secret);

  const { sql } = storage;
  try {
    return storage.transactionSync((): EstablishSessionResult => {
      const pairing = findPairing(sql, secretHash);
      if (pairing === null) {
        return { status: 'invalid_secret' };
      }
      if (pairing.expiresAt <= now) {
        deletePairing(sql, pairing.id);
        return { status: 'pairing_expired' };
      }
      if (sessionExists(sql, clientPubkey)) {
        return { status: 'already_connected' };
      }
      const session: Session = {
        clientPubkey,
        identityPubkey: pairing.identityPubkey,
        permissions:
          requested === null
            ? pairing.permissions
            : intersectPermissions(requested, pairing.permissions),
        clientMetadata,
        createdAt: now,
        lastUsedAt: now,
      };
      insertSession(sql, session);
      deletePairing(sql, pairing.id);
      return { status: 'created', session };
    });
  } catch (error) {
    if (error instanceof StorageFullError) {
      return { status: 'storage_full' };
    }
    throw error;
  }
}

// Throws MalformedPermissionsError if the stored permissions were altered.
export function getSession(
  sql: SqlStorage,
  clientPubkey: string,
): Session | null {
  const [row] = sql
    .exec<SessionRow>(
      `SELECT ${SESSION_COLUMNS} FROM sessions WHERE client_pubkey = ?`,
      clientPubkey,
    )
    .toArray();
  return row ? toSession(row) : null;
}

// Oldest first. Throws MalformedPermissionsError if any stored permissions
// were altered.
export function listSessions(
  sql: SqlStorage,
  identityPubkey: string,
): Session[] {
  return sql
    .exec<SessionRow>(
      `SELECT ${SESSION_COLUMNS} FROM sessions
      WHERE identity_pubkey = ?
      ORDER BY created_at, client_pubkey`,
      identityPubkey,
    )
    .toArray()
    .map(toSession);
}

export function revokeSession(sql: SqlStorage, clientPubkey: string): boolean {
  return (
    sql
      .exec(
        'DELETE FROM sessions WHERE client_pubkey = ? RETURNING client_pubkey',
        clientPubkey,
      )
      .toArray().length > 0
  );
}

// Records a successful authorized request. Only last_used_at changes, and it
// never moves backwards. Returns false if there is no such session.
//
// Throws StorageFullError.
export function touchSession(
  sql: SqlStorage,
  clientPubkey: string,
  now: number,
): boolean {
  return withStorageFullDetection(
    () =>
      sql
        .exec(
          `UPDATE sessions SET last_used_at = MAX(last_used_at, ?)
          WHERE client_pubkey = ? RETURNING client_pubkey`,
          now,
          clientPubkey,
        )
        .toArray().length > 0,
  );
}

function sessionExists(sql: SqlStorage, clientPubkey: string): boolean {
  return (
    sql
      .exec('SELECT 1 FROM sessions WHERE client_pubkey = ?', clientPubkey)
      .toArray().length > 0
  );
}

// No ON CONFLICT clause: should the already_connected check ever miss a
// session, the primary key makes this throw and roll the transaction back.
function insertSession(sql: SqlStorage, session: Session): void {
  const { name, url, image } = session.clientMetadata;
  withStorageFullDetection(() =>
    sql.exec(
      `INSERT INTO sessions (${SESSION_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      session.clientPubkey,
      session.identityPubkey,
      serializePermissions(session.permissions),
      name,
      url,
      image,
      session.createdAt,
      session.lastUsedAt,
    ),
  );
}

function toSession(row: SessionRow): Session {
  return {
    clientPubkey: row.client_pubkey,
    identityPubkey: row.identity_pubkey,
    permissions: deserializePermissions(row.permissions),
    clientMetadata: {
      name: row.client_name,
      url: row.client_url,
      image: row.client_image,
    },
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
  };
}

// The NIP-46 layer parses the metadata JSON and passes strings on.
function toClientMetadata(
  metadata: Partial<ClientMetadata> | undefined,
): ClientMetadata {
  return {
    name: metadataField(metadata?.name),
    url: metadataField(metadata?.url),
    image: metadataField(metadata?.image),
  };
}

function metadataField(value: unknown): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== 'string') {
    throw new TypeError('Client metadata fields must be strings');
  }
  return value;
}
