import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { StorageFullError, withStorageFullDetection } from './storage-errors';

// Fixed at login and never extended by activity (docs/design.md §11.4).
export const ADMIN_SESSION_LIFETIME_SECONDS = 12 * 60 * 60;

const TOKEN_BYTES = 32;
const TOKEN = /^[0-9a-f]{64}$/;

export interface AdminSession {
  readonly adminPubkey: string;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface AdminLogin {
  // The verified NIP-98 login event being consumed, and the time from which
  // it no longer passes the timestamp check.
  readonly eventId: string;
  readonly eventExpiresAt: number;
  readonly tokenHash: Uint8Array;
  readonly adminPubkey: string;
  readonly now: number;
}

export type AdminLoginResult =
  | { readonly status: 'created'; readonly session: AdminSession }
  | { readonly status: 'replayed' }
  | { readonly status: 'storage_full' };

type AdminSessionRow = {
  admin_pubkey: string;
  created_at: number;
  expires_at: number;
};

// The raw token may only be sent to the browser as the session cookie. Store
// hashAdminSessionToken(token) instead.
export function generateAdminSessionToken(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(TOKEN_BYTES)));
}

export function isAdminSessionToken(value: string): boolean {
  return TOKEN.test(value);
}

// The token is 256 bits of randomness, so an unsalted SHA-256 is sufficient.
export async function hashAdminSessionToken(
  token: string,
): Promise<Uint8Array> {
  if (!isAdminSessionToken(token)) {
    throw new TypeError('Malformed admin session token');
  }
  return new Uint8Array(
    await crypto.subtle.digest('SHA-256', hexToBytes(token)),
  );
}

// Consumes the login event and issues the session in one transaction, so a
// replayed event, including a concurrent one, never yields a second session
// and a failure leaves neither row behind (docs/design.md §11.5).
export function createAdminSession(
  storage: DurableObjectStorage,
  login: AdminLogin,
): AdminLoginResult {
  if (login.eventExpiresAt <= login.now) {
    // The cleanup below may already have forgotten such an event.
    throw new RangeError('Login event is outside the authentication window');
  }
  const { sql } = storage;
  const session: AdminSession = {
    adminPubkey: login.adminPubkey,
    createdAt: login.now,
    expiresAt: login.now + ADMIN_SESSION_LIFETIME_SECONDS,
  };
  try {
    return storage.transactionSync((): AdminLoginResult => {
      deleteStaleAdminState(sql, login.adminPubkey, login.now);
      const consumed =
        sql
          .exec(
            'SELECT 1 FROM admin_auth_events WHERE event_id = ?',
            login.eventId,
          )
          .toArray().length > 0;
      if (consumed) {
        return { status: 'replayed' };
      }
      withStorageFullDetection(() => {
        // No ON CONFLICT clause: should the check above ever miss a consumed
        // event, its primary key makes this throw and roll everything back.
        sql.exec(
          'INSERT INTO admin_auth_events (event_id, expires_at) VALUES (?, ?)',
          login.eventId,
          login.eventExpiresAt,
        );
        sql.exec(
          `INSERT INTO admin_sessions (
            token_hash,
            admin_pubkey,
            expires_at,
            created_at
          ) VALUES (?, ?, ?, ?)`,
          login.tokenHash,
          session.adminPubkey,
          session.expiresAt,
          session.createdAt,
        );
      });
      return { status: 'created', session };
    });
  } catch (error) {
    if (error instanceof StorageFullError) {
      return { status: 'storage_full' };
    }
    throw error;
  }
}

// Returns the session only while it is unexpired and was issued to the
// currently configured administrator. Never changes its expiration.
export function authenticateAdminSession(
  sql: SqlStorage,
  tokenHash: Uint8Array,
  adminPubkey: string,
  now: number,
): AdminSession | null {
  const [row] = sql
    .exec<AdminSessionRow>(
      'SELECT admin_pubkey, created_at, expires_at FROM admin_sessions WHERE token_hash = ?',
      tokenHash,
    )
    .toArray();
  if (!row) {
    return null;
  }
  if (row.expires_at <= now || row.admin_pubkey !== adminPubkey) {
    // Removed so that it stays invalid even if ADMIN_PUBKEY is changed back.
    deleteAdminSession(sql, tokenHash);
    return null;
  }
  return {
    adminPubkey: row.admin_pubkey,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  };
}

export function deleteAdminSession(
  sql: SqlStorage,
  tokenHash: Uint8Array,
): boolean {
  return (
    sql
      .exec(
        'DELETE FROM admin_sessions WHERE token_hash = ? RETURNING admin_pubkey',
        tokenHash,
      )
      .toArray().length > 0
  );
}

// Lazy cleanup. An event row is kept until its event can no longer pass the
// timestamp check, so dropping it never re-enables a replay.
function deleteStaleAdminState(
  sql: SqlStorage,
  adminPubkey: string,
  now: number,
): void {
  sql.exec('DELETE FROM admin_auth_events WHERE expires_at <= ?', now);
  sql.exec(
    'DELETE FROM admin_sessions WHERE expires_at <= ? OR admin_pubkey != ?',
    now,
    adminPubkey,
  );
}
