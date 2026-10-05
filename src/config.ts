import { MIN_MASTER_KEY_LENGTH } from './private-key-encryption';

const PUBKEY = /^[0-9a-f]{64}$/;

// ADMIN_PUBKEY is public deployment configuration (docs/design.md §7.3).
// Returns null when it is missing or malformed so that callers can report a
// server configuration error instead of an authentication failure.
export function parseAdminPubkey(value: unknown): string | null {
  return typeof value === 'string' && PUBKEY.test(value) ? value : null;
}

// MASTER_ENCRYPTION_KEY is a Worker secret (docs/design.md §7.1). The exact
// UTF-8 bytes of its text are the root key material: the text is not trimmed,
// normalized, or decoded from hex or base64. Returns null when it is missing
// or shorter than 32 bytes, so that callers can report a server configuration
// error. The length check says nothing about the entropy of the value.
//
// The caller owns the returned buffer and should overwrite it once it is no
// longer needed. The secret string itself cannot be erased.
export function parseMasterEncryptionKey(value: unknown): Uint8Array | null {
  if (typeof value !== 'string') {
    return null;
  }
  const masterKey = new TextEncoder().encode(value);
  if (masterKey.byteLength < MIN_MASTER_KEY_LENGTH) {
    masterKey.fill(0);
    return null;
  }
  return masterKey;
}
