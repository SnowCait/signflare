const PUBKEY = /^[0-9a-f]{64}$/;

// ADMIN_PUBKEY is public deployment configuration (docs/design.md §7.3).
// Returns null when it is missing or malformed so that callers can report a
// server configuration error instead of an authentication failure.
export function parseAdminPubkey(value: unknown): string | null {
  return typeof value === 'string' && PUBKEY.test(value) ? value : null;
}
