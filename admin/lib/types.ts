// Admin API response bodies (src/admin-api.ts) as the Admin SPA uses them.
// They carry public information only, and each parser keeps exactly the
// fields below, so nothing else a response might hold reaches the UI.

export interface AdminSession {
  readonly pubkey: string;
  // Unix seconds, fixed at login.
  readonly expiresAt: number;
}

export interface AdminStatus {
  readonly identities: number;
  readonly sessions: number;
  // Pairings that can still establish a session.
  readonly pairings: number;
  // Bytes.
  readonly databaseSize: number;
}

export interface Identity {
  readonly pubkey: string;
  readonly npub: string;
  readonly createdAt: number;
  readonly updatedAt: number;
}

// Unauthenticated display hints sent by the client (docs/design.md §15).
export interface ClientMetadata {
  readonly name: string | null;
  readonly url: string | null;
  readonly image: string | null;
}

export interface ClientSession {
  readonly clientPubkey: string;
  readonly permissions: readonly string[];
  readonly clientMetadata: ClientMetadata;
  readonly createdAt: number;
  readonly lastUsedAt: number;
}

// The connection token of a new pairing: its bunkerUrl holds the one-time
// pairing secret and the remote-signer pubkey.
export interface Pairing {
  readonly bunkerUrl: string;
  readonly expiresAt: number;
}

// The permissions to grant a pairing: "all", or explicit permissions.
export type PairingPermissions = 'all' | readonly string[];

const PUBKEY = /^[0-9a-f]{64}$/;

export function parseAdminSession(value: unknown): AdminSession | null {
  if (
    !isRecord(value) ||
    !isPubkey(value.pubkey) ||
    !isCount(value.expiresAt)
  ) {
    return null;
  }
  return { pubkey: value.pubkey, expiresAt: value.expiresAt };
}

export function parseAdminStatus(value: unknown): AdminStatus | null {
  if (
    !isRecord(value) ||
    !isCount(value.identities) ||
    !isCount(value.sessions) ||
    !isCount(value.pairings) ||
    !isCount(value.databaseSize)
  ) {
    return null;
  }
  return {
    identities: value.identities,
    sessions: value.sessions,
    pairings: value.pairings,
    databaseSize: value.databaseSize,
  };
}

export function parseIdentity(value: unknown): Identity | null {
  if (
    !isRecord(value) ||
    !isPubkey(value.pubkey) ||
    typeof value.npub !== 'string' ||
    !value.npub.startsWith('npub1') ||
    !isCount(value.createdAt) ||
    !isCount(value.updatedAt)
  ) {
    return null;
  }
  return {
    pubkey: value.pubkey,
    npub: value.npub,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
  };
}

export function parseIdentities(value: unknown): Identity[] | null {
  return parseList(value, parseIdentity);
}

export function parseClientSessions(value: unknown): ClientSession[] | null {
  return parseList(value, parseClientSession);
}

export function parsePairing(value: unknown): Pairing | null {
  if (
    !isRecord(value) ||
    typeof value.bunkerUrl !== 'string' ||
    !value.bunkerUrl.startsWith('bunker://') ||
    !isCount(value.expiresAt)
  ) {
    return null;
  }
  return { bunkerUrl: value.bunkerUrl, expiresAt: value.expiresAt };
}

function parseClientSession(value: unknown): ClientSession | null {
  if (
    !isRecord(value) ||
    !isPubkey(value.clientPubkey) ||
    !Array.isArray(value.permissions) ||
    !value.permissions.every((permission) => typeof permission === 'string') ||
    !isRecord(value.clientMetadata) ||
    !isCount(value.createdAt) ||
    !isCount(value.lastUsedAt)
  ) {
    return null;
  }
  const { name, url, image } = value.clientMetadata;
  if (!isOptionalText(name) || !isOptionalText(url) || !isOptionalText(image)) {
    return null;
  }
  return {
    clientPubkey: value.clientPubkey,
    permissions: [...value.permissions],
    clientMetadata: { name, url, image },
    createdAt: value.createdAt,
    lastUsedAt: value.lastUsedAt,
  };
}

function parseList<T>(
  value: unknown,
  parse: (item: unknown) => T | null,
): T[] | null {
  if (!Array.isArray(value)) {
    return null;
  }
  const items: T[] = [];
  for (const item of value) {
    const parsed = parse(item);
    if (parsed === null) {
      return null;
    }
    items.push(parsed);
  }
  return items;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isPubkey(value: unknown): value is string {
  return typeof value === 'string' && PUBKEY.test(value);
}

// Counts, byte sizes, and Unix timestamps.
function isCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isOptionalText(value: unknown): value is string | null {
  return value === null || typeof value === 'string';
}
