import { HTTPAuth } from 'nostr-tools/kinds';
import {
  type EventTemplate,
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  type NostrEvent,
} from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';

export const ORIGIN = 'https://signflare.example';
export const LOGIN_URL = `${ORIGIN}/admin/api/login`;

export interface TestKey {
  readonly secretKey: Uint8Array;
  readonly pubkey: string;
}

export function randomKey(): TestKey {
  const secretKey = generateSecretKey();
  return { secretKey, pubkey: getPublicKey(secretKey) };
}

export function unixNow(): number {
  return Math.floor(Date.now() / 1000);
}

// A NIP-98 event for POST /admin/api/login, with any field overridden.
// Round-tripped through JSON so that it carries no cached verification flag.
export function signHttpAuthEvent(
  key: TestKey,
  overrides: Partial<EventTemplate> = {},
): NostrEvent {
  const event = finalizeEvent(
    {
      kind: HTTPAuth,
      created_at: unixNow(),
      tags: [
        ['u', LOGIN_URL],
        ['method', 'POST'],
      ],
      content: '',
      ...overrides,
    },
    key.secretKey,
  );
  return JSON.parse(JSON.stringify(event));
}

export function encodeBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function nostrAuthorization(event: unknown): string {
  return `Nostr ${encodeBase64(new TextEncoder().encode(JSON.stringify(event)))}`;
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes =
    typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return bytesToHex(
    new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
  );
}

// Changes one hex digit, keeping the value well-formed.
export function tamperHex(hex: string, index = 0): string {
  const digit = hex[index] === '0' ? '1' : '0';
  return hex.slice(0, index) + digit + hex.slice(index + 1);
}
