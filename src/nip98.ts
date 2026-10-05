import { HTTPAuth } from 'nostr-tools/kinds';
import { type NostrEvent, validateEvent, verifyEvent } from 'nostr-tools/pure';
import { bytesToHex } from 'nostr-tools/utils';

// NIP-98 HTTP authentication (docs/design.md §30.1).
//
// The validation helpers in nostr-tools/nip98 are deliberately not used: the
// installed version hashes JSON.stringify(body) instead of the raw request
// body, compares the method case-insensitively, and reads the clock itself.

// created_at must be less than this many seconds away from the server clock,
// in either direction.
export const NIP98_TIME_WINDOW_SECONDS = 60;

// A login event with a payload tag encodes to roughly 700 characters. Longer
// headers are rejected before decoding or signature verification.
export const MAX_AUTHORIZATION_HEADER_LENGTH = 4096;

export type Nip98FailureReason =
  | 'missing'
  | 'malformed'
  | 'kind'
  | 'pubkey'
  | 'created_at'
  | 'url'
  | 'method'
  | 'payload'
  | 'signature';

// The message is deliberately generic: it never echoes the authorization.
export class Nip98AuthError extends Error {
  constructor(readonly reason: Nip98FailureReason) {
    super('Invalid NIP-98 authorization');
    this.name = 'Nip98AuthError';
  }
}

export interface Nip98Request {
  // The absolute URL and method of the request as received.
  readonly url: string;
  readonly method: string;
  // The raw request body, empty when the request has none.
  readonly body: Uint8Array;
  // The only pubkey allowed to authenticate.
  readonly pubkey: string;
  readonly now: number;
}

const AUTHORIZATION = /^Nostr +([A-Za-z0-9+/]+={0,2})$/i;
const HEX_ID = /^[0-9a-f]{64}$/;
const HEX_SIG = /^[0-9a-f]{128}$/;

// Decodes `Authorization: Nostr <base64 event>`. Throws Nip98AuthError.
export function parseNip98Authorization(
  header: string | undefined,
): NostrEvent {
  if (!header) {
    throw new Nip98AuthError('missing');
  }
  if (header.length > MAX_AUTHORIZATION_HEADER_LENGTH) {
    throw new Nip98AuthError('malformed');
  }
  const encoded = AUTHORIZATION.exec(header)?.[1];
  if (encoded === undefined || encoded.length % 4 !== 0) {
    throw new Nip98AuthError('malformed');
  }

  let event: unknown;
  try {
    const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    event = JSON.parse(
      new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes),
    );
  } catch {
    // Parser messages can quote the input, so they are discarded.
    throw new Nip98AuthError('malformed');
  }
  if (!isSignedEvent(event)) {
    throw new Nip98AuthError('malformed');
  }
  return event;
}

// Throws Nip98AuthError unless the event authorizes exactly this request.
export async function verifyNip98Event(
  event: NostrEvent,
  request: Nip98Request,
): Promise<void> {
  if (event.kind !== HTTPAuth) {
    throw new Nip98AuthError('kind');
  }
  if (event.pubkey !== request.pubkey) {
    throw new Nip98AuthError('pubkey');
  }
  if (Math.abs(request.now - event.created_at) >= NIP98_TIME_WINDOW_SECONDS) {
    throw new Nip98AuthError('created_at');
  }
  if (singleTagValue(event, 'u') !== request.url) {
    throw new Nip98AuthError('url');
  }
  if (singleTagValue(event, 'method') !== request.method) {
    throw new Nip98AuthError('method');
  }

  // A body must be covered by a payload tag, and a payload tag must match the
  // body as sent, byte for byte.
  const payloads = tagValues(event, 'payload');
  if (
    payloads.length > 1 ||
    (payloads.length === 0 && request.body.byteLength > 0) ||
    (payloads.length === 1 && payloads[0] !== (await sha256Hex(request.body)))
  ) {
    throw new Nip98AuthError('payload');
  }

  // Last, as the most expensive check. Also requires id to be the event hash.
  // verifyEvent trusts a cached verification flag on the object; events from
  // parseNip98Authorization are freshly parsed and never carry one.
  if (!verifyEvent(event)) {
    throw new Nip98AuthError('signature');
  }
}

// The time from which the event no longer passes the timestamp check.
export function nip98EventExpiresAt(event: NostrEvent): number {
  return event.created_at + NIP98_TIME_WINDOW_SECONDS;
}

function isSignedEvent(value: unknown): value is NostrEvent {
  if (!validateEvent(value)) {
    return false;
  }
  const { id, sig } = value as Partial<NostrEvent>;
  return (
    Number.isSafeInteger(value.kind) &&
    Number.isSafeInteger(value.created_at) &&
    typeof id === 'string' &&
    HEX_ID.test(id) &&
    typeof sig === 'string' &&
    HEX_SIG.test(sig)
  );
}

function tagValues(event: NostrEvent, name: string): (string | undefined)[] {
  return event.tags.filter((tag) => tag[0] === name).map((tag) => tag[1]);
}

// Undefined unless the tag occurs exactly once.
function singleTagValue(event: NostrEvent, name: string): string | undefined {
  const values = tagValues(event, name);
  return values.length === 1 ? values[0] : undefined;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  return bytesToHex(
    new Uint8Array(await crypto.subtle.digest('SHA-256', data)),
  );
}
