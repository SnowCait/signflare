import { ADMIN_API_PATH } from './api';

// NIP-98 login through a NIP-07 browser signer (docs/design.md §30.1, §31.2).
// https://github.com/nostr-protocol/nips/blob/master/07.md
// https://github.com/nostr-protocol/nips/blob/master/98.md
//
// The signed event is only ever turned into the Authorization header of the
// login request. It is not stored or logged, and error messages never quote
// the event or what the signer threw.

export const HTTP_AUTH_KIND = 27235;

export interface EventTemplate {
  readonly kind: number;
  readonly created_at: number;
  readonly tags: string[][];
  readonly content: string;
}

export interface SignedEvent extends EventTemplate {
  readonly id: string;
  readonly pubkey: string;
  readonly sig: string;
}

// The part of window.nostr that the Admin UI uses. What signEvent() returns
// is checked before use.
export interface Nip07Signer {
  signEvent(event: EventTemplate): Promise<unknown>;
}

export class NoSignerError extends Error {
  constructor() {
    super('No NIP-07 signer is available');
    this.name = 'NoSignerError';
  }
}

export class SignerRejectedError extends Error {
  constructor() {
    super('The NIP-07 signer did not sign the login event');
    this.name = 'SignerRejectedError';
  }
}

export class InvalidSignedEventError extends Error {
  constructor() {
    super('The NIP-07 signer returned an invalid event');
    this.name = 'InvalidSignedEventError';
  }
}

const HEX_32 = /^[0-9a-f]{64}$/;
const HEX_64 = /^[0-9a-f]{128}$/;

// btoa() is given at most this many bytes at a time, as one character each.
const BASE64_CHUNK_BYTES = 0x3000;

export function unixNow(): number {
  return Math.floor(Date.now() / 1000);
}

// The absolute URL of POST /admin/api/login for the page at `pageUrl`. The
// login request is sent to this exact URL, and the u tag must equal it.
export function loginUrl(pageUrl: string | URL): string {
  return new URL(`${ADMIN_API_PATH}/login`, pageUrl).href;
}

// The login request has no body, so the event has no payload tag.
export function loginEventTemplate(url: string, now: number): EventTemplate {
  return {
    kind: HTTP_AUTH_KIND,
    created_at: now,
    tags: [
      ['u', url],
      ['method', 'POST'],
    ],
    content: '',
  };
}

// Throws NoSignerError, SignerRejectedError, or InvalidSignedEventError.
export async function signLoginEvent(
  signer: Nip07Signer | undefined,
  url: string,
  now: number,
): Promise<SignedEvent> {
  if (typeof signer?.signEvent !== 'function') {
    throw new NoSignerError();
  }
  const template = loginEventTemplate(url, now);
  let signed: unknown;
  try {
    // A copy, so that a signer that fills in the object it is given cannot
    // change the template.
    signed = await signer.signEvent({
      ...template,
      tags: template.tags.map((tag) => [...tag]),
    });
  } catch {
    throw new SignerRejectedError();
  }
  return signedLoginEvent(signed, template);
}

// `Authorization: Nostr <base64>` for the event: its JSON is UTF-8 encoded
// before base64, so that any character survives (NIP-98).
export function nostrAuthorization(event: SignedEvent): string {
  return `Nostr ${encodeBase64(new TextEncoder().encode(JSON.stringify(event)))}`;
}

// btoa() only accepts characters up to U+00FF. Each byte is therefore passed
// as the character of the same value, never the text itself.
export function encodeBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += BASE64_CHUNK_BYTES) {
    binary += String.fromCharCode(
      ...bytes.subarray(offset, offset + BASE64_CHUNK_BYTES),
    );
  }
  return btoa(binary);
}

// The signed template with the NIP-01 fields only. Anything a signer adds
// beyond id, pubkey, and sig is not sent.
function signedLoginEvent(
  value: unknown,
  template: EventTemplate,
): SignedEvent {
  if (typeof value !== 'object' || value === null) {
    throw new InvalidSignedEventError();
  }
  const event = value as Record<string, unknown>;
  const { id, pubkey, sig } = event;
  if (
    typeof id !== 'string' ||
    !HEX_32.test(id) ||
    typeof pubkey !== 'string' ||
    !HEX_32.test(pubkey) ||
    typeof sig !== 'string' ||
    !HEX_64.test(sig) ||
    event.kind !== template.kind ||
    event.created_at !== template.created_at ||
    event.content !== template.content ||
    !sameTags(event.tags, template.tags)
  ) {
    throw new InvalidSignedEventError();
  }
  return {
    id,
    pubkey,
    created_at: template.created_at,
    kind: template.kind,
    tags: template.tags.map((tag) => [...tag]),
    content: template.content,
    sig,
  };
}

function sameTags(value: unknown, tags: readonly string[][]): boolean {
  return (
    Array.isArray(value) &&
    value.length === tags.length &&
    value.every(
      (tag, i) =>
        Array.isArray(tag) &&
        tag.length === tags[i].length &&
        tag.every((item, j) => item === tags[i][j]),
    )
  );
}
