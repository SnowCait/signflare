// The NIP-11 Relay Information Document of the restricted NIP-46 relay at the
// root (docs/design.md §4.4, §37.2). It is built from ADMIN_PUBKEY alone. It
// has no `self` and never carries the remote-signer pubkey, which is
// connection material that only bunker:// connection tokens disclose (§7.2).

export const RELAY_INFORMATION_MEDIA_TYPE = 'application/nostr+json';

export const SOFTWARE_URL = 'https://github.com/SnowCait/signflare';

// NIP-11 requires relays to send these three. The document is public and
// read without credentials, so any origin may read it, sending any request
// headers. Clients fetch it with GET; HEAD and the OPTIONS preflight are
// answered as well.
export const RELAY_INFORMATION_CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
} as const;

export interface RelayInformation {
  readonly name: string;
  readonly description: string;
  readonly pubkey: string;
  readonly supported_nips: readonly number[];
  readonly software: string;
  readonly limitation: { readonly restricted_writes: boolean };
}

// RFC 9110 §12.4.2: a weight of 0 marks a media range as not acceptable.
const ZERO_WEIGHT = /^\s*q=0(?:\.0{0,3})?\s*$/i;

// Whether an Accept header asks for the relay information document, by
// listing application/nostr+json with a nonzero weight. Wildcards such as */*
// do not count, so that browsers get the landing page instead.
export function acceptsRelayInformation(accept: string | undefined): boolean {
  if (accept === undefined) {
    return false;
  }
  return accept.split(',').some((range) => {
    const [mediaType, ...parameters] = range.split(';');
    return (
      mediaType.trim().toLowerCase() === RELAY_INFORMATION_MEDIA_TYPE &&
      !parameters.some((parameter) => ZERO_WEIGHT.test(parameter))
    );
  });
}

// `adminPubkey` is the parsed ADMIN_PUBKEY: the administrative contact.
export function relayInformation(adminPubkey: string): RelayInformation {
  return {
    name: 'Signflare',
    description: 'Restricted relay for Signflare NIP-46 remote signing.',
    pubkey: adminPubkey,
    supported_nips: [1, 11, 46],
    software: SOFTWARE_URL,
    limitation: { restricted_writes: true },
  };
}
