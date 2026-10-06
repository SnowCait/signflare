import type { Nip07Signer } from './lib/nip98';

declare global {
  interface Window {
    // Set by a NIP-07 browser signer extension, when one is installed.
    nostr?: Nip07Signer;
  }
}
