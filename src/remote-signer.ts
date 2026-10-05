import { InvalidPrivateKeyError, parsePrivateKey } from './private-key';

// The deployment-wide NIP-46 remote-signer keypair (docs/design.md §7.2). Its
// private key is the REMOTE_SIGNER_PRIVATE_KEY Worker secret, in the encodings
// identity registration accepts, but it is not an identity: it is never
// stored, and its public key is connection material that only
// pairing-generated bunker:// URLs carry.

export interface RemoteSignerKey {
  readonly secretKey: Uint8Array;
  // Lowercase hexadecimal Nostr public key.
  readonly pubkey: string;
}

// REMOTE_SIGNER_PRIVATE_KEY is missing or not a valid private key. The
// message is fixed: it never includes the configured value or a parser error.
export class RemoteSignerConfigurationError extends Error {
  constructor() {
    super('Invalid REMOTE_SIGNER_PRIVATE_KEY');
    this.name = 'RemoteSignerConfigurationError';
  }
}

// Parses REMOTE_SIGNER_PRIVATE_KEY, an nsec or a 64-character hex private key,
// and passes the key to `use`. The secret key bytes are overwritten, as a best
// effort, as soon as `use` returns or throws, so `use` must neither keep them
// nor finish with them asynchronously. The secret string itself cannot be
// erased.
//
// Throws RemoteSignerConfigurationError.
export function withRemoteSignerKey<T>(
  value: unknown,
  use: (key: RemoteSignerKey) => T,
): T {
  let key: RemoteSignerKey;
  try {
    key = parsePrivateKey(value);
  } catch (error) {
    if (error instanceof InvalidPrivateKeyError) {
      throw new RemoteSignerConfigurationError();
    }
    throw error;
  }
  try {
    return use(key);
  } finally {
    key.secretKey.fill(0);
  }
}

// Throws RemoteSignerConfigurationError.
export function remoteSignerPubkey(value: unknown): string {
  return withRemoteSignerKey(value, ({ pubkey }) => pubkey);
}
