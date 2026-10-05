import { decode } from 'nostr-tools/nip19';
import { getPublicKey } from 'nostr-tools/pure';
import { hexToBytes } from 'nostr-tools/utils';

// An nsec is 63 characters and a hex key is 64. Longer input is rejected
// before any Bech32 decoding or secp256k1 work is attempted.
export const MAX_PRIVATE_KEY_INPUT_LENGTH = 128;

const SECRET_KEY_LENGTH = 32;
const HEX_SECRET_KEY = /^[0-9a-fA-F]{64}$/;

// The message is deliberately generic: it must never echo the rejected input.
export class InvalidPrivateKeyError extends Error {
  constructor() {
    super('Invalid private key');
    this.name = 'InvalidPrivateKeyError';
  }
}

export interface ParsedPrivateKey {
  // The caller owns this buffer and should overwrite it once it is no longer needed.
  readonly secretKey: Uint8Array;
  // Lowercase hexadecimal Nostr public key.
  readonly pubkey: string;
}

// Accepts an `nsec` or a 64-character hexadecimal secret key, surrounded by
// optional whitespace.
export function parsePrivateKey(input: unknown): ParsedPrivateKey {
  if (typeof input !== 'string') {
    throw new InvalidPrivateKeyError();
  }
  const value = input.trim();
  if (value.length > MAX_PRIVATE_KEY_INPUT_LENGTH) {
    throw new InvalidPrivateKeyError();
  }

  const secretKey = decodeSecretKey(value);
  try {
    // Rejects scalars outside the secp256k1 range [1, n - 1].
    return { secretKey, pubkey: getPublicKey(secretKey) };
  } catch {
    secretKey.fill(0);
    throw new InvalidPrivateKeyError();
  }
}

function decodeSecretKey(value: string): Uint8Array {
  if (HEX_SECRET_KEY.test(value)) {
    return hexToBytes(value);
  }

  let decoded: ReturnType<typeof decode>;
  try {
    decoded = decode(value);
  } catch {
    // nostr-tools error messages can include the input, so they are discarded.
    throw new InvalidPrivateKeyError();
  }
  if (decoded.type !== 'nsec') {
    throw new InvalidPrivateKeyError();
  }
  if (decoded.data.length !== SECRET_KEY_LENGTH) {
    decoded.data.fill(0);
    throw new InvalidPrivateKeyError();
  }
  return decoded.data;
}
