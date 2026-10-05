// At-rest envelope for registered identity private keys (docs/design.md §10).
//
// Buffers owned by this module are overwritten after use. This is best effort
// only: the runtime, Web Crypto, and callers may hold other copies, so it is not
// a guarantee that the key has been erased from memory.

export const CURRENT_KEY_VERSION = 1;

// MASTER_ENCRYPTION_KEY must carry at least 256 bits of key material (§7.1).
export const MIN_MASTER_KEY_LENGTH = 32;
export const KDF_SALT_LENGTH = 32;
export const IV_LENGTH = 12;

const SECRET_KEY_LENGTH = 32;
const PUBKEY = /^[0-9a-f]{64}$/;

export interface EncryptedPrivateKey {
  readonly ciphertext: Uint8Array;
  readonly iv: Uint8Array;
  readonly kdfSalt: Uint8Array;
  readonly keyVersion: number;
}

// Covers a wrong master key and any tampering with the stored envelope. The
// message never includes key material.
export class PrivateKeyDecryptionError extends Error {
  constructor() {
    super('Failed to decrypt identity private key');
    this.name = 'PrivateKeyDecryptionError';
  }
}

// The normative HKDF context `signflare:identity:<pubkey>:v<key_version>`.
//
// The same string, UTF-8 encoded, is also the AES-GCM additional authenticated
// data, so the ciphertext is bound to the pubkey and key version independently
// of the key derivation. The encoding is unambiguous because the pubkey is
// always exactly 64 lowercase hex characters and the version is a positive
// integer written in base 10 without leading zeros.
export function identityContext(pubkey: string, keyVersion: number): string {
  if (!PUBKEY.test(pubkey)) {
    throw new TypeError('pubkey must be 64 lowercase hexadecimal characters');
  }
  if (!Number.isSafeInteger(keyVersion) || keyVersion < 1) {
    throw new TypeError('keyVersion must be a positive integer');
  }
  return `signflare:identity:${pubkey}:v${keyVersion}`;
}

export async function encryptPrivateKey(
  masterKey: Uint8Array,
  pubkey: string,
  secretKey: Uint8Array,
): Promise<EncryptedPrivateKey> {
  if (secretKey.byteLength !== SECRET_KEY_LENGTH) {
    throw new TypeError('secretKey must be 32 bytes');
  }
  const keyVersion = CURRENT_KEY_VERSION;
  const context = new TextEncoder().encode(identityContext(pubkey, keyVersion));
  const kdfSalt = crypto.getRandomValues(new Uint8Array(KDF_SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const key = await deriveIdentityKey(masterKey, kdfSalt, context, 'encrypt');
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: context, tagLength: 128 },
    key,
    secretKey,
  );
  return { ciphertext: new Uint8Array(ciphertext), iv, kdfSalt, keyVersion };
}

// Decrypts the key only for the duration of `use` and overwrites the
// plaintext buffer afterwards, whether `use` succeeds or throws.
export async function withDecryptedPrivateKey<T>(
  masterKey: Uint8Array,
  pubkey: string,
  encrypted: EncryptedPrivateKey,
  use: (secretKey: Uint8Array) => T | Promise<T>,
): Promise<T> {
  const secretKey = await decryptPrivateKey(masterKey, pubkey, encrypted);
  try {
    return await use(secretKey);
  } finally {
    secretKey.fill(0);
  }
}

async function decryptPrivateKey(
  masterKey: Uint8Array,
  pubkey: string,
  { ciphertext, iv, kdfSalt, keyVersion }: EncryptedPrivateKey,
): Promise<Uint8Array> {
  const context = new TextEncoder().encode(identityContext(pubkey, keyVersion));
  if (iv.byteLength !== IV_LENGTH || kdfSalt.byteLength !== KDF_SALT_LENGTH) {
    throw new PrivateKeyDecryptionError();
  }

  const key = await deriveIdentityKey(masterKey, kdfSalt, context, 'decrypt');
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: context, tagLength: 128 },
        key,
        ciphertext,
      ),
    );
  } catch {
    throw new PrivateKeyDecryptionError();
  }
  if (plaintext.byteLength !== SECRET_KEY_LENGTH) {
    plaintext.fill(0);
    throw new PrivateKeyDecryptionError();
  }
  return plaintext;
}

async function deriveIdentityKey(
  masterKey: Uint8Array,
  kdfSalt: Uint8Array,
  context: Uint8Array,
  usage: 'encrypt' | 'decrypt',
): Promise<CryptoKey> {
  if (masterKey.byteLength < MIN_MASTER_KEY_LENGTH) {
    throw new TypeError('masterKey must be at least 32 bytes');
  }
  const rootKey = await crypto.subtle.importKey(
    'raw',
    masterKey,
    'HKDF',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: kdfSalt, info: context },
    rootKey,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  );
}
