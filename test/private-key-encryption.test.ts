import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { describe, expect, it } from 'vitest';
import {
  CURRENT_KEY_VERSION,
  type EncryptedPrivateKey,
  encryptPrivateKey,
  identityContext,
  IV_LENGTH,
  KDF_SALT_LENGTH,
  PrivateKeyDecryptionError,
  withDecryptedPrivateKey,
} from '../src/private-key-encryption';

// Test-only fixtures: trivially guessable scalars that must never hold funds or identity.
const SECRET_ONE = hexToBytes(`${'00'.repeat(31)}01`);
const PUBKEY_ONE =
  '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const SECRET_THREE = hexToBytes(`${'00'.repeat(31)}03`);
const PUBKEY_THREE =
  'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';

function randomMasterKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function flipBit(bytes: Uint8Array, index: number): Uint8Array {
  const copy = bytes.slice();
  copy[index] ^= 0x01;
  return copy;
}

function decryptToHex(
  masterKey: Uint8Array,
  pubkey: string,
  encrypted: EncryptedPrivateKey,
): Promise<string> {
  return withDecryptedPrivateKey(masterKey, pubkey, encrypted, (secretKey) =>
    bytesToHex(secretKey),
  );
}

describe('identityContext', () => {
  it('uses the normative HKDF context string', () => {
    expect(identityContext(PUBKEY_ONE, 1)).toBe(
      `signflare:identity:${PUBKEY_ONE}:v1`,
    );
    expect(identityContext(PUBKEY_ONE, 12)).toBe(
      `signflare:identity:${PUBKEY_ONE}:v12`,
    );
  });

  it('rejects components that would make the context ambiguous', () => {
    expect(() => identityContext(PUBKEY_ONE.toUpperCase(), 1)).toThrow(
      TypeError,
    );
    expect(() => identityContext(PUBKEY_ONE.slice(1), 1)).toThrow(TypeError);
    expect(() => identityContext(`${PUBKEY_ONE}:v1`, 1)).toThrow(TypeError);
    expect(() => identityContext(PUBKEY_ONE, 0)).toThrow(TypeError);
    expect(() => identityContext(PUBKEY_ONE, -1)).toThrow(TypeError);
    expect(() => identityContext(PUBKEY_ONE, 1.5)).toThrow(TypeError);
    expect(() => identityContext(PUBKEY_ONE, Number.NaN)).toThrow(TypeError);
  });
});

describe('encryptPrivateKey', () => {
  it('round-trips a private key', async () => {
    const masterKey = randomMasterKey();
    const encrypted = await encryptPrivateKey(
      masterKey,
      PUBKEY_ONE,
      SECRET_ONE,
    );
    expect(await decryptToHex(masterKey, PUBKEY_ONE, encrypted)).toBe(
      bytesToHex(SECRET_ONE),
    );
  });

  it('produces the stored envelope fields for key version 1', async () => {
    const encrypted = await encryptPrivateKey(
      randomMasterKey(),
      PUBKEY_ONE,
      SECRET_ONE,
    );
    expect(CURRENT_KEY_VERSION).toBe(1);
    expect(encrypted.keyVersion).toBe(1);
    expect(encrypted.iv.byteLength).toBe(IV_LENGTH);
    expect(encrypted.kdfSalt.byteLength).toBe(KDF_SALT_LENGTH);
    // 32-byte key plus a 16-byte GCM authentication tag.
    expect(encrypted.ciphertext.byteLength).toBe(48);
    expect(bytesToHex(encrypted.ciphertext)).not.toContain(
      bytesToHex(SECRET_ONE),
    );
  });

  it('does not modify the caller-owned secret key', async () => {
    const secretKey = SECRET_ONE.slice();
    await encryptPrivateKey(randomMasterKey(), PUBKEY_ONE, secretKey);
    expect(secretKey).toEqual(SECRET_ONE);
  });

  it('uses a fresh salt and IV for every encryption', async () => {
    const masterKey = randomMasterKey();
    const first = await encryptPrivateKey(masterKey, PUBKEY_ONE, SECRET_ONE);
    const second = await encryptPrivateKey(masterKey, PUBKEY_ONE, SECRET_ONE);
    expect(second.kdfSalt).not.toEqual(first.kdfSalt);
    expect(second.iv).not.toEqual(first.iv);
    expect(second.ciphertext).not.toEqual(first.ciphertext);
    expect(await decryptToHex(masterKey, PUBKEY_ONE, first)).toBe(
      bytesToHex(SECRET_ONE),
    );
    expect(await decryptToHex(masterKey, PUBKEY_ONE, second)).toBe(
      bytesToHex(SECRET_ONE),
    );
  });

  it('rejects a master key shorter than 256 bits', async () => {
    await expect(
      encryptPrivateKey(new Uint8Array(31), PUBKEY_ONE, SECRET_ONE),
    ).rejects.toThrow(TypeError);
  });

  it('rejects a secret key that is not 32 bytes', async () => {
    await expect(
      encryptPrivateKey(randomMasterKey(), PUBKEY_ONE, new Uint8Array(31)),
    ).rejects.toThrow(TypeError);
  });

  it('follows the documented HKDF-SHA-256 and AES-256-GCM envelope', async () => {
    const masterKey = randomMasterKey();
    const encrypted = await encryptPrivateKey(
      masterKey,
      PUBKEY_ONE,
      SECRET_ONE,
    );
    const context = new TextEncoder().encode(
      `signflare:identity:${PUBKEY_ONE}:v1`,
    );

    const rootKey = await crypto.subtle.importKey(
      'raw',
      masterKey,
      'HKDF',
      false,
      ['deriveKey'],
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: encrypted.kdfSalt, info: context },
      rootKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: encrypted.iv, additionalData: context },
      key,
      encrypted.ciphertext,
    );
    expect(new Uint8Array(plaintext)).toEqual(SECRET_ONE);

    // The same key without the pubkey/version AAD must not authenticate.
    await expect(
      crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: encrypted.iv },
        key,
        encrypted.ciphertext,
      ),
    ).rejects.toThrow();
  });
});

describe('withDecryptedPrivateKey', () => {
  it('derives independent encryption contexts for different identities', async () => {
    const masterKey = randomMasterKey();
    const one = await encryptPrivateKey(masterKey, PUBKEY_ONE, SECRET_ONE);
    const three = await encryptPrivateKey(
      masterKey,
      PUBKEY_THREE,
      SECRET_THREE,
    );

    expect(await decryptToHex(masterKey, PUBKEY_THREE, three)).toBe(
      bytesToHex(SECRET_THREE),
    );
    await expect(decryptToHex(masterKey, PUBKEY_THREE, one)).rejects.toThrow(
      PrivateKeyDecryptionError,
    );
    // Even with an identical salt and IV, the other identity's key cannot open it.
    await expect(
      decryptToHex(masterKey, PUBKEY_THREE, {
        ...three,
        ciphertext: one.ciphertext,
        iv: one.iv,
        kdfSalt: one.kdfSalt,
      }),
    ).rejects.toThrow(PrivateKeyDecryptionError);
  });

  it('fails with the wrong master key', async () => {
    const encrypted = await encryptPrivateKey(
      randomMasterKey(),
      PUBKEY_ONE,
      SECRET_ONE,
    );
    await expect(
      decryptToHex(randomMasterKey(), PUBKEY_ONE, encrypted),
    ).rejects.toThrow(PrivateKeyDecryptionError);
  });

  it('fails when the ciphertext or tag is modified', async () => {
    const masterKey = randomMasterKey();
    const encrypted = await encryptPrivateKey(
      masterKey,
      PUBKEY_ONE,
      SECRET_ONE,
    );
    for (const index of [0, 31, 32, 47]) {
      await expect(
        decryptToHex(masterKey, PUBKEY_ONE, {
          ...encrypted,
          ciphertext: flipBit(encrypted.ciphertext, index),
        }),
      ).rejects.toThrow(PrivateKeyDecryptionError);
    }
    await expect(
      decryptToHex(masterKey, PUBKEY_ONE, {
        ...encrypted,
        ciphertext: encrypted.ciphertext.slice(0, 32),
      }),
    ).rejects.toThrow(PrivateKeyDecryptionError);
  });

  it('fails when the pubkey in the AAD differs', async () => {
    const masterKey = randomMasterKey();
    const encrypted = await encryptPrivateKey(
      masterKey,
      PUBKEY_ONE,
      SECRET_ONE,
    );
    const otherPubkey = `${PUBKEY_ONE.slice(0, -1)}9`;
    await expect(
      decryptToHex(masterKey, otherPubkey, encrypted),
    ).rejects.toThrow(PrivateKeyDecryptionError);
  });

  it('fails when the key version differs', async () => {
    const masterKey = randomMasterKey();
    const encrypted = await encryptPrivateKey(
      masterKey,
      PUBKEY_ONE,
      SECRET_ONE,
    );
    await expect(
      decryptToHex(masterKey, PUBKEY_ONE, { ...encrypted, keyVersion: 2 }),
    ).rejects.toThrow(PrivateKeyDecryptionError);
  });

  it('fails when the IV is modified', async () => {
    const masterKey = randomMasterKey();
    const encrypted = await encryptPrivateKey(
      masterKey,
      PUBKEY_ONE,
      SECRET_ONE,
    );
    await expect(
      decryptToHex(masterKey, PUBKEY_ONE, {
        ...encrypted,
        iv: flipBit(encrypted.iv, 0),
      }),
    ).rejects.toThrow(PrivateKeyDecryptionError);
    await expect(
      decryptToHex(masterKey, PUBKEY_ONE, {
        ...encrypted,
        iv: encrypted.iv.slice(0, IV_LENGTH - 1),
      }),
    ).rejects.toThrow(PrivateKeyDecryptionError);
  });

  it('fails when the KDF salt is modified', async () => {
    const masterKey = randomMasterKey();
    const encrypted = await encryptPrivateKey(
      masterKey,
      PUBKEY_ONE,
      SECRET_ONE,
    );
    await expect(
      decryptToHex(masterKey, PUBKEY_ONE, {
        ...encrypted,
        kdfSalt: flipBit(encrypted.kdfSalt, KDF_SALT_LENGTH - 1),
      }),
    ).rejects.toThrow(PrivateKeyDecryptionError);
    await expect(
      decryptToHex(masterKey, PUBKEY_ONE, {
        ...encrypted,
        kdfSalt: encrypted.kdfSalt.slice(1),
      }),
    ).rejects.toThrow(PrivateKeyDecryptionError);
  });

  it('overwrites the decrypted key after use', async () => {
    const masterKey = randomMasterKey();
    const encrypted = await encryptPrivateKey(
      masterKey,
      PUBKEY_ONE,
      SECRET_ONE,
    );
    let exposed: Uint8Array | undefined;
    await withDecryptedPrivateKey(masterKey, PUBKEY_ONE, encrypted, (key) => {
      expect(key).toEqual(SECRET_ONE);
      exposed = key;
    });
    expect(exposed).toEqual(new Uint8Array(32));
  });

  it('overwrites the decrypted key when the operation throws', async () => {
    const masterKey = randomMasterKey();
    const encrypted = await encryptPrivateKey(
      masterKey,
      PUBKEY_ONE,
      SECRET_ONE,
    );
    let exposed: Uint8Array | undefined;
    await expect(
      withDecryptedPrivateKey(masterKey, PUBKEY_ONE, encrypted, async (key) => {
        exposed = key;
        throw new Error('operation failed');
      }),
    ).rejects.toThrow('operation failed');
    expect(exposed).toEqual(new Uint8Array(32));
  });

  it('does not run the operation when decryption fails', async () => {
    const encrypted = await encryptPrivateKey(
      randomMasterKey(),
      PUBKEY_ONE,
      SECRET_ONE,
    );
    let called = false;
    await expect(
      withDecryptedPrivateKey(randomMasterKey(), PUBKEY_ONE, encrypted, () => {
        called = true;
      }),
    ).rejects.toThrow(PrivateKeyDecryptionError);
    expect(called).toBe(false);
  });
});
