import { npubEncode } from 'nostr-tools/nip19';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseAdminPubkey, parseMasterEncryptionKey } from '../src/config';

// Test-only values. None of them is a real secret.
const ASCII_32 = 'test-only master key: 32 bytes!!';
const ASCII_31 = 'test-only master key: 31 bytes!';
// The public key of the private key 1.
const PUBKEY_ONE =
  '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('parseAdminPubkey', () => {
  it('accepts a lowercase 64-character hex public key', () => {
    expect(parseAdminPubkey(PUBKEY_ONE)).toBe(PUBKEY_ONE);
  });

  it.each<[string, unknown]>([
    ['a missing value', undefined],
    ['the empty placeholder in wrangler.jsonc', ''],
    ['a number', 12_345],
    ['uppercase hex', PUBKEY_ONE.toUpperCase()],
    ['63 characters', PUBKEY_ONE.slice(1)],
    ['65 characters', `${PUBKEY_ONE}0`],
    ['surrounding whitespace', ` ${PUBKEY_ONE}\n`],
    ['an npub', npubEncode(PUBKEY_ONE)],
  ])('rejects %s', (_case, value) => {
    expect(parseAdminPubkey(value)).toBeNull();
  });
});

describe('parseMasterEncryptionKey', () => {
  it('returns the exact UTF-8 bytes of the secret text', () => {
    expect(parseMasterEncryptionKey(ASCII_32)).toEqual(utf8(ASCII_32));
  });

  it.each<[string, string]>([
    ['exactly 32 bytes', ASCII_32],
    ['33 bytes', `${ASCII_32}!`],
    ['64 bytes', ASCII_32.repeat(2)],
    ['1 KiB', 'k'.repeat(1024)],
  ])('accepts %s', (_case, value) => {
    const masterKey = parseMasterEncryptionKey(value);
    expect(masterKey).toEqual(utf8(value));
    expect(masterKey?.byteLength).toBe(utf8(value).byteLength);
  });

  it.each<[string, unknown]>([
    ['a missing value', undefined],
    ['null', null],
    ['a number', 12_345],
    ['bytes', utf8(ASCII_32)],
    ['an empty string', ''],
    ['31 bytes', ASCII_31],
  ])('rejects %s', (_case, value) => {
    expect(parseMasterEncryptionKey(value)).toBeNull();
  });

  it('counts UTF-8 bytes rather than characters', () => {
    // 3, 2, and 4 bytes in UTF-8.
    const kanji = '\u9375';
    const accented = '\u00e9';
    const emoji = '\u{1f511}';
    expect(parseMasterEncryptionKey(kanji.repeat(10))).toBeNull();
    expect(parseMasterEncryptionKey(`${accented.repeat(15)}a`)).toBeNull();

    for (const value of [
      `${kanji.repeat(10)}ab`,
      accented.repeat(16),
      emoji.repeat(8),
    ]) {
      expect(value.length).toBeLessThan(32);
      const masterKey = parseMasterEncryptionKey(value);
      expect(masterKey).toEqual(utf8(value));
      expect(masterKey?.byteLength).toBe(32);
    }
  });

  it('does not trim the value', () => {
    // 30 bytes once trimmed, which would be rejected.
    const padded = ` ${ASCII_32.slice(2)}\n`;
    expect(parseMasterEncryptionKey(padded)).toEqual(utf8(padded));
    expect(parseMasterEncryptionKey(' '.repeat(32))).toEqual(
      utf8(' '.repeat(32)),
    );
  });

  it('does not normalize the value', () => {
    const decomposed = 'test-only cafe\u0301 master key, decomposed';
    const masterKey = parseMasterEncryptionKey(decomposed);
    expect(masterKey).toEqual(utf8(decomposed));
    expect(masterKey).not.toEqual(utf8(decomposed.normalize('NFC')));
  });

  it('does not decode hex', () => {
    const hex = '0123456789abcdef'.repeat(4);
    expect(parseMasterEncryptionKey(hex)).toEqual(utf8(hex));
    // Decoded, 62 hex digits would be 31 bytes and rejected.
    const shortHex = hex.slice(2);
    expect(hexToBytes(shortHex).byteLength).toBe(31);
    expect(parseMasterEncryptionKey(shortHex)).toEqual(utf8(shortHex));
  });

  it('does not decode base64', () => {
    // Decoded, this would be 30 bytes and rejected.
    const base64 = btoa('test-only master key, 30 bytes');
    expect(base64).toHaveLength(40);
    expect(parseMasterEncryptionKey(base64)).toEqual(utf8(base64));
  });

  it('returns a new buffer the caller can overwrite', () => {
    const first = parseMasterEncryptionKey(ASCII_32);
    first?.fill(0);
    expect(parseMasterEncryptionKey(ASCII_32)).toEqual(utf8(ASCII_32));
  });

  it('overwrites the bytes of a value it rejects', () => {
    const encode = vi.spyOn(TextEncoder.prototype, 'encode');
    expect(parseMasterEncryptionKey(ASCII_31)).toBeNull();
    expect(encode).toHaveBeenCalledOnce();
    const [{ value: encoded }] = encode.mock.results;
    expect(bytesToHex(encoded)).toBe('00'.repeat(31));
  });
});
