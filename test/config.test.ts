import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { afterEach, describe, expect, expectTypeOf, it, vi } from 'vitest';
import gitignore from '../.gitignore?raw';
import wranglerConfig from '../wrangler.jsonc?raw';
import {
  parseMasterEncryptionKey,
  type SignflareBindings,
} from '../src/config';

// Test-only values. None of them is a real secret.
const ASCII_32 = 'test-only master key: 32 bytes!!';
const ASCII_31 = 'test-only master key: 31 bytes!';

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

// wrangler.jsonc as JSON: without comments and trailing commas.
function parseJsonc(text: string): unknown {
  return JSON.parse(
    text.replace(/^\s*\/\/.*$/gm, '').replace(/,(\s*[}\]])/g, '$1'),
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('deployment configuration', () => {
  it('declares no required secrets in wrangler.jsonc', () => {
    // With secrets.required set, local development loads only the listed keys
    // from .dev.vars and .env, so ADMIN_PUBKEY and MASTER_ENCRYPTION_KEY could
    // no longer be configured there together.
    const config = parseJsonc(wranglerConfig) as Record<string, unknown>;
    expect(config).not.toHaveProperty('secrets');
  });

  it('keeps configuration values out of the repository', () => {
    const config = parseJsonc(wranglerConfig) as Record<string, unknown>;
    expect(config).not.toHaveProperty('vars');
    expect(wranglerConfig).not.toContain('MASTER_ENCRYPTION_KEY');
    expect(wranglerConfig).not.toContain('ADMIN_PUBKEY');
    // Local values belong in .dev.vars or .env, which are never committed.
    const ignored = gitignore.split('\n');
    expect(ignored).toContain('.dev.vars*');
    expect(ignored).toContain('.env*');
  });

  it('types ADMIN_PUBKEY and MASTER_ENCRYPTION_KEY as optional bindings', () => {
    expectTypeOf<SignflareBindings>()
      .toHaveProperty('ADMIN_PUBKEY')
      .toEqualTypeOf<string | undefined>();
    expectTypeOf<SignflareBindings>()
      .toHaveProperty('MASTER_ENCRYPTION_KEY')
      .toEqualTypeOf<string | undefined>();
    expectTypeOf<SignflareBindings>().toExtend<Env>();
    expectTypeOf<{
      ADMIN_PUBKEY: string;
      MASTER_ENCRYPTION_KEY: string;
      SIGNER_HUB: Env['SIGNER_HUB'];
    }>().toExtend<SignflareBindings>();
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
