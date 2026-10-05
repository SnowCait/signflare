import {
  encodeBytes,
  neventEncode,
  noteEncode,
  nprofileEncode,
  npubEncode,
  nsecEncode,
} from 'nostr-tools/nip19';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { describe, expect, it } from 'vitest';
import {
  InvalidPrivateKeyError,
  MAX_PRIVATE_KEY_INPUT_LENGTH,
  parsePrivateKey,
} from '../src/private-key';

// Test-only fixtures: trivially guessable scalars that must never hold funds or identity.
const SECRET_ONE_HEX = `${'00'.repeat(31)}01`;
const SECRET_ONE_NSEC =
  'nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsmhltgl';
// x-coordinate of the secp256k1 generator point.
const PUBKEY_ONE =
  '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
// BIP-340 test vector 0.
const SECRET_THREE_HEX = `${'00'.repeat(31)}03`;
const PUBKEY_THREE =
  'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const CURVE_ORDER_HEX =
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
const CURVE_ORDER_MINUS_ONE_HEX =
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140';

function expectRejected(input: unknown): void {
  let caught: unknown;
  try {
    parsePrivateKey(input);
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(InvalidPrivateKeyError);
  const error = caught as InvalidPrivateKeyError;
  expect(error.message).toBe('Invalid private key');
  expect(error.cause).toBeUndefined();
  if (typeof input === 'string' && input.trim().length > 0) {
    expect(String(error)).not.toContain(input.trim());
    expect(JSON.stringify(error)).not.toContain(input.trim());
  }
}

describe('parsePrivateKey', () => {
  it('accepts a valid nsec', () => {
    const { secretKey, pubkey } = parsePrivateKey(SECRET_ONE_NSEC);
    expect(bytesToHex(secretKey)).toBe(SECRET_ONE_HEX);
    expect(pubkey).toBe(PUBKEY_ONE);
  });

  it('accepts a valid 64-character hex secret key', () => {
    const { secretKey, pubkey } = parsePrivateKey(SECRET_THREE_HEX);
    expect(bytesToHex(secretKey)).toBe(SECRET_THREE_HEX);
    expect(pubkey).toBe(PUBKEY_THREE);
  });

  it('derives the same pubkey from nsec and hex forms of a key', () => {
    const nsec = nsecEncode(hexToBytes(SECRET_THREE_HEX));
    expect(parsePrivateKey(nsec).pubkey).toBe(PUBKEY_THREE);
    expect(parsePrivateKey(SECRET_THREE_HEX).pubkey).toBe(PUBKEY_THREE);
  });

  it('accepts uppercase hex and returns a lowercase pubkey', () => {
    const { pubkey } = parsePrivateKey(SECRET_THREE_HEX.toUpperCase());
    expect(pubkey).toBe(PUBKEY_THREE);
    expect(pubkey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('ignores surrounding whitespace', () => {
    expect(parsePrivateKey(`  ${SECRET_ONE_NSEC}\n`).pubkey).toBe(PUBKEY_ONE);
    expect(parsePrivateKey(`\t${SECRET_ONE_HEX} `).pubkey).toBe(PUBKEY_ONE);
  });

  it('accepts the largest valid secp256k1 scalar', () => {
    expect(parsePrivateKey(CURVE_ORDER_MINUS_ONE_HEX).pubkey).toBe(PUBKEY_ONE);
  });

  it('rejects invalid nsec values', () => {
    const lastChar = SECRET_ONE_NSEC.at(-1) === 'q' ? 'p' : 'q';
    expectRejected(`${SECRET_ONE_NSEC.slice(0, -1)}${lastChar}`);
    expectRejected(SECRET_ONE_NSEC.slice(0, -1));
    expectRejected(
      `${SECRET_ONE_NSEC.slice(0, 10)}B${SECRET_ONE_NSEC.slice(11)}`,
    );
    expectRejected('nsec1invalid');
    expectRejected('nsec1');
    expectRejected(`nostr:${SECRET_ONE_NSEC}`);
  });

  it('rejects NIP-19 entities other than nsec', () => {
    expectRejected(npubEncode(PUBKEY_ONE));
    expectRejected(noteEncode(PUBKEY_ONE));
    expectRejected(nprofileEncode({ pubkey: PUBKEY_ONE }));
    expectRejected(neventEncode({ id: PUBKEY_ONE }));
    expectRejected(encodeBytes('nseckey', hexToBytes(SECRET_ONE_HEX)));
  });

  it('rejects malformed hex', () => {
    expectRejected(`${'00'.repeat(31)}0g`);
    expectRejected(`0x${'00'.repeat(31)}01`);
    expectRejected(`${'00'.repeat(15)} ${'00'.repeat(15)}01`);
    expectRejected('not a key');
  });

  it('rejects secret keys that are not 32 bytes', () => {
    expectRejected('');
    expectRejected('   ');
    expectRejected('01'.repeat(31));
    expectRejected('01'.repeat(33));
    expectRejected('0'.repeat(63));
    expectRejected(encodeBytes('nsec', new Uint8Array(31).fill(1)));
    expectRejected(encodeBytes('nsec', new Uint8Array(33).fill(1)));
  });

  it('rejects values that are not valid secp256k1 secret keys', () => {
    expectRejected('00'.repeat(32));
    expectRejected(CURVE_ORDER_HEX);
    expectRejected('ff'.repeat(32));
    expectRejected(nsecEncode(new Uint8Array(32)));
    expectRejected(nsecEncode(hexToBytes(CURVE_ORDER_HEX)));
  });

  it('rejects oversized input before decoding it', () => {
    expectRejected('a'.repeat(MAX_PRIVATE_KEY_INPUT_LENGTH + 1));
    expectRejected(`nsec1${'q'.repeat(4000)}`);
  });

  it('rejects non-string input', () => {
    expectRejected(undefined);
    expectRejected(null);
    expectRejected(1);
    expectRejected(hexToBytes(SECRET_ONE_HEX));
    expectRejected({ privateKey: SECRET_ONE_HEX });
  });
});
