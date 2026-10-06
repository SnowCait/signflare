import { encodeBytes, npubEncode, nsecEncode } from 'nostr-tools/nip19';
import { getPublicKey } from 'nostr-tools/pure';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { InvalidPrivateKeyError } from '../src/private-key';
import {
  RemoteSignerConfigurationError,
  type RemoteSignerKey,
  remoteSignerPubkey,
  withRemoteSignerKey,
} from '../src/remote-signer';
import { randomKey } from './nostr-helpers';

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

const INVALID_CONFIGURATIONS: [string, unknown][] = [
  ['missing', undefined],
  ['null', null],
  ['empty', ''],
  ['whitespace', ' \n'],
  ['an nsec with a bad checksum', tamperNsec(SECRET_ONE_NSEC)],
  ['a truncated nsec', SECRET_ONE_NSEC.slice(0, -1)],
  ['an nsec with a prefix', `nostr:${SECRET_ONE_NSEC}`],
  ['an nsec of 31 bytes', encodeBytes('nsec', new Uint8Array(31).fill(1))],
  ['an npub', npubEncode(PUBKEY_ONE)],
  ['hex that is too short', SECRET_THREE_HEX.slice(1)],
  ['hex that is too long', `${SECRET_THREE_HEX}0`],
  ['hex with a non-hex digit', `${SECRET_THREE_HEX.slice(0, -1)}g`],
  ['hex with a 0x prefix', `0x${SECRET_THREE_HEX.slice(2)}`],
  ['the zero scalar', '00'.repeat(32)],
  ['the curve order', CURVE_ORDER_HEX],
  ['a scalar above the curve order', 'ff'.repeat(32)],
  ['an nsec of the zero scalar', nsecEncode(new Uint8Array(32))],
  ['an oversized value', 'a'.repeat(1000)],
  ['a number', 1],
  ['bytes', hexToBytes(SECRET_THREE_HEX)],
];

function tamperNsec(nsec: string): string {
  return `${nsec.slice(0, -1)}${nsec.endsWith('q') ? 'p' : 'q'}`;
}

// The configuration error is fixed: it never carries the configured value.
function expectConfigurationError(run: () => unknown, value: unknown): void {
  let caught: unknown;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(RemoteSignerConfigurationError);
  expect(caught).not.toBeInstanceOf(InvalidPrivateKeyError);
  const error = caught as RemoteSignerConfigurationError;
  expect(error.name).toBe('RemoteSignerConfigurationError');
  expect(error.message).toBe('Invalid REMOTE_SIGNER_PRIVATE_KEY');
  expect(error.cause).toBeUndefined();
  if (typeof value === 'string' && value.trim() !== '') {
    for (const text of [
      String(error),
      JSON.stringify(error),
      `${error.stack}`,
    ]) {
      expect(text).not.toContain(value.trim());
    }
  }
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('remoteSignerPubkey', () => {
  it('derives the pubkey from an nsec', () => {
    expect(remoteSignerPubkey(SECRET_ONE_NSEC)).toBe(PUBKEY_ONE);
  });

  it('derives the pubkey from a 64-character hex private key', () => {
    expect(remoteSignerPubkey(SECRET_THREE_HEX)).toBe(PUBKEY_THREE);
  });

  it.each<[string, string]>([
    ['lowercase hex', SECRET_THREE_HEX],
    ['uppercase hex', SECRET_THREE_HEX.toUpperCase()],
    ['an nsec', nsecEncode(hexToBytes(SECRET_THREE_HEX))],
    [
      'an nsec surrounded by whitespace',
      ` ${nsecEncode(hexToBytes(SECRET_THREE_HEX))}\n`,
    ],
    ['hex surrounded by whitespace', `\t${SECRET_THREE_HEX} `],
  ])('accepts %s, as identity registration does', (_case, value) => {
    expect(remoteSignerPubkey(value)).toBe(PUBKEY_THREE);
  });

  it('agrees with nostr-tools on random keys', () => {
    for (let i = 0; i < 8; i++) {
      const key = randomKey();
      expect(key.pubkey).toBe(getPublicKey(key.secretKey));
      expect(remoteSignerPubkey(bytesToHex(key.secretKey))).toBe(key.pubkey);
      expect(remoteSignerPubkey(nsecEncode(key.secretKey))).toBe(key.pubkey);
    }
  });

  it('returns a lowercase 64-character hex pubkey', () => {
    expect(remoteSignerPubkey(SECRET_THREE_HEX.toUpperCase())).toMatch(
      /^[0-9a-f]{64}$/,
    );
  });

  it.each(INVALID_CONFIGURATIONS)(
    'reports a configuration error for %s without including it',
    (_case, value) => {
      expectConfigurationError(() => remoteSignerPubkey(value), value);
    },
  );

  it('logs nothing', () => {
    const logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map(
      (method) => vi.spyOn(console, method).mockImplementation(() => {}),
    );
    remoteSignerPubkey(SECRET_ONE_NSEC);
    for (const [, value] of INVALID_CONFIGURATIONS) {
      expect(() => remoteSignerPubkey(value)).toThrow(
        RemoteSignerConfigurationError,
      );
    }
    for (const log of logs) {
      expect(log).not.toHaveBeenCalled();
    }
  });
});

describe('withRemoteSignerKey', () => {
  it('passes the parsed key to the callback and returns its result', () => {
    const result = withRemoteSignerKey(SECRET_ONE_NSEC, (key) => ({
      secretKey: bytesToHex(key.secretKey),
      pubkey: key.pubkey,
    }));
    expect(result).toEqual({ secretKey: SECRET_ONE_HEX, pubkey: PUBKEY_ONE });
  });

  it.each<[string, string, string]>([
    ['an nsec', SECRET_ONE_NSEC, SECRET_ONE_HEX],
    ['hex', SECRET_THREE_HEX, SECRET_THREE_HEX],
  ])(
    'overwrites the key bytes decoded from %s once the callback returns',
    (_case, value, hex) => {
      let secretKey: Uint8Array | undefined;
      withRemoteSignerKey(value, (key) => {
        secretKey = key.secretKey;
        expect(bytesToHex(key.secretKey)).toBe(hex);
      });
      expect(secretKey).toEqual(new Uint8Array(32));
    },
  );

  it('overwrites the key bytes when the callback throws', () => {
    const failure = new Error('callback failed');
    let secretKey: Uint8Array | undefined;
    let caught: unknown;
    try {
      withRemoteSignerKey(SECRET_THREE_HEX, (key) => {
        secretKey = key.secretKey;
        throw failure;
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBe(failure);
    expect(secretKey).toEqual(new Uint8Array(32));
  });

  it('takes synchronous callbacks only', () => {
    // The key would be overwritten while an asynchronous callback still ran,
    // so such callbacks do not type-check.
    const asynchronous = async ({ secretKey }: RemoteSignerKey) => secretKey;
    const promising = ({ pubkey }: RemoteSignerKey) => Promise.resolve(pubkey);
    const calls = [
      // @ts-expect-error The callback returns a promise.
      () => withRemoteSignerKey(SECRET_ONE_NSEC, asynchronous),
      // @ts-expect-error The callback returns a promise.
      () => withRemoteSignerKey(SECRET_ONE_NSEC, promising),
    ];
    expect(calls).toHaveLength(2);
    const pubkey: string = withRemoteSignerKey(
      SECRET_ONE_NSEC,
      (key) => key.pubkey,
    );
    expect(pubkey).toBe(PUBKEY_ONE);
  });

  it('decodes the configured value afresh on every call', () => {
    const seen: string[] = [];
    for (let i = 0; i < 3; i++) {
      withRemoteSignerKey(SECRET_ONE_NSEC, ({ secretKey }) => {
        seen.push(bytesToHex(secretKey));
      });
    }
    expect(seen).toEqual([SECRET_ONE_HEX, SECRET_ONE_HEX, SECRET_ONE_HEX]);
  });

  it.each(INVALID_CONFIGURATIONS)(
    'does not call the callback when the configuration is %s',
    (_case, value) => {
      const use = vi.fn();
      expectConfigurationError(() => withRemoteSignerKey(value, use), value);
      expect(use).not.toHaveBeenCalled();
    },
  );
});
