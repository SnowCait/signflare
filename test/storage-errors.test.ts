import { bytesToHex } from 'nostr-tools/utils';
import { describe, expect, it } from 'vitest';
import { registerIdentity } from '../src/identities';
import {
  isStorageFullError,
  StorageFullError,
  withStorageFullDetection,
} from '../src/storage-errors';

// Cloudflare's documented error for writes to a full SQLite-backed Durable Object.
const SQLITE_FULL_MESSAGE = 'database or disk is full: SQLITE_FULL';

// Test-only fixture: a trivially guessable scalar that must never hold funds or identity.
const SECRET_ONE_HEX = `${'00'.repeat(31)}01`;
const SECRET_ONE_NSEC =
  'nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsmhltgl';

// Reads succeed and every write fails, as on a Durable Object at its storage limit.
function fullStorage(writes: unknown[][]): SqlStorage {
  return {
    exec(query: string, ...bindings: unknown[]) {
      if (/^\s*SELECT\b/i.test(query)) {
        return { toArray: () => [] };
      }
      writes.push(bindings);
      throw new Error(SQLITE_FULL_MESSAGE);
    },
  } as unknown as SqlStorage;
}

describe('isStorageFullError', () => {
  it('detects the documented SQLITE_FULL error', () => {
    expect(isStorageFullError(new Error(SQLITE_FULL_MESSAGE))).toBe(true);
  });

  it('ignores other errors and non-error values', () => {
    expect(
      isStorageFullError(
        new Error(
          'UNIQUE constraint failed: identities.pubkey: SQLITE_CONSTRAINT',
        ),
      ),
    ).toBe(false);
    expect(isStorageFullError(new Error('database is locked'))).toBe(false);
    expect(isStorageFullError(SQLITE_FULL_MESSAGE)).toBe(false);
    expect(isStorageFullError(undefined)).toBe(false);
  });
});

describe('withStorageFullDetection', () => {
  it('returns the result of a successful write', () => {
    expect(withStorageFullDetection(() => 42)).toBe(42);
  });

  it('converts SQLITE_FULL into a safe StorageFullError', () => {
    let caught: unknown;
    try {
      withStorageFullDetection(() => {
        throw new Error(SQLITE_FULL_MESSAGE);
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(StorageFullError);
    expect((caught as Error).message).toBe('Durable Object storage is full');
    expect((caught as Error).cause).toBeUndefined();
  });

  it('rethrows other errors unchanged', () => {
    const original = new Error('database is locked');
    expect(() =>
      withStorageFullDetection(() => {
        throw original;
      }),
    ).toThrow(original);
  });
});

describe('registerIdentity on full storage', () => {
  it('fails with StorageFullError that carries no secret material', async () => {
    for (const input of [SECRET_ONE_NSEC, SECRET_ONE_HEX]) {
      const writes: unknown[][] = [];
      const masterKey = crypto.getRandomValues(new Uint8Array(32));

      let caught: unknown;
      try {
        await registerIdentity(fullStorage(writes), masterKey, input);
      } catch (error) {
        caught = error;
      }

      expect(caught).toBeInstanceOf(StorageFullError);
      expect(writes).toHaveLength(1);
      const error = caught as StorageFullError;
      expect(error.cause).toBeUndefined();
      const text = `${String(error)} ${error.stack ?? ''} ${JSON.stringify(error)}`;
      expect(text).not.toContain(SECRET_ONE_HEX);
      expect(text).not.toContain(SECRET_ONE_NSEC);
      for (const binding of writes[0]) {
        if (binding instanceof Uint8Array) {
          expect(text).not.toContain(bytesToHex(binding));
          expect(text).not.toContain(btoa(String.fromCharCode(...binding)));
        }
      }
    }
  });
});
