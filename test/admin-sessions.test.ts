import { env } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { bytesToHex, hexToBytes } from 'nostr-tools/utils';
import { describe, expect, it } from 'vitest';
import {
  ADMIN_SESSION_LIFETIME_SECONDS,
  type AdminLogin,
  authenticateAdminSession,
  createAdminSession,
  deleteAdminSession,
  generateAdminSessionToken,
  hashAdminSessionToken,
  isAdminSessionToken,
} from '../src/admin-sessions';
import { StorageFullError } from '../src/storage-errors';

const NOW = 1_700_000_000;
const ADMIN = 'ab'.repeat(32);
const PREVIOUS_ADMIN = 'cd'.repeat(32);
const SQLITE_FULL_MESSAGE = 'database or disk is full: SQLITE_FULL';

function freshHub() {
  return env.SIGNER_HUB.getByName(crypto.randomUUID());
}

function randomTokenHash(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function randomEventId(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

function login(overrides: Partial<AdminLogin> = {}): AdminLogin {
  return {
    eventId: randomEventId(),
    eventExpiresAt: NOW + 60,
    tokenHash: randomTokenHash(),
    adminPubkey: ADMIN,
    now: NOW,
    ...overrides,
  };
}

function sessionRows(sql: SqlStorage) {
  return sql
    .exec<{
      token_hash: ArrayBuffer;
      admin_pubkey: string;
      expires_at: number;
      created_at: number;
    }>('SELECT * FROM admin_sessions ORDER BY created_at, token_hash')
    .toArray()
    .map((row) => ({
      ...row,
      token_hash: bytesToHex(new Uint8Array(row.token_hash)),
    }));
}

function eventRows(sql: SqlStorage) {
  return sql
    .exec<{
      event_id: string;
      expires_at: number;
    }>('SELECT * FROM admin_auth_events ORDER BY event_id')
    .toArray();
}

// Delegates to the real storage, but makes the admin session insert fail.
function failingSessionInsert(
  storage: DurableObjectStorage,
  message: string,
): DurableObjectStorage {
  const sql = {
    exec(query: string, ...bindings: SqlStorageValue[]) {
      if (query.includes('INSERT INTO admin_sessions')) {
        throw new Error(message);
      }
      return storage.sql.exec(query, ...bindings);
    },
  } as SqlStorage;
  return {
    sql,
    transactionSync: <T>(closure: () => T) => storage.transactionSync(closure),
  } as unknown as DurableObjectStorage;
}

describe('admin session tokens', () => {
  it('are 32 random bytes encoded as lowercase hex', () => {
    const tokens = new Set(
      Array.from({ length: 16 }, () => generateAdminSessionToken()),
    );
    expect(tokens.size).toBe(16);
    for (const token of tokens) {
      expect(token).toMatch(/^[0-9a-f]{64}$/);
      expect(isAdminSessionToken(token)).toBe(true);
    }
  });

  it('are hashed with SHA-256 over the raw token bytes', async () => {
    const token = generateAdminSessionToken();
    const hash = await hashAdminSessionToken(token);
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.byteLength).toBe(32);
    expect(hash).toEqual(
      new Uint8Array(await crypto.subtle.digest('SHA-256', hexToBytes(token))),
    );
    expect(bytesToHex(hash)).not.toContain(token);
  });

  it.each([
    ['an empty string', ''],
    ['uppercase hex', 'AB'.repeat(32)],
    ['a short value', 'ab'.repeat(31)],
    ['a long value', 'ab'.repeat(33)],
    ['non-hex characters', 'zz'.repeat(32)],
  ])('rejects %s', async (_case, value) => {
    expect(isAdminSessionToken(value)).toBe(false);
    await expect(hashAdminSessionToken(value)).rejects.toThrow(
      'Malformed admin session token',
    );
  });
});

describe('createAdminSession', () => {
  it('consumes the event and issues a 12-hour session', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const attempt = login();
      expect(createAdminSession(state.storage, attempt)).toEqual({
        status: 'created',
        session: {
          adminPubkey: ADMIN,
          createdAt: NOW,
          expiresAt: NOW + 12 * 60 * 60,
        },
      });
      expect(ADMIN_SESSION_LIFETIME_SECONDS).toBe(43_200);
      expect(sessionRows(state.storage.sql)).toEqual([
        {
          token_hash: bytesToHex(attempt.tokenHash),
          admin_pubkey: ADMIN,
          expires_at: NOW + 43_200,
          created_at: NOW,
        },
      ]);
      expect(eventRows(state.storage.sql)).toEqual([
        { event_id: attempt.eventId, expires_at: NOW + 60 },
      ]);
    });
  });

  it('rejects a consumed event without issuing a session', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const first = login();
      createAdminSession(state.storage, first);
      const before = sessionRows(state.storage.sql);

      for (const now of [NOW, NOW + 30, NOW + 59]) {
        expect(
          createAdminSession(state.storage, {
            ...first,
            tokenHash: randomTokenHash(),
            now,
          }),
        ).toEqual({ status: 'replayed' });
      }
      expect(sessionRows(state.storage.sql)).toEqual(before);
      expect(eventRows(state.storage.sql)).toHaveLength(1);
    });
  });

  it('accepts distinct events, each with its own session', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      expect(createAdminSession(state.storage, login()).status).toBe('created');
      expect(createAdminSession(state.storage, login()).status).toBe('created');
      expect(sessionRows(state.storage.sql)).toHaveLength(2);
      expect(eventRows(state.storage.sql)).toHaveLength(2);
    });
  });

  it('leaves neither row behind when issuing the session fails', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const existing = login();
      createAdminSession(state.storage, existing);

      // A colliding token hash makes the session insert violate its key.
      const attempt = login({ tokenHash: existing.tokenHash });
      expect(() => createAdminSession(state.storage, attempt)).toThrow(
        /UNIQUE constraint failed: admin_sessions\.token_hash/,
      );
      expect(eventRows(state.storage.sql)).toEqual([
        { event_id: existing.eventId, expires_at: NOW + 60 },
      ]);
      expect(sessionRows(state.storage.sql)).toHaveLength(1);

      // The event was not consumed, so it can still be used.
      expect(
        createAdminSession(state.storage, login({ eventId: attempt.eventId }))
          .status,
      ).toBe('created');
    });
  });

  it('reports full storage and rolls back the consumed event', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const storage = failingSessionInsert(state.storage, SQLITE_FULL_MESSAGE);
      expect(createAdminSession(storage, login())).toEqual({
        status: 'storage_full',
      });
      expect(eventRows(state.storage.sql)).toEqual([]);
      expect(sessionRows(state.storage.sql)).toEqual([]);
    });
  });

  it('rethrows other failures after rolling back', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const storage = failingSessionInsert(state.storage, 'unexpected');
      expect(() => createAdminSession(storage, login())).toThrow('unexpected');
      expect(() => createAdminSession(storage, login())).not.toThrow(
        StorageFullError,
      );
      expect(eventRows(state.storage.sql)).toEqual([]);
      expect(sessionRows(state.storage.sql)).toEqual([]);
    });
  });

  it('enforces event ID uniqueness in the schema as well', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const { sql } = state.storage;
      sql.exec(
        'INSERT INTO admin_auth_events (event_id, expires_at) VALUES (?, ?)',
        'e'.repeat(64),
        NOW + 60,
      );
      expect(() =>
        sql.exec(
          'INSERT INTO admin_auth_events (event_id, expires_at) VALUES (?, ?)',
          'e'.repeat(64),
          NOW + 120,
        ),
      ).toThrow(/UNIQUE constraint failed/);
    });
  });

  it('refuses an event that is already outside the authentication window', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      for (const eventExpiresAt of [NOW, NOW - 1]) {
        expect(() =>
          createAdminSession(state.storage, login({ eventExpiresAt })),
        ).toThrow(RangeError);
      }
      expect(eventRows(state.storage.sql)).toEqual([]);
      expect(sessionRows(state.storage.sql)).toEqual([]);
    });
  });

  it('forgets consumed events only once they can no longer authenticate', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const expired = login({
        eventId: '1'.repeat(64),
        now: NOW - 100,
        eventExpiresAt: NOW,
      });
      const lastSecond = login({
        eventId: '2'.repeat(64),
        now: NOW - 59,
        eventExpiresAt: NOW + 1,
      });
      createAdminSession(state.storage, expired);
      createAdminSession(state.storage, lastSecond);

      createAdminSession(state.storage, login({ eventId: '3'.repeat(64) }));
      expect(
        eventRows(state.storage.sql).map(({ event_id }) => event_id),
      ).toEqual(['2'.repeat(64), '3'.repeat(64)]);
      expect(
        createAdminSession(state.storage, {
          ...lastSecond,
          tokenHash: randomTokenHash(),
          now: NOW,
        }),
      ).toEqual({ status: 'replayed' });
    });
  });

  it('removes expired sessions and sessions of other administrators', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const { sql } = state.storage;
      const insert = (adminPubkey: string, createdAt: number) => {
        const tokenHash = randomTokenHash();
        sql.exec(
          'INSERT INTO admin_sessions VALUES (?, ?, ?, ?)',
          tokenHash,
          adminPubkey,
          createdAt + ADMIN_SESSION_LIFETIME_SECONDS,
          createdAt,
        );
        return bytesToHex(tokenHash);
      };
      insert(ADMIN, NOW - ADMIN_SESSION_LIFETIME_SECONDS);
      const lastSecond = insert(
        ADMIN,
        NOW - ADMIN_SESSION_LIFETIME_SECONDS + 1,
      );
      insert(PREVIOUS_ADMIN, NOW - 10);

      const current = login();
      createAdminSession(state.storage, current);

      expect(
        sessionRows(sql)
          .map(({ token_hash }) => token_hash)
          .sort(),
      ).toEqual([lastSecond, bytesToHex(current.tokenHash)].sort());
    });
  });
});

describe('authenticateAdminSession', () => {
  async function withSession(
    run: (sql: SqlStorage, tokenHash: Uint8Array) => void,
  ) {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const attempt = login();
      createAdminSession(state.storage, attempt);
      run(state.storage.sql, attempt.tokenHash);
    });
  }

  it('returns a valid session without changing it', async () => {
    await withSession((sql, tokenHash) => {
      const before = sessionRows(sql);
      for (const now of [NOW, NOW + 1, NOW + 6 * 60 * 60, NOW + 43_199]) {
        expect(authenticateAdminSession(sql, tokenHash, ADMIN, now)).toEqual({
          adminPubkey: ADMIN,
          createdAt: NOW,
          expiresAt: NOW + 43_200,
        });
      }
      expect(sessionRows(sql)).toEqual(before);
    });
  });

  it('rejects an unknown token hash', async () => {
    await withSession((sql) => {
      expect(
        authenticateAdminSession(sql, randomTokenHash(), ADMIN, NOW),
      ).toBeNull();
      expect(sessionRows(sql)).toHaveLength(1);
    });
  });

  it('rejects and removes an expired session', async () => {
    await withSession((sql, tokenHash) => {
      expect(
        authenticateAdminSession(sql, tokenHash, ADMIN, NOW + 43_200),
      ).toBeNull();
      expect(sessionRows(sql)).toEqual([]);
      expect(
        authenticateAdminSession(sql, tokenHash, ADMIN, NOW + 1),
      ).toBeNull();
    });
  });

  it('rejects and removes a session issued to another administrator', async () => {
    await withSession((sql, tokenHash) => {
      expect(
        authenticateAdminSession(sql, tokenHash, PREVIOUS_ADMIN, NOW + 1),
      ).toBeNull();
      expect(sessionRows(sql)).toEqual([]);
      // Changing ADMIN_PUBKEY back does not revive it.
      expect(
        authenticateAdminSession(sql, tokenHash, ADMIN, NOW + 2),
      ).toBeNull();
    });
  });
});

describe('deleteAdminSession', () => {
  it('deletes only the given session', async () => {
    await runInDurableObject(freshHub(), (_instance, state) => {
      const { sql } = state.storage;
      const first = login();
      const second = login();
      createAdminSession(state.storage, first);
      createAdminSession(state.storage, second);

      expect(deleteAdminSession(sql, first.tokenHash)).toBe(true);
      expect(deleteAdminSession(sql, first.tokenHash)).toBe(false);
      expect(
        authenticateAdminSession(sql, first.tokenHash, ADMIN, NOW),
      ).toBeNull();
      expect(
        authenticateAdminSession(sql, second.tokenHash, ADMIN, NOW),
      ).not.toBeNull();
    });
  });
});
