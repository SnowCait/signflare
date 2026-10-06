import { runInDurableObject } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AdminStatus } from '../src/admin-status';
import { PAIRING_LIFETIME_SECONDS } from '../src/pairings';
import type { SignerHub } from '../src/signer-hub';
import {
  addIdentity,
  freshHub,
  instrumentHubSql,
  replaceHubEnv,
} from './hub-helpers';
import { randomKey } from './nostr-helpers';

type Hub = DurableObjectStub<SignerHub>;

const NOW = 1_700_000_000;

// Every statement except a SELECT.
const ANY_WRITE = /^\s*(?!SELECT\b)\S/i;

async function pair(hub: Hub, identity: string, now = NOW): Promise<string> {
  const result = await hub.createPairing(identity, 'all', now);
  if (result.status !== 'created') {
    throw new Error(`pairing not created: ${result.status}`);
  }
  return result.secret;
}

async function connect(hub: Hub, identity: string, now = NOW): Promise<string> {
  const clientPubkey = randomKey().pubkey;
  const result = await hub.establishSession({
    secret: await pair(hub, identity, now),
    clientPubkey,
    now,
  });
  if (result.status !== 'created') {
    throw new Error(`session not established: ${result.status}`);
  }
  return clientPubkey;
}

// A pairing whose expires_at is exactly `expiresAt`.
function pairExpiringAt(
  hub: Hub,
  identity: string,
  expiresAt: number,
): Promise<string> {
  return pair(hub, identity, expiresAt - PAIRING_LIFETIME_SECONDS);
}

function counts(status: AdminStatus) {
  return {
    identities: status.identities,
    sessions: status.sessions,
    pairings: status.pairings,
  };
}

function pairingExpirations(hub: Hub): Promise<number[]> {
  return runInDurableObject(hub, (_instance, state) =>
    state.storage.sql
      .exec<{
        expires_at: number;
      }>('SELECT expires_at FROM pairings ORDER BY expires_at')
      .toArray()
      .map(({ expires_at }) => expires_at),
  );
}

// The status and the database size the SignerHub reports at the same moment.
function statusWithDatabaseSize(
  hub: Hub,
  now = NOW,
): Promise<{ status: AdminStatus; databaseSize: number }> {
  return runInDurableObject(hub, (instance, state) => ({
    status: (instance as SignerHub).getAdminStatus(now),
    databaseSize: state.storage.sql.databaseSize,
  }));
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('SignerHub.getAdminStatus', () => {
  it('reports zero counts for a fresh deployment', async () => {
    const status = await freshHub().getAdminStatus(NOW);
    expect(Object.keys(status).sort()).toEqual([
      'databaseSize',
      'identities',
      'pairings',
      'sessions',
    ]);
    expect(counts(status)).toEqual({ identities: 0, sessions: 0, pairings: 0 });
    expect(typeof status.databaseSize).toBe('number');
    expect(Number.isFinite(status.databaseSize)).toBe(true);
    expect(status.databaseSize).toBeGreaterThanOrEqual(0);
  });

  it('counts registered identities', async () => {
    const hub = freshHub();
    await addIdentity(hub);
    expect(counts(await hub.getAdminStatus(NOW))).toEqual({
      identities: 1,
      sessions: 0,
      pairings: 0,
    });
    await addIdentity(hub);
    expect((await hub.getAdminStatus(NOW)).identities).toBe(2);
  });

  it('counts created pairings', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    await pair(hub, identity);
    expect(counts(await hub.getAdminStatus(NOW))).toEqual({
      identities: 1,
      sessions: 0,
      pairings: 1,
    });
    await pair(hub, identity);
    expect((await hub.getAdminStatus(NOW)).pairings).toBe(2);
  });

  it('moves a consumed pairing to the session count', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const secret = await pair(hub, identity);
    await pair(hub, identity);
    expect(counts(await hub.getAdminStatus(NOW))).toEqual({
      identities: 1,
      sessions: 0,
      pairings: 2,
    });

    const result = await hub.establishSession({
      secret,
      clientPubkey: randomKey().pubkey,
      now: NOW,
    });
    expect(result.status).toBe('created');
    expect(counts(await hub.getAdminStatus(NOW))).toEqual({
      identities: 1,
      sessions: 1,
      pairings: 1,
    });
  });

  it('stops counting a revoked session', async () => {
    const hub = freshHub();
    const identity = await addIdentity(hub);
    const [revoked] = [
      await connect(hub, identity),
      await connect(hub, identity),
    ];
    expect((await hub.getAdminStatus(NOW)).sessions).toBe(2);

    expect(await hub.revokeSession(revoked)).toBe(true);
    expect(counts(await hub.getAdminStatus(NOW))).toEqual({
      identities: 1,
      sessions: 1,
      pairings: 0,
    });
  });

  it('reflects the sessions and pairings removed with a deleted identity', async () => {
    const hub = freshHub();
    const deleted = await addIdentity(hub);
    const kept = await addIdentity(hub);
    await connect(hub, deleted);
    await connect(hub, deleted);
    await pair(hub, deleted);
    await connect(hub, kept);
    await pair(hub, kept);
    expect(counts(await hub.getAdminStatus(NOW))).toEqual({
      identities: 2,
      sessions: 3,
      pairings: 2,
    });

    expect(await hub.deleteIdentity(deleted)).toBe(true);
    expect(counts(await hub.getAdminStatus(NOW))).toEqual({
      identities: 1,
      sessions: 1,
      pairings: 1,
    });
  });

  it('aggregates across identities', async () => {
    const hub = freshHub();
    const identities = [
      await addIdentity(hub),
      await addIdentity(hub),
      await addIdentity(hub),
    ];
    for (const [index, identity] of identities.entries()) {
      for (let i = 0; i <= index; i++) {
        await connect(hub, identity);
        await pair(hub, identity);
      }
    }
    await pair(hub, identities[0]);
    expect(counts(await hub.getAdminStatus(NOW))).toEqual({
      identities: 3,
      sessions: 6,
      pairings: 7,
    });
  });

  describe('pairing expiration', () => {
    it('counts only pairings that expire after now', async () => {
      const hub = freshHub();
      const identity = await addIdentity(hub);
      await pairExpiringAt(hub, identity, 999);
      await pairExpiringAt(hub, identity, 1000);
      await pairExpiringAt(hub, identity, 1001);
      expect(await pairingExpirations(hub)).toEqual([999, 1000, 1001]);

      expect((await hub.getAdminStatus(1000)).pairings).toBe(1);
      expect((await hub.getAdminStatus(998)).pairings).toBe(3);
      expect((await hub.getAdminStatus(999)).pairings).toBe(2);
      expect((await hub.getAdminStatus(1001)).pairings).toBe(0);
    });

    it.each<[string, number, number]>([
      ['before now', NOW - 1, 0],
      ['exactly at now', NOW, 0],
      ['after now', NOW + 1, 1],
    ])(
      'treats a pairing that expires %s like session establishment does',
      async (_case, expiresAt, counted) => {
        const hub = freshHub();
        const identity = await addIdentity(hub);
        const secret = await pairExpiringAt(hub, identity, expiresAt);

        expect((await hub.getAdminStatus(NOW)).pairings).toBe(counted);
        const result = await hub.establishSession({
          secret,
          clientPubkey: randomKey().pubkey,
          now: NOW,
        });
        expect(result.status).toBe(counted ? 'created' : 'pairing_expired');
      },
    );

    it('leaves expired pairings in place', async () => {
      const hub = freshHub();
      const identity = await addIdentity(hub);
      await pairExpiringAt(hub, identity, NOW - 1);
      await pairExpiringAt(hub, identity, NOW);
      await pairExpiringAt(hub, identity, NOW + 1);
      await pairExpiringAt(hub, identity, NOW + 2);
      const statements: string[] = [];
      await instrumentHubSql(hub, { statements });

      expect((await hub.getAdminStatus(NOW)).pairings).toBe(2);
      expect((await hub.getAdminStatus(NOW + 10)).pairings).toBe(0);
      expect(statements).toHaveLength(2);
      vi.restoreAllMocks();
      expect(await pairingExpirations(hub)).toEqual([
        NOW - 1,
        NOW,
        NOW + 1,
        NOW + 2,
      ]);
    });
  });

  describe('databaseSize', () => {
    it('is the SQLite database size of the Durable Object', async () => {
      const hub = freshHub();
      const empty = await statusWithDatabaseSize(hub);
      expect(empty.status.databaseSize).toBe(empty.databaseSize);

      const identity = await addIdentity(hub);
      await connect(hub, identity);
      await pair(hub, identity);
      const filled = await statusWithDatabaseSize(hub);
      expect(filled.status.databaseSize).toBe(filled.databaseSize);
      expect(Number.isFinite(filled.status.databaseSize)).toBe(true);
      expect(filled.status.databaseSize).toBeGreaterThanOrEqual(0);
    });

    it('is returned over RPC as a number of bytes', async () => {
      const hub = freshHub();
      await addIdentity(hub);
      const status = await hub.getAdminStatus(NOW);
      expect(typeof status.databaseSize).toBe('number');
      expect(Number.isInteger(status.databaseSize)).toBe(true);
      expect(status.databaseSize).toBe(
        (await statusWithDatabaseSize(hub)).databaseSize,
      );
    });
  });

  describe('read-only behavior', () => {
    it('runs a single aggregate SELECT that reads no secret columns', async () => {
      const hub = freshHub();
      const identity = await addIdentity(hub);
      await connect(hub, identity);
      await pair(hub, identity);
      const statements: string[] = [];
      await instrumentHubSql(hub, { statements });

      await hub.getAdminStatus(NOW);
      expect(statements).toHaveLength(1);
      const [statement] = statements;
      expect(statement).toMatch(/^SELECT /);
      expect(statement.match(/COUNT\(\*\)/g)).toHaveLength(3);
      expect(statement).not.toMatch(
        /\b(encrypted_private_key|iv|kdf_salt|key_version|secret_hash|permissions|pubkey|identity_pubkey|client_pubkey|client_name|client_url|client_image|token_hash|admin_pubkey)\b/,
      );
      expect(statement).not.toMatch(/\b(INSERT|UPDATE|DELETE|REPLACE)\b/);
      expect(statement).not.toMatch(
        /\b(admin_sessions|admin_auth_events|_sql_schema_migrations)\b/,
      );
    });

    it('works when every statement other than SELECT fails with SQLITE_FULL', async () => {
      const hub = freshHub();
      const identity = await addIdentity(hub);
      await connect(hub, identity);
      await pair(hub, identity);
      await pairExpiringAt(hub, identity, NOW);
      await instrumentHubSql(hub, {
        failing: ANY_WRITE,
        message: 'database or disk is full: SQLITE_FULL',
      });

      expect(counts(await hub.getAdminStatus(NOW))).toEqual({
        identities: 1,
        sessions: 1,
        pairings: 1,
      });
      vi.restoreAllMocks();
      expect(await pairingExpirations(hub)).toHaveLength(2);
    });

    it('reads no binding, so needs neither MASTER_ENCRYPTION_KEY nor REMOTE_SIGNER_PRIVATE_KEY', async () => {
      const hub = freshHub();
      const identity = await addIdentity(hub);
      await connect(hub, identity);
      const reads: PropertyKey[] = [];
      await replaceHubEnv(
        hub,
        () =>
          new Proxy(
            {},
            {
              get(_object, key) {
                reads.push(key);
                return undefined;
              },
              has(_object, key) {
                reads.push(key);
                return false;
              },
            },
          ),
      );

      expect(counts(await hub.getAdminStatus(NOW))).toEqual({
        identities: 1,
        sessions: 1,
        pairings: 0,
      });
      expect(reads).toEqual([]);
    });
  });
});
