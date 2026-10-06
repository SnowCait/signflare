import { env, exports } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { SignerHub } from '../src/index';

// The Worker as the test pool configures it from wrangler.jsonc, with the
// test-only ADMIN_PUBKEY of vitest.config.ts.
describe('worker', () => {
  it('responds to a request', async () => {
    const response = await exports.default.fetch('https://example.com/');
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toMatch(/^text\/html/);
  });

  it('serves the NIP-11 document with the configured ADMIN_PUBKEY', async () => {
    const response = await exports.default.fetch('https://example.com/', {
      headers: { Accept: 'application/nostr+json' },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      pubkey: env.ADMIN_PUBKEY,
    });
  });
});

describe('SignerHub', () => {
  it('is bound as a SQLite-backed Durable Object', async () => {
    const stub = env.SIGNER_HUB.getByName('signer');
    await runInDurableObject(stub, (instance, state) => {
      expect(instance).toBeInstanceOf(SignerHub);
      expect(state.storage.sql.databaseSize).toBeGreaterThan(0);
    });
  });
});
