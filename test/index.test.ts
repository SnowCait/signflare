import { env, exports } from 'cloudflare:workers';
import { runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { SignerHub } from '../src/index';

describe('worker', () => {
  it('responds to a request', async () => {
    const response = await exports.default.fetch('https://example.com/');
    expect(response.status).toBe(200);
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
