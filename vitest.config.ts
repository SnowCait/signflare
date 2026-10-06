import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          // A test-only value, so that the Worker's own env never takes
          // ADMIN_PUBKEY from a local .dev.vars: the public key of the
          // private key 1.
          ADMIN_PUBKEY:
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        },
      },
    }),
  ],
});
