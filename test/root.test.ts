import { env } from 'cloudflare:workers';
import { npubEncode, nsecEncode } from 'nostr-tools/nip19';
import { bytesToHex } from 'nostr-tools/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import app from '../src/index';
import { DEPLOY_TO_CLOUDFLARE_URL, landingPage } from '../src/landing-page';
import {
  acceptsRelayInformation,
  SOFTWARE_URL,
} from '../src/relay-information';
import {
  recordingReads,
  TEST_MASTER_ENCRYPTION_KEY,
  withoutBinding,
} from './hub-helpers';
import { ORIGIN, randomKey } from './nostr-helpers';

// The public root (docs/design.md §37): the NIP-46 relay for WebSocket
// upgrades, the NIP-11 document, and the landing page.

const NIP11 = { Accept: 'application/nostr+json' };
const NAVIGATION = {
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Dest': 'document',
  Accept:
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
};
const CONFIGURATION_ERROR =
  'ADMIN_PUBKEY must be set to a lowercase 64-character hex public key';
const BINDINGS = [
  'ADMIN_PUBKEY',
  'ASSETS',
  'MASTER_ENCRYPTION_KEY',
  'REMOTE_SIGNER_PRIVATE_KEY',
  'SIGNER_HUB',
];

const admin = randomKey();
// Test-only REMOTE_SIGNER_PRIVATE_KEY, generated for this run.
const remoteSigner = randomKey();

interface Deployment {
  readonly env: Env;
  // Names used to reach the SignerHub.
  readonly hubNames: string[];
  // Requests made through the ASSETS binding.
  readonly assetRequests: string[];
  // Bindings read from the env, in order.
  readonly reads: string[];
}

// A deployment with every value configured, whose SignerHub and assets
// record their use.
function deployment(overrides: Partial<Env> = {}): Deployment {
  const hubNames: string[] = [];
  const assetRequests: string[] = [];
  const reads: string[] = [];
  const workerEnv: Env = {
    ...env,
    ADMIN_PUBKEY: admin.pubkey,
    MASTER_ENCRYPTION_KEY: TEST_MASTER_ENCRYPTION_KEY,
    REMOTE_SIGNER_PRIVATE_KEY: nsecEncode(remoteSigner.secretKey),
    SIGNER_HUB: {
      getByName(name: string) {
        hubNames.push(name);
        return env.SIGNER_HUB.getByName(crypto.randomUUID());
      },
    } as unknown as Env['SIGNER_HUB'],
    ASSETS: {
      async fetch(input: RequestInfo | URL) {
        assetRequests.push(new Request(input).url);
        return new Response('asset');
      },
    } as unknown as Env['ASSETS'],
    ...overrides,
  };
  return {
    env: recordingReads(workerEnv, BINDINGS, reads),
    hubNames,
    assetRequests,
    reads,
  };
}

async function send(
  d: Deployment | Env,
  init: RequestInit = {},
  url = `${ORIGIN}/`,
): Promise<Response> {
  return app.fetch(new Request(url, init), 'env' in d ? d.env : d);
}

// Every way the remote-signer pubkey and the secrets could appear in text.
function secretMaterial(): string[] {
  return [
    remoteSigner.pubkey,
    npubEncode(remoteSigner.pubkey),
    bytesToHex(remoteSigner.secretKey),
    nsecEncode(remoteSigner.secretKey),
    TEST_MASTER_ENCRYPTION_KEY,
  ];
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('root routing', () => {
  it('connects a WebSocket upgrade to the relay', async () => {
    const d = deployment();
    const response = await send(d, { headers: { Upgrade: 'websocket' } });
    expect(response.status).toBe(101);
    expect(response.webSocket).not.toBeNull();
    expect(d.hubNames).toEqual(['signer']);
    response.webSocket?.accept();
    response.webSocket?.close(1000);
  });

  it('prefers the WebSocket upgrade to the NIP-11 document', async () => {
    const d = deployment();
    const response = await send(d, {
      headers: { Upgrade: 'websocket', ...NIP11 },
    });
    expect(response.status).toBe(101);
    expect(response.webSocket).not.toBeNull();
    expect(response.headers.get('Content-Type')).toBeNull();
    expect(d.hubNames).toEqual(['signer']);
    response.webSocket?.accept();
    response.webSocket?.close(1000);
  });

  it('serves the NIP-11 document to Accept: application/nostr+json', async () => {
    const d = deployment();
    const response = await send(d, { headers: NIP11 });
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toBe('application/nostr+json');
    expect(d.hubNames).toEqual([]);
  });

  it.each<[string, Record<string, string>]>([
    ['a browser navigation', NAVIGATION],
    ['no Accept header', {}],
    ['Accept: */*', { Accept: '*/*' }],
    ['Accept: application/json', { Accept: 'application/json' }],
  ])('serves the landing page to %s', async (_case, headers) => {
    const d = deployment();
    const response = await send(d, { headers });
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toMatch(/^text\/html/);
    expect(await response.text()).toContain('<h1>Signflare</h1>');
    expect(d.hubNames).toEqual([]);
  });

  it.each([NIP11, NAVIGATION])(
    'marks the response as varying by Accept: %j',
    async (headers) => {
      const response = await send(deployment(), { headers });
      expect(response.headers.get('Vary')).toBe('Accept');
    },
  );

  it.each([NIP11, NAVIGATION])(
    'answers HEAD like GET, without a body: %j',
    async (headers) => {
      const get = await send(deployment(), { headers });
      const head = await send(deployment(), { method: 'HEAD', headers });
      expect(head.status).toBe(200);
      expect(head.headers.get('Content-Type')).toBe(
        get.headers.get('Content-Type'),
      );
      expect(await head.text()).toBe('');
    },
  );

  it('does not upgrade a HEAD request', async () => {
    const d = deployment();
    const response = await send(d, {
      method: 'HEAD',
      headers: { Upgrade: 'websocket' },
    });
    expect(response.status).toBe(200);
    expect(response.webSocket).toBeNull();
    expect(d.hubNames).toEqual([]);
  });
});

describe('acceptsRelayInformation', () => {
  it.each([
    'application/nostr+json',
    'Application/Nostr+JSON',
    ' application/nostr+json ',
    'application/nostr+json; charset=utf-8',
    'application/nostr+json;q=0.5',
    'text/html, application/nostr+json',
    'application/nostr+json, application/json;q=0.9',
  ])('accepts %j', (accept) => {
    expect(acceptsRelayInformation(accept)).toBe(true);
  });

  it.each([
    undefined,
    '',
    '*/*',
    'application/*',
    'application/json',
    'application/nostr+jsonl',
    NAVIGATION.Accept,
    'application/nostr+json;q=0',
    'application/nostr+json; Q=0.000',
    'text/html, application/nostr+json;q=0',
  ])('does not accept %j', (accept) => {
    expect(acceptsRelayInformation(accept)).toBe(false);
  });
});

describe('NIP-11 relay information document', () => {
  it('advertises the restricted NIP-46 relay', async () => {
    const response = await send(deployment(), { headers: NIP11 });
    expect(await response.json()).toStrictEqual({
      name: 'Signflare',
      description: 'Restricted relay for Signflare NIP-46 remote signing.',
      pubkey: admin.pubkey,
      supported_nips: [1, 11, 46],
      software: 'https://github.com/SnowCait/signflare',
      limitation: {
        restricted_writes: true,
      },
    });
  });

  it('omits self and the remote-signer pubkey', async () => {
    const response = await send(deployment(), { headers: NIP11 });
    const text = await response.text();
    expect(JSON.parse(text)).not.toHaveProperty('self');
    for (const material of secretMaterial()) {
      expect(text).not.toContain(material);
    }
  });

  it('sends the CORS headers that NIP-11 requires', async () => {
    const response = await send(deployment(), {
      headers: { ...NIP11, Origin: 'https://client.example' },
    });
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(response.headers.get('Access-Control-Allow-Headers')).toBe('*');
    expect(response.headers.get('Access-Control-Allow-Methods')).toBe(
      'GET, HEAD, OPTIONS',
    );
  });

  it('answers the CORS preflight', async () => {
    const d = deployment();
    const response = await send(d, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://client.example',
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'accept, cache-control',
      },
    });
    expect(response.status).toBe(204);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(response.headers.get('Access-Control-Allow-Headers')).toBe('*');
    expect(response.headers.get('Access-Control-Allow-Methods')).toBe(
      'GET, HEAD, OPTIONS',
    );
    expect(response.headers.get('Allow')).toBe('GET, HEAD, OPTIONS');
    expect(await response.text()).toBe('');
    expect(d.reads).toEqual([]);
    expect(d.hubNames).toEqual([]);
  });

  it('reads ADMIN_PUBKEY and nothing else', async () => {
    const d = deployment();
    const response = await send(d, { headers: NIP11 });
    expect(response.status).toBe(200);
    expect(d.reads).toEqual(['ADMIN_PUBKEY']);
    expect(d.hubNames).toEqual([]);
    expect(d.assetRequests).toEqual([]);
  });

  it('needs neither the remote-signer key nor the master key', async () => {
    const d = deployment();
    const unconfigured = withoutBinding(
      withoutBinding(d.env, 'REMOTE_SIGNER_PRIVATE_KEY'),
      'MASTER_ENCRYPTION_KEY',
    );
    const response = await send(unconfigured, { headers: NIP11 });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ pubkey: admin.pubkey });
  });

  it.each<[string, unknown]>([
    ['missing', undefined],
    ['the empty placeholder', ''],
    ['uppercase', admin.pubkey.toUpperCase()],
    ['an npub', npubEncode(admin.pubkey)],
    ['markup', '<script>alert(1)</script>'],
  ])('fails safely when ADMIN_PUBKEY is %s', async (_case, value) => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const d = deployment();
    const misconfigured =
      value === undefined
        ? withoutBinding(d.env, 'ADMIN_PUBKEY')
        : { ...d.env, ADMIN_PUBKEY: value as string };
    const response = await send(misconfigured, { headers: NIP11 });
    expect(response.status).toBe(500);
    expect(response.headers.get('Content-Type')).toMatch(/^application\/json/);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    const text = await response.text();
    expect(JSON.parse(text)).toEqual({ error: 'server configuration error' });
    expect(logged.mock.calls).toEqual([[CONFIGURATION_ERROR]]);
    if (typeof value === 'string' && value !== '') {
      expect(text).not.toContain(value);
    }
    expect(d.hubNames).toEqual([]);
  });
});

describe('landing page', () => {
  async function page(d = deployment(), url = `${ORIGIN}/`) {
    const response = await send(d, { headers: NAVIGATION }, url);
    expect(response.status).toBe(200);
    return { response, html: await response.text() };
  }

  it('describes the deployment', async () => {
    const { response, html } = await page();
    expect(response.headers.get('Content-Type')).toBe(
      'text/html; charset=UTF-8',
    );
    expect(html).toContain('<h1>Signflare</h1>');
    expect(html).toContain(
      'Self-hosted Nostr remote signer running on Cloudflare Workers.',
    );
    expect(html).toMatch(/restricted NIP-46 relay/);
    expect(html).toMatch(/not a general-purpose Nostr relay/);
    expect(html).toContain(`<code>${admin.pubkey}</code>`);
    expect(html).toContain(`<code>${npubEncode(admin.pubkey)}</code>`);
    expect(html).toContain('<code>wss://signflare.example/</code>');
    expect(html).toMatch(/NIP-46 remote signing/);
    expect(html).toContain('<code>bunker://</code>');
    expect(html).toContain(`<a href="${SOFTWARE_URL}">`);
    expect(html).toContain(`<a href="${DEPLOY_TO_CLOUDFLARE_URL}">`);
    expect(DEPLOY_TO_CLOUDFLARE_URL).toBe(
      'https://deploy.workers.cloudflare.com/?url=https://github.com/SnowCait/signflare',
    );
  });

  it.each<[string, string]>([
    ['https://example.com/', 'wss://example.com/'],
    ['http://localhost/', 'ws://localhost/'],
    ['http://localhost:5173/?a=1', 'ws://localhost:5173/'],
    ['https://signer.example.com:8443/', 'wss://signer.example.com:8443/'],
    ['http://127.0.0.1:8787/', 'ws://127.0.0.1:8787/'],
  ])('derives the relay URL of %s', async (url, relay) => {
    const { html } = await page(deployment(), url);
    expect(html).toContain(`<dd><code>${relay}</code></dd>`);
  });

  it('ignores Host and X-Forwarded-* headers', async () => {
    const d = deployment();
    const response = await send(d, {
      headers: {
        ...NAVIGATION,
        Host: 'evil.example',
        'X-Forwarded-Host': 'evil.example',
        'X-Forwarded-Proto': 'http',
        Forwarded: 'host=evil.example;proto=http',
      },
    });
    const html = await response.text();
    expect(html).toContain('<code>wss://signflare.example/</code>');
    expect(html).not.toContain('evil.example');
  });

  it('exposes no secret or operational state', async () => {
    const { html } = await page();
    for (const material of secretMaterial()) {
      expect(html).not.toContain(material);
    }
    expect(html).not.toContain('/admin');
    expect(html).not.toMatch(/identit|session|pairing|database|storage/i);
  });

  it('reads ADMIN_PUBKEY and nothing else', async () => {
    const d = deployment();
    await page(d);
    expect(d.reads).toEqual(['ADMIN_PUBKEY']);
    expect(d.hubNames).toEqual([]);
    expect(d.assetRequests).toEqual([]);
  });

  it('runs no script and loads no resource', async () => {
    const { response, html } = await page();
    expect(html).not.toMatch(/<script|<link|<img|<iframe|\ssrc=/i);
    expect(response.headers.get('Content-Security-Policy')).toBe(
      "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    );
  });

  it('escapes the values it shows', async () => {
    const html = String(
      await landingPage(admin.pubkey, 'wss://x.example/"><script>&\''),
    );
    expect(html).toContain(
      'wss://x.example/&quot;&gt;&lt;script&gt;&amp;&#39;',
    );
    expect(html).not.toContain('<script>');
  });

  it.each<[string, unknown]>([
    ['missing', undefined],
    ['the empty placeholder', ''],
    ['malformed', '<script>alert(1)</script>'],
  ])('fails safely when ADMIN_PUBKEY is %s', async (_case, value) => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const d = deployment();
    const misconfigured =
      value === undefined
        ? withoutBinding(d.env, 'ADMIN_PUBKEY')
        : { ...d.env, ADMIN_PUBKEY: value as string };
    const response = await send(misconfigured, { headers: NAVIGATION });
    expect(response.status).toBe(500);
    const text = await response.text();
    expect(text).toBe('server configuration error');
    expect(logged.mock.calls).toEqual([[CONFIGURATION_ERROR]]);
    expect(d.hubNames).toEqual([]);
  });
});
