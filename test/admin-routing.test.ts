import { env } from 'cloudflare:workers';
import { afterEach, describe, expect, it, vi } from 'vitest';
import adminPage from '../admin/index.html?raw';
import viteConfig from '../vite.config.ts?raw';
import wranglerConfig from '../wrangler.jsonc?raw';
import app from '../src/index';
import { ORIGIN, randomKey } from './nostr-helpers';

// The Worker's part of serving the Admin SPA (docs/design.md §31.1). In a
// deployment, Workers Static Assets answers requests for built files before
// the Worker runs; the Worker gets every other request. The test pool has no
// built assets, so ASSETS is replaced by a recording stand-in here, and the
// static routing configuration is checked as configuration.

const SHELL = '<!doctype html><title>Signflare Admin</title>';
const NAVIGATION = {
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Dest': 'document',
  Accept: 'text/html',
};

interface AssetsStub {
  readonly env: Env;
  // Method and URL of each request made through the ASSETS binding.
  readonly requests: string[];
  // Names used to reach the SignerHub.
  readonly hubNames: string[];
}

function deployment(): AssetsStub {
  const requests: string[] = [];
  const hubNames: string[] = [];
  const assets = {
    async fetch(input: RequestInfo | URL, init?: RequestInit) {
      const request = new Request(input, init);
      requests.push(`${request.method} ${request.url}`);
      return new Response(SHELL, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    },
  };
  return {
    env: {
      ...env,
      ADMIN_PUBKEY: randomKey().pubkey,
      ASSETS: assets as unknown as Env['ASSETS'],
      SIGNER_HUB: {
        getByName(name: string) {
          hubNames.push(name);
          return env.SIGNER_HUB.getByName(name);
        },
      } as unknown as Env['SIGNER_HUB'],
    },
    requests,
    hubNames,
  };
}

async function send(
  d: AssetsStub,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  return app.fetch(new Request(`${ORIGIN}${path}`, init), d.env);
}

// wrangler.jsonc as JSON: without comments and trailing commas.
function parseJsonc(text: string): Record<string, unknown> {
  return JSON.parse(
    text.replace(/^\s*\/\/.*$/gm, '').replace(/,(\s*[}\]])/g, '$1'),
  );
}

// Whether a run_worker_first entry matches a path: Cloudflare's documented
// glob semantics, where * matches anything and the pattern must match the
// whole path.
function globMatches(pattern: string, path: string): boolean {
  const source = pattern
    .split('*')
    .map((part) => part.replace(/[.+?^${}()|[\]\\/-]/g, '\\$&'))
    .join('.*');
  return new RegExp(`^${source}$`).test(path);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Admin SPA routes', () => {
  it.each([
    '/admin',
    '/admin/',
    '/admin/identities',
    '/admin/some/deep/link?tab=sessions',
  ])('serve the SPA entry page for GET %s', async (path) => {
    const d = deployment();
    const response = await send(d, path, { headers: NAVIGATION });
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toMatch(/^text\/html/);
    expect(await response.text()).toBe(SHELL);
    expect(d.requests).toEqual([`GET ${ORIGIN}/admin/`]);
    expect(d.hubNames).toEqual([]);
  });

  it('serves the entry page to HEAD requests', async () => {
    const d = deployment();
    const response = await send(d, '/admin/identities', { method: 'HEAD' });
    expect(response.status).toBe(200);
    expect(d.requests).toEqual([`HEAD ${ORIGIN}/admin/`]);
  });

  it('serves the entry page rather than the relay to a WebSocket upgrade', async () => {
    const d = deployment();
    const response = await send(d, '/admin/relay', {
      headers: { Upgrade: 'websocket' },
    });
    expect(response.status).toBe(200);
    expect(response.webSocket).toBeNull();
    expect(d.hubNames).toEqual([]);
  });

  it('do not answer missing built files with the entry page', async () => {
    const d = deployment();
    const response = await send(d, '/admin/assets/index-missing.js');
    expect(response.status).toBe(404);
    expect(await response.text()).not.toContain('<!doctype html>');
    expect(d.requests).toEqual([]);
  });

  it.each(['POST', 'PUT', 'DELETE'])('do not answer %s', async (method) => {
    const d = deployment();
    const response = await send(d, '/admin/identities', {
      method,
      headers: { Origin: ORIGIN },
    });
    expect(response.status).toBe(404);
    expect(d.requests).toEqual([]);
  });
});

describe('Admin API routes', () => {
  it.each([{}, NAVIGATION])('reach the Admin API: %j', async (headers) => {
    const d = deployment();
    const response = await send(d, '/admin/api/session', { headers });
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'unauthorized' });
    expect(d.requests).toEqual([]);
  });

  it.each([
    '/admin/api',
    '/admin/api/',
    '/admin/api/unknown',
    '/admin/api/identities/x/unknown',
    '/admin/api/assets/index.js',
  ])('answer the unknown endpoint %s with a JSON error', async (path) => {
    const d = deployment();
    const response = await send(d, path, { headers: NAVIGATION });
    expect(response.status).toBe(404);
    expect(response.headers.get('Content-Type')).toMatch(/^application\/json/);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(await response.json()).toEqual({ error: 'not found' });
    expect(d.requests).toEqual([]);
  });

  it('keep checking the origin of unknown state-changing requests', async () => {
    const d = deployment();
    const sameOrigin = await send(d, '/admin/api/unknown', {
      method: 'POST',
      headers: { Origin: ORIGIN },
    });
    expect(sameOrigin.status).toBe(404);
    const crossOrigin = await send(d, '/admin/api/unknown', {
      method: 'POST',
      headers: { Origin: 'https://attacker.example' },
    });
    expect(crossOrigin.status).toBe(403);
    expect(d.requests).toEqual([]);
  });
});

describe('root routes', () => {
  it('keep serving the landing page rather than the SPA', async () => {
    const d = deployment();
    const response = await send(d, '/', { headers: NAVIGATION });
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toMatch(/^text\/html/);
    expect(await response.text()).toContain('<h1>Signflare</h1>');
    expect(d.requests).toEqual([]);
    expect(d.hubNames).toEqual([]);
  });

  it('keep the WebSocket upgrade to the relay', async () => {
    const d = deployment();
    const response = await send(d, '/', { headers: { Upgrade: 'websocket' } });
    expect(response.status).toBe(101);
    expect(response.webSocket).not.toBeNull();
    expect(d.hubNames).toEqual(['signer']);
    expect(d.requests).toEqual([]);
    response.webSocket?.accept();
    response.webSocket?.close(1000);
  });

  it('do not serve the SPA elsewhere', async () => {
    const d = deployment();
    for (const path of ['/admin-panel', '/favicon.ico', '/index.html']) {
      const response = await send(d, path, { headers: NAVIGATION });
      expect(response.status, path).toBe(404);
    }
    expect(d.requests).toEqual([]);
  });
});

describe('static asset configuration', () => {
  const config = parseJsonc(wranglerConfig);
  const assets = config.assets as Record<string, unknown>;

  it('binds the assets for the SPA fallback', () => {
    expect(assets.binding).toBe('ASSETS');
  });

  it('leaves the assets directory to the Cloudflare Vite plugin', () => {
    expect(assets).not.toHaveProperty('directory');
  });

  it('keeps browser navigations reaching the Worker', () => {
    // With not_found_handling set, Workers Static Assets would answer
    // navigations itself, always with the root index.html.
    expect(assets).not.toHaveProperty('not_found_handling');
    // The default, which serves /admin/index.html at /admin/.
    expect(assets).not.toHaveProperty('html_handling');
  });

  it('runs the Worker first for the root and the Admin API only', () => {
    const patterns = assets.run_worker_first as string[];
    const workerFirst = (path: string) =>
      patterns.some(
        (pattern) => !pattern.startsWith('!') && globMatches(pattern, path),
      ) &&
      !patterns.some(
        (pattern) =>
          pattern.startsWith('!') && globMatches(pattern.slice(1), path),
      );
    for (const path of [
      '/',
      '/admin/api/session',
      '/admin/api/identities/x/sessions',
      '/admin/api/x/y',
    ]) {
      expect(workerFirst(path), path).toBe(true);
    }
    for (const path of [
      '/admin',
      '/admin/',
      '/admin/index.html',
      '/admin/assets/index-abc.js',
      '/admin/identities',
    ]) {
      expect(workerFirst(path), path).toBe(false);
    }
  });

  it('builds the SPA where the Worker expects it', () => {
    // The entry page becomes /admin/index.html, served at /admin/, and the
    // bundles go to /admin/assets/.
    expect(viteConfig).toContain("input: 'admin/index.html'");
    expect(viteConfig).toContain("assetsDir: 'admin/assets'");
    expect(adminPage).toContain('<script type="module" src="/admin/main.ts">');
  });
});
