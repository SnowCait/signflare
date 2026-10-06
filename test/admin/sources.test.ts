import { describe, expect, it } from 'vitest';
import design from '../../docs/design.md?raw';

// Properties of the Admin SPA's source that hold for every component,
// including the Svelte ones that the other tests do not run
// (docs/design.md §31.4, §39.11).

const sources = import.meta.glob<string>(
  '../../admin/**/*.{ts,svelte,html,css}',
  {
    query: '?raw',
    import: 'default',
    eager: true,
  },
);

const files = Object.entries(sources).map(([path, text]) => ({
  path: path.replace('../../', ''),
  text,
}));

// Links in comments that only document behavior.
const DOCUMENTATION_URL =
  /https:\/\/github\.com\/nostr-protocol\/nips\/blob\/master\/\d+\.md/g;

describe('Admin SPA sources', () => {
  it('include the app', () => {
    const paths = files.map(({ path }) => path);
    expect(paths).toContain('admin/index.html');
    expect(paths).toContain('admin/App.svelte');
    expect(paths).toContain('admin/lib/admin-controller.ts');
    expect(
      paths.filter((path) => path.endsWith('.svelte')).length,
    ).toBeGreaterThan(5);
  });

  it.each([
    ['localStorage', /\blocalStorage\b/],
    ['sessionStorage', /\bsessionStorage\b/],
    ['IndexedDB', /\bindexedDB\b|\bIDB[A-Z]/],
    ['cookies', /\.cookie\b|\bcookieStore\b/],
    ['the Cache API', /\bcaches\b/],
    ['history state', /\bhistory\.(push|replace)State\b/],
    ['console', /\bconsole\./],
  ])('do not use %s', (_name, pattern) => {
    for (const { path, text } of files) {
      expect(text, path).not.toMatch(pattern);
    }
  });

  it('never insert HTML', () => {
    for (const { path, text } of files) {
      expect(text, path).not.toMatch(
        /\{@html\b|innerHTML|outerHTML|insertAdjacentHTML/,
      );
    }
  });

  it('load nothing that a response could point to', () => {
    for (const { path, text } of files) {
      expect(text, path).not.toMatch(
        /<(img|iframe|object|embed|video|audio|source)\b/i,
      );
      expect(text, path).not.toMatch(/\bnew Image\b|\burl\(/);
      expect(text, path).not.toMatch(/<a\b[^>]*\bhref=\{/);
    }
  });

  it('refer to no third-party resources', () => {
    for (const { path, text } of files) {
      const urls = text
        .replace(DOCUMENTATION_URL, '')
        .match(/\b(https?:)?\/\/[^\s'"`)]+/g);
      expect(urls, path).toBeNull();
    }
  });

  it('load only the bundled entry script from the page', () => {
    const page = sources['../../admin/index.html'];
    expect(page.match(/<script\b[^>]*>/g)).toEqual([
      '<script type="module" src="/admin/main.ts">',
    ]);
    expect(page.match(/<link\b[^>]*>/g)).toEqual([
      '<link rel="icon" href="data:," />',
    ]);
  });

  it('obscure the private-key input and keep it out of autofill', () => {
    const form = sources['../../admin/components/IdentityForm.svelte'];
    const input = form.match(
      /<input\b[^>]*bind:value=\{privateKey\}[^>]*>/s,
    )?.[0];
    expect(input).toContain('type="password"');
    expect(input).toContain('autocomplete="off"');
  });
});

// Without explicit permissions, a session cannot sign, encrypt, or decrypt,
// but the control methods of docs/design.md §16.2 need no permission.
describe('descriptions of empty permissions', () => {
  const section =
    /### 16\.2 Control methods\n([\s\S]*?)\nThey still require/.exec(
      design,
    )?.[1] ?? '';
  const methods = [...section.matchAll(/^- `(\w+)`$/gm)].map(
    ([, method]) => method,
  );

  // Template markup with its line breaks and indentation collapsed.
  function text(path: string, start: string, end: string): string {
    const source = sources[`../../admin/components/${path}`];
    const from = source.indexOf(start);
    return source
      .slice(from + start.length, source.indexOf(end, from))
      .replace(/\s+/g, ' ')
      .trim();
  }

  it('reads the control methods from the design', () => {
    expect(methods).toEqual([
      'ping',
      'get_public_key',
      'switch_relays',
      'logout',
    ]);
  });

  it('never limit an empty grant to the public key and ping', () => {
    for (const { path, text: source } of files) {
      expect(source.replace(/\s+/g, ' '), path).not.toMatch(
        /only get (the (identity’s )?)?public key and ping/,
      );
    }
  });

  it('keep the control methods available for an empty pairing selection', () => {
    const hint = text('PairingForm.svelte', '{#if nothingSelected}', '{/if}');
    expect(hint).toContain(
      'No signing, encryption, or decryption permissions are granted.',
    );
    expect(hint).toContain('remain available once the client is connected');
    for (const method of methods) {
      expect(hint).toContain(`<code>${method}</code>`);
    }
  });

  it('tell an empty stored grant apart from having no methods', () => {
    expect(
      text(
        'SessionList.svelte',
        '{#if session.permissions.length === 0}',
        '{:else}',
      ),
    ).toBe(
      'None: no signing, encryption, or decryption permissions. Control methods remain available.',
    );
  });
});
