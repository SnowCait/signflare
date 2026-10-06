import { describe, expect, it } from 'vitest';

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
