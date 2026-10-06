import { describe, expect, expectTypeOf, it } from 'vitest';
import devVarsExample from '../.dev.vars.example?raw';
import gitignore from '../.gitignore?raw';
import packageJson from '../package.json?raw';
import readme from '../README.md?raw';
import { parseAdminPubkey, parseMasterEncryptionKey } from '../src/config';
import { InvalidPrivateKeyError, parsePrivateKey } from '../src/private-key';
import type { SignerHub } from '../src/signer-hub';
import {
  wranglerConfig as config,
  wranglerConfigText,
} from './wrangler-config';

// The deployment configuration model (docs/design.md §7, §36): wrangler.jsonc
// declares every binding and holds no real value, the generated Env types
// them, and .dev.vars.example names the secrets for Deploy to Cloudflare.

interface PackageJson {
  scripts: Record<string, string>;
}

// Every binding of the Worker and the SignerHub.
const BINDINGS = [
  'ADMIN_PUBKEY',
  'ASSETS',
  'MASTER_ENCRYPTION_KEY',
  'REMOTE_SIGNER_PRIVATE_KEY',
  'SIGNER_HUB',
] as const;

// The NAME=value lines of a dotenv file. Comments are not assignments.
function dotenvAssignments(text: string): Map<string, string> {
  const assignments = new Map<string, string>();
  for (const line of text.split('\n')) {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$/.exec(line);
    if (match !== null) {
      assignments.set(match[1], match[2].trim());
    }
  }
  return assignments;
}

// Whether git ignores a file at the root of the repository under the rules
// .gitignore uses: the last matching pattern decides, a leading ! re-includes
// the file, and * matches within a name.
function ignoredByGit(name: string): boolean {
  let ignored = false;
  for (const line of gitignore.split('\n')) {
    const pattern = line.trim();
    if (pattern === '' || pattern.startsWith('#')) {
      continue;
    }
    const negated = pattern.startsWith('!');
    const source = (negated ? pattern.slice(1) : pattern)
      .split('*')
      .map((part) => part.replace(/[.+?^${}()|[\]\\/-]/g, '\\$&'))
      .join('[^/]*');
    if (new RegExp(`^${source}$`).test(name)) {
      ignored = !negated;
    }
  }
  return ignored;
}

const pkg = JSON.parse(packageJson) as PackageJson;
const example = dotenvAssignments(devVarsExample);

describe('wrangler.jsonc', () => {
  it('declares every binding of the Worker and the SignerHub', () => {
    const declared = [
      ...Object.keys(config.vars),
      ...config.secrets.required,
      config.assets.binding,
      ...config.durable_objects.bindings.map(({ name }) => name),
    ];
    expect(declared.toSorted()).toEqual(BINDINGS);
    expect(config.durable_objects.bindings).toEqual([
      { name: 'SIGNER_HUB', class_name: 'SignerHub' },
    ]);
    expect(config.exports).toEqual({
      SignerHub: { type: 'durable-object', storage: 'sqlite' },
    });
  });

  it('declares ADMIN_PUBKEY as public configuration', () => {
    expect(Object.keys(config.vars)).toEqual(['ADMIN_PUBKEY']);
    expect(config.secrets.required).not.toContain('ADMIN_PUBKEY');
  });

  it('declares the two keys as required Worker secrets', () => {
    expect(config.secrets.required).toEqual([
      'MASTER_ENCRYPTION_KEY',
      'REMOTE_SIGNER_PRIVATE_KEY',
    ]);
    for (const secret of config.secrets.required) {
      expect(config.vars).not.toHaveProperty(secret);
    }
  });

  it('holds no administrator public key', () => {
    expect(config.vars.ADMIN_PUBKEY).toBe('');
    expect(parseAdminPubkey(config.vars.ADMIN_PUBKEY)).toBeNull();
  });

  it('stays the source of truth for ADMIN_PUBKEY on deploy', () => {
    expect(config).not.toHaveProperty('keep_vars');
  });
});

describe('generated binding types', () => {
  it('types every binding from wrangler.jsonc', () => {
    expectTypeOf<keyof Env>().toEqualTypeOf<(typeof BINDINGS)[number]>();
    expectTypeOf<Env['ADMIN_PUBKEY']>().toEqualTypeOf<string>();
    expectTypeOf<Env['MASTER_ENCRYPTION_KEY']>().toEqualTypeOf<string>();
    expectTypeOf<Env['REMOTE_SIGNER_PRIVATE_KEY']>().toEqualTypeOf<string>();
    expectTypeOf<Env['ASSETS']>().toEqualTypeOf<Fetcher>();
    expectTypeOf<Env['SIGNER_HUB']>().toEqualTypeOf<
      DurableObjectNamespace<SignerHub>
    >();
  });

  it('gives the SignerHub the bindings of the Worker', () => {
    expectTypeOf<
      ConstructorParameters<typeof SignerHub>[1]
    >().toEqualTypeOf<Env>();
  });

  it('types ADMIN_PUBKEY as a string rather than its placeholder', () => {
    // With literal types, the generated Env would type ADMIN_PUBKEY as "".
    expect(pkg.scripts.types).toBe('wrangler types --strict-vars=false');
    expect(pkg.scripts.typecheck).toMatch(/^npm run types && /);
  });
});

describe('.dev.vars.example', () => {
  it('names exactly the required secrets', () => {
    expect([...example.keys()]).toEqual(config.secrets.required);
  });

  it('assigns no ADMIN_PUBKEY, not even in a comment', () => {
    // Deploy to Cloudflare reads the names in this file as Worker secrets.
    expect(devVarsExample).not.toMatch(/ADMIN_PUBKEY\s*=/);
  });

  it('holds placeholders that are not usable secrets', () => {
    expect(
      parseMasterEncryptionKey(example.get('MASTER_ENCRYPTION_KEY')),
    ).toBeNull();
    expect(() =>
      parsePrivateKey(example.get('REMOTE_SIGNER_PRIVATE_KEY')),
    ).toThrow(InvalidPrivateKeyError);
  });
});

describe('.gitignore', () => {
  it.each([
    '.dev.vars',
    '.dev.vars.production',
    '.env',
    '.env.local',
    'worker-configuration.d.ts',
  ])('ignores %s', (name) => {
    expect(ignoredByGit(name)).toBe(true);
  });

  it('tracks .dev.vars.example', () => {
    expect(ignoredByGit('.dev.vars.example')).toBe(false);
  });
});

describe('committed configuration and documentation', () => {
  it.each<[string, string]>([
    ['wrangler.jsonc', wranglerConfigText],
    ['.dev.vars.example', devVarsExample],
    ['package.json', packageJson],
    ['README.md', readme],
  ])('%s contains no key', (_name, text) => {
    // A hex key or an nsec, as a real value would be written.
    expect(text).not.toMatch(/(^|[^0-9a-f])[0-9a-f]{64}($|[^0-9a-f])/i);
    expect(text).not.toMatch(/nsec1[02-9ac-hj-np-z]{6}/);
  });
});
