import { describe, expect, it } from 'vitest';
import {
  ALL_PERMISSIONS,
  canonicalizePermissions,
  deserializePermissions,
  intersectPermissions,
  InvalidPermissionError,
  isPermitted,
  MalformedPermissionsError,
  MAX_EVENT_KIND,
  parsePairingPermissions,
  parseRequestedPermissions,
  type Permission,
  PERMISSION_METHODS,
  serializePermissions,
} from '../src/permissions';

// docs/design.md §16, in canonical order.
const EXPANDED_ALL = [
  'sign_event',
  'nip04_encrypt',
  'nip04_decrypt',
  'nip44_encrypt',
  'nip44_decrypt',
];

// Strings that are not explicit v1 permissions.
const INVALID_PERMISSIONS: [string, string][] = [
  ['an empty string', ''],
  ['the convenience value all', 'all'],
  ['an uppercase all', 'ALL'],
  ['ping', 'ping'],
  ['get_public_key', 'get_public_key'],
  ['switch_relays', 'switch_relays'],
  ['logout', 'logout'],
  ['connect', 'connect'],
  ['an unknown method', 'nip17_encrypt'],
  ['a method prefix', 'nip44'],
  ['an uppercase method', 'SIGN_EVENT'],
  ['a mixed-case method', 'Nip44_encrypt'],
  ['a negative kind', 'sign_event:-1'],
  ['a decimal kind', 'sign_event:1.5'],
  ['a kind with a zero fraction', 'sign_event:1.0'],
  ['an exponent', 'sign_event:1e3'],
  ['a hexadecimal kind', 'sign_event:0x1'],
  ['a plus sign', 'sign_event:+1'],
  ['a leading zero', 'sign_event:01'],
  ['a doubled zero', 'sign_event:00'],
  ['the first kind above 65535', 'sign_event:65536'],
  ['a kind beyond 32 bits', 'sign_event:4294967297'],
  ['a long digit string', `sign_event:${'9'.repeat(400)}`],
  ['Infinity', 'sign_event:Infinity'],
  ['NaN', 'sign_event:NaN'],
  ['an empty kind', 'sign_event:'],
  ['a doubled separator', 'sign_event::1'],
  ['a second parameter', 'sign_event:1:2'],
  ['a parameter on another method', 'nip44_encrypt:1'],
  ['a kind without a method', ':1'],
  ['leading whitespace', ' sign_event'],
  ['trailing whitespace', 'nip44_encrypt '],
  ['whitespace before the kind', 'sign_event: 1'],
  ['whitespace before the separator', 'sign_event :1'],
  ['a trailing newline', 'sign_event:1\n'],
  ['a tab', '\tnip04_decrypt'],
  ['full-width digits', 'sign_event:１'],
  ['Arabic-Indic digits', 'sign_event:٧'],
  ['a comma-separated list', 'sign_event,nip44_encrypt'],
  ['a quoted permission', '"sign_event"'],
];

const NON_STRINGS: [string, unknown][] = [
  ['a number', 1],
  ['null', null],
  ['undefined', undefined],
  ['a boolean', true],
  ['an object', { method: 'sign_event' }],
  ['a nested array', ['sign_event']],
];

function expectInvalid(run: () => unknown, input: string): void {
  let caught: unknown;
  try {
    run();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(InvalidPermissionError);
  const error = caught as InvalidPermissionError;
  expect(error.message).toBe('Invalid permission');
  if (input.trim().length > 0) {
    expect(String(error)).not.toContain(input.trim());
  }
}

describe('canonicalizePermissions', () => {
  it('accepts every explicit v1 method', () => {
    expect(PERMISSION_METHODS).toEqual(EXPANDED_ALL);
    for (const method of PERMISSION_METHODS) {
      expect(canonicalizePermissions([method])).toEqual([method]);
    }
  });

  it('accepts sign_event kinds across the NIP-01 range', () => {
    expect(MAX_EVENT_KIND).toBe(65_535);
    for (const kind of [0, 1, 7, 10_002, 30_023, 65_535]) {
      expect(canonicalizePermissions([`sign_event:${kind}`])).toEqual([
        `sign_event:${kind}`,
      ]);
    }
  });

  it.each(INVALID_PERMISSIONS)('rejects %s', (_case, permission) => {
    expectInvalid(() => canonicalizePermissions([permission]), permission);
    expectInvalid(
      () => canonicalizePermissions(['nip44_encrypt', permission]),
      permission,
    );
  });

  it.each(NON_STRINGS)('rejects %s as an entry', (_case, permission) => {
    expect(() => canonicalizePermissions([permission])).toThrow(
      InvalidPermissionError,
    );
  });

  it('returns an empty set unchanged', () => {
    expect(canonicalizePermissions([])).toEqual([]);
  });

  it('removes duplicates', () => {
    expect(
      canonicalizePermissions([
        'nip44_encrypt',
        'sign_event:1',
        'nip44_encrypt',
        'sign_event:1',
      ]),
    ).toEqual(['sign_event:1', 'nip44_encrypt']);
  });

  it('orders methods as designed and kinds numerically', () => {
    expect(
      canonicalizePermissions([
        'nip44_decrypt',
        'sign_event:10',
        'nip04_decrypt',
        'sign_event:2',
        'nip44_encrypt',
        'sign_event:1',
        'nip04_encrypt',
      ]),
    ).toEqual([
      'sign_event:1',
      'sign_event:2',
      'sign_event:10',
      'nip04_encrypt',
      'nip04_decrypt',
      'nip44_encrypt',
      'nip44_decrypt',
    ]);
  });

  it('does not depend on the input order', () => {
    const permissions = [
      'sign_event:30023',
      'nip04_decrypt',
      'sign_event:0',
      'nip44_encrypt',
      'sign_event:7',
    ];
    const canonical = canonicalizePermissions(permissions);
    for (let shift = 1; shift < permissions.length; shift++) {
      const rotated = [
        ...permissions.slice(shift),
        ...permissions.slice(0, shift),
      ];
      expect(canonicalizePermissions(rotated)).toEqual(canonical);
      expect(canonicalizePermissions(rotated.reverse())).toEqual(canonical);
    }
  });

  it('drops kinds that sign_event already grants', () => {
    expect(
      canonicalizePermissions([
        'sign_event:1',
        'nip04_encrypt',
        'sign_event',
        'sign_event:7',
      ]),
    ).toEqual(['sign_event', 'nip04_encrypt']);
  });
});

describe('parsePairingPermissions', () => {
  it('expands all to the explicit v1 permission set', () => {
    expect(ALL_PERMISSIONS).toBe('all');
    expect(parsePairingPermissions('all')).toEqual(EXPANDED_ALL);
  });

  it('expands all inside a list', () => {
    expect(parsePairingPermissions(['all'])).toEqual(EXPANDED_ALL);
    expect(
      parsePairingPermissions(['sign_event:1', 'all', 'nip44_decrypt']),
    ).toEqual(EXPANDED_ALL);
  });

  it('canonicalizes an explicit list', () => {
    expect(
      parsePairingPermissions([
        'sign_event:1',
        'nip44_encrypt',
        'nip44_decrypt',
      ]),
    ).toEqual(['sign_event:1', 'nip44_encrypt', 'nip44_decrypt']);
    expect(
      parsePairingPermissions(['nip44_encrypt', 'sign_event:7', 'sign_event']),
    ).toEqual(['sign_event', 'nip44_encrypt']);
  });

  it('accepts an empty list', () => {
    expect(parsePairingPermissions([])).toEqual([]);
  });

  it('never returns all', () => {
    for (const input of ['all', ['all'], ['all', 'sign_event:1']]) {
      expect(parsePairingPermissions(input)).not.toContain('all');
    }
  });

  it.each<[string, unknown]>([
    ['an uppercase ALL', 'ALL'],
    ['a capitalized All', 'All'],
    ['all with whitespace', ' all'],
    ['all inside a list with whitespace', ['all ']],
    ['a single permission string', 'sign_event'],
    ['a comma-separated string', 'sign_event,nip44_encrypt'],
    ['an empty string', ''],
    ['null', null],
    ['undefined', undefined],
    ['a number', 42],
    ['an object', { permissions: 'all' }],
    ['a nested list', [['all']]],
    ['a list with a number', [1]],
    ['a list with an unknown method', ['all', 'ping']],
    ['a list with an invalid kind', ['sign_event:-1']],
  ])('rejects %s', (_case, input) => {
    expect(() => parsePairingPermissions(input)).toThrow(
      InvalidPermissionError,
    );
  });
});

describe('parseRequestedPermissions', () => {
  it('treats omitted and empty requests as no restriction', () => {
    expect(parseRequestedPermissions(undefined)).toBeNull();
    expect(parseRequestedPermissions('')).toBeNull();
  });

  it('parses a comma-separated method[:params] list', () => {
    expect(
      parseRequestedPermissions('nip44_encrypt,sign_event:1,sign_event:7'),
    ).toEqual(['sign_event:1', 'sign_event:7', 'nip44_encrypt']);
    // The example from NIP-46.
    expect(parseRequestedPermissions('nip44_encrypt,sign_event:4')).toEqual([
      'sign_event:4',
      'nip44_encrypt',
    ]);
    expect(parseRequestedPermissions('sign_event')).toEqual(['sign_event']);
  });

  it('canonicalizes duplicates and kinds covered by sign_event', () => {
    expect(
      parseRequestedPermissions(
        'sign_event:7,nip04_decrypt,sign_event:7,sign_event,nip04_decrypt',
      ),
    ).toEqual(['sign_event', 'nip04_decrypt']);
  });

  it.each([
    ['all', 'all'],
    ['all within a list', 'sign_event:1,all'],
    ['whitespace after a comma', 'nip44_encrypt, sign_event:1'],
    ['whitespace before a comma', 'nip44_encrypt ,sign_event:1'],
    ['surrounding whitespace', ' nip44_encrypt '],
    ['only whitespace', ' '],
    ['a lone comma', ','],
    ['a trailing comma', 'sign_event,'],
    ['a leading comma', ',sign_event'],
    ['an empty entry', 'sign_event,,nip44_encrypt'],
    ['a control method', 'sign_event,get_public_key'],
    ['ping', 'ping'],
    ['an unknown method', 'nip44_encrypt,create_account'],
    ['a kind above 65535', 'sign_event:65536'],
    ['a negative kind', 'sign_event:-1'],
    ['a decimal kind', 'sign_event:1.5'],
    ['another separator', 'sign_event;nip44_encrypt'],
    ['spaces as separators', 'sign_event nip44_encrypt'],
    ['a JSON array', '["sign_event"]'],
  ])('rejects %s', (_case, requested) => {
    expectInvalid(() => parseRequestedPermissions(requested), requested);
  });

  it.each<[string, unknown]>([
    ['null', null],
    ['a number', 0],
    ['an empty array', []],
    ['an array', ['sign_event']],
  ])('rejects %s', (_case, requested) => {
    expect(() => parseRequestedPermissions(requested)).toThrow(
      InvalidPermissionError,
    );
  });
});

describe('isPermitted', () => {
  const probes = [
    'sign_event',
    'sign_event:0',
    'sign_event:1',
    'sign_event:7',
    'sign_event:65535',
    'nip04_encrypt',
    'nip04_decrypt',
    'nip44_encrypt',
    'nip44_decrypt',
  ];

  function permitted(granted: Permission[]): string[] {
    return probes.filter((probe) => isPermitted(granted, probe));
  }

  it('denies everything by default', () => {
    expect(permitted([])).toEqual([]);
  });

  it('grants a method permission only for that exact method', () => {
    expect(permitted(['nip04_encrypt'])).toEqual(['nip04_encrypt']);
    expect(permitted(['nip44_decrypt'])).toEqual(['nip44_decrypt']);
    expect(permitted(['nip04_decrypt', 'nip44_encrypt'])).toEqual([
      'nip04_decrypt',
      'nip44_encrypt',
    ]);
  });

  it('grants every kind for sign_event', () => {
    expect(permitted(['sign_event'])).toEqual([
      'sign_event',
      'sign_event:0',
      'sign_event:1',
      'sign_event:7',
      'sign_event:65535',
    ]);
  });

  it('grants only the listed kinds for sign_event:<kind>', () => {
    expect(permitted(['sign_event:1'])).toEqual(['sign_event:1']);
    expect(permitted(['sign_event:0', 'sign_event:7'])).toEqual([
      'sign_event:0',
      'sign_event:7',
    ]);
  });

  it('never grants anything that is not an explicit permission', () => {
    const everything = parsePairingPermissions('all');
    for (const permission of [
      'all',
      'ping',
      'get_public_key',
      'switch_relays',
      'logout',
      'connect',
      'sign_event:65536',
      'sign_event:-1',
      'sign_event:01',
      'sign_event:1.5',
      ' sign_event',
      '',
    ]) {
      expect(isPermitted(everything, permission)).toBe(false);
    }
  });
});

describe('intersectPermissions', () => {
  it.each<[string, Permission[], Permission[], Permission[]]>([
    [
      'wildcard pairing, one requested kind',
      ['sign_event'],
      ['sign_event:1'],
      ['sign_event:1'],
    ],
    [
      'one pairing kind, wildcard request',
      ['sign_event:1'],
      ['sign_event'],
      ['sign_event:1'],
    ],
    ['wildcard on both sides', ['sign_event'], ['sign_event'], ['sign_event']],
    [
      'overlapping kinds',
      ['sign_event:1', 'sign_event:7'],
      ['sign_event:7', 'sign_event:42'],
      ['sign_event:7'],
    ],
    ['disjoint kinds', ['sign_event:1'], ['sign_event:2'], []],
    [
      'several pairing kinds, wildcard request',
      ['sign_event:1', 'sign_event:7'],
      ['sign_event'],
      ['sign_event:1', 'sign_event:7'],
    ],
    [
      'wildcard pairing, several requested kinds',
      ['sign_event'],
      ['sign_event:7', 'sign_event:42'],
      ['sign_event:7', 'sign_event:42'],
    ],
    [
      'exact method matches',
      ['nip04_encrypt', 'nip44_decrypt'],
      ['nip04_decrypt', 'nip44_decrypt'],
      ['nip44_decrypt'],
    ],
    [
      'methods and kinds together',
      ['sign_event', 'nip44_encrypt'],
      ['sign_event:1', 'nip04_encrypt', 'nip44_encrypt'],
      ['sign_event:1', 'nip44_encrypt'],
    ],
    [
      'a request for methods the pairing lacks',
      ['sign_event:7', 'nip44_encrypt'],
      ['nip04_encrypt', 'nip04_decrypt', 'nip44_decrypt'],
      [],
    ],
    ['an empty pairing', [], ['sign_event', 'nip44_encrypt'], []],
    ['an empty request', ['sign_event', 'nip44_encrypt'], [], []],
    [
      'everything on both sides',
      [...PERMISSION_METHODS],
      [...PERMISSION_METHODS],
      [...PERMISSION_METHODS],
    ],
  ])('intersects %s', (_case, pairing, requested, expected) => {
    expect(intersectPermissions(requested, pairing)).toEqual(expected);
    expect(intersectPermissions(pairing, requested)).toEqual(expected);
  });

  // Every subset of these, as pairing and as request.
  const UNIVERSE: Permission[] = [
    'sign_event',
    'sign_event:1',
    'sign_event:7',
    'nip04_encrypt',
    'nip04_decrypt',
    'nip44_encrypt',
    'nip44_decrypt',
  ];
  const PROBES = [
    ...UNIVERSE,
    'sign_event:0',
    'sign_event:42',
    'sign_event:65535',
  ];

  function subsets<T>(items: readonly T[]): T[][] {
    return Array.from({ length: 2 ** items.length }, (_, mask) =>
      items.filter((_item, index) => mask & (1 << index)),
    );
  }

  it('grants exactly what both sets grant, for every combination', () => {
    const sets = subsets(UNIVERSE).map((set) => canonicalizePermissions(set));
    const failures: string[] = [];
    for (const a of sets) {
      for (const b of sets) {
        const result = intersectPermissions(a, b);
        const label = `[${a}] ∩ [${b}] = [${result}]`;
        for (const probe of PROBES) {
          if (
            isPermitted(result, probe) !==
            (isPermitted(a, probe) && isPermitted(b, probe))
          ) {
            failures.push(`${label}: ${probe}`);
          }
        }
        if (
          JSON.stringify(canonicalizePermissions(result)) !==
          JSON.stringify(result)
        ) {
          failures.push(`${label}: not canonical`);
        }
        if (
          JSON.stringify(intersectPermissions(b, a)) !== JSON.stringify(result)
        ) {
          failures.push(`${label}: not commutative`);
        }
        if (result.some((p) => !a.includes(p) && !b.includes(p))) {
          failures.push(`${label}: introduces a permission`);
        }
      }
    }
    expect(failures).toEqual([]);
  });
});

describe('serializePermissions', () => {
  it('writes the canonical set as a JSON array', () => {
    expect(
      serializePermissions([
        'nip44_encrypt',
        'sign_event:7',
        'sign_event:1',
        'sign_event:7',
      ]),
    ).toBe('["sign_event:1","sign_event:7","nip44_encrypt"]');
    expect(serializePermissions([])).toBe('[]');
    expect(serializePermissions(parsePairingPermissions('all'))).toBe(
      '["sign_event","nip04_encrypt","nip04_decrypt","nip44_encrypt","nip44_decrypt"]',
    );
  });

  it('writes the same text for the same set', () => {
    expect(serializePermissions(['nip04_decrypt', 'sign_event:1'])).toBe(
      serializePermissions(['sign_event:1', 'nip04_decrypt', 'sign_event:1']),
    );
    expect(serializePermissions(['sign_event', 'sign_event:1'])).toBe(
      serializePermissions(['sign_event']),
    );
  });

  it('refuses all and other invalid permissions', () => {
    for (const permission of ['all', 'ping', 'sign_event:65536']) {
      expect(() => serializePermissions([permission as Permission])).toThrow(
        InvalidPermissionError,
      );
    }
  });
});

describe('deserializePermissions', () => {
  it('reads back what serializePermissions wrote', () => {
    const sets: Permission[][] = [
      [],
      ['sign_event'],
      ['sign_event:0', 'sign_event:65535'],
      ['sign_event:1', 'sign_event:7', 'nip44_encrypt'],
      [...PERMISSION_METHODS],
    ];
    for (const permissions of sets) {
      expect(deserializePermissions(serializePermissions(permissions))).toEqual(
        permissions,
      );
    }
  });

  it.each<[string, unknown]>([
    ['an empty string', ''],
    ['a bare permission', 'sign_event'],
    ['a comma-separated list', 'sign_event,nip44_encrypt'],
    ['JSON null', 'null'],
    ['a JSON object', '{"0":"sign_event"}'],
    ['a JSON string', '"sign_event"'],
    ['a JSON number', '1'],
    ['a number entry', '[1]'],
    ['a null entry', '[null]'],
    ['a nested array', '[["sign_event"]]'],
    ['all', '["all"]'],
    ['all next to explicit permissions', '["sign_event","all"]'],
    ['a control method', '["ping"]'],
    ['an invalid kind', '["sign_event:01"]'],
    ['a kind out of range', '["sign_event:65536"]'],
    ['duplicates', '["sign_event","sign_event"]'],
    ['methods out of order', '["nip44_encrypt","sign_event"]'],
    ['kinds out of order', '["sign_event:7","sign_event:1"]'],
    ['kinds sorted as text', '["sign_event:10","sign_event:2"]'],
    ['a kind next to sign_event', '["sign_event","sign_event:1"]'],
    ['whitespace inside', '[ "sign_event" ]'],
    ['trailing whitespace', '["sign_event"] '],
    ['a trailing newline', '["sign_event"]\n'],
    ['escaped characters', '["sign\\u005fevent"]'],
    ['invalid JSON', '["sign_event",]'],
    ['truncated JSON', '["sign_event"'],
    ['a SQL NULL', null],
    ['an undefined value', undefined],
    ['a number', 1],
    ['a blob', new TextEncoder().encode('["sign_event"]').buffer],
  ])('rejects %s', (_case, stored) => {
    let caught: unknown;
    try {
      deserializePermissions(stored);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(MalformedPermissionsError);
    expect((caught as Error).message).toBe('Malformed stored permissions');
  });
});
