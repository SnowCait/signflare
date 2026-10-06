import { describe, expect, it } from 'vitest';
import {
  MAX_EVENT_KIND,
  pairingPermissions,
  parseEventKinds,
  PERMISSION_METHODS,
  type PermissionSelection,
} from '../../admin/lib/permissions';
import { parsePairingPermissions } from '../../src/permissions';

function explicit(
  methods: PermissionSelection['methods'],
  kinds = '',
): PermissionSelection {
  return { mode: 'explicit', methods, kinds };
}

describe('pairingPermissions', () => {
  it('sends "all" for all permissions', () => {
    expect(pairingPermissions({ mode: 'all', methods: [], kinds: '' })).toEqual(
      {
        ok: true,
        permissions: 'all',
      },
    );
    // Whatever else was selected before switching to "all".
    expect(
      pairingPermissions({
        mode: 'all',
        methods: ['nip04_encrypt'],
        kinds: 'x',
      }),
    ).toEqual({ ok: true, permissions: 'all' });
  });

  it('sends explicit method permissions', () => {
    expect(
      pairingPermissions(explicit(['nip44_decrypt', 'nip04_encrypt'])),
    ).toEqual({
      ok: true,
      permissions: ['nip04_encrypt', 'nip44_decrypt'],
    });
    expect(pairingPermissions(explicit([...PERMISSION_METHODS]))).toEqual({
      ok: true,
      permissions: [...PERMISSION_METHODS],
    });
  });

  it('sends sign_event:<kind> for each valid kind, without duplicates', () => {
    expect(
      pairingPermissions(explicit(['nip44_encrypt'], '7, 1 30023,1')),
    ).toEqual({
      ok: true,
      permissions: [
        'sign_event:1',
        'sign_event:7',
        'sign_event:30023',
        'nip44_encrypt',
      ],
    });
    expect(pairingPermissions(explicit([], `0 ${MAX_EVENT_KIND}`))).toEqual({
      ok: true,
      permissions: ['sign_event:0', 'sign_event:65535'],
    });
  });

  it('leaves kinds out when sign_event covers every kind', () => {
    expect(
      pairingPermissions(explicit(['sign_event', 'nip04_decrypt'], '1, 7')),
    ).toEqual({ ok: true, permissions: ['sign_event', 'nip04_decrypt'] });
    // Even malformed kinds, which are not used.
    expect(pairingPermissions(explicit(['sign_event'], 'abc'))).toEqual({
      ok: true,
      permissions: ['sign_event'],
    });
  });

  it('removes duplicate methods', () => {
    expect(
      pairingPermissions(explicit(['nip04_encrypt', 'nip04_encrypt'])),
    ).toEqual({ ok: true, permissions: ['nip04_encrypt'] });
  });

  it('allows an empty selection, which the server accepts as no grant', () => {
    const result = pairingPermissions(explicit([], ' , '));
    expect(result).toEqual({ ok: true, permissions: [] });
    if (result.ok) {
      // No sign_event, NIP-04, or NIP-44 permission. The control methods of
      // docs/design.md §16.2 need none.
      expect(parsePairingPermissions(result.permissions)).toEqual([]);
    }
  });

  it.each([
    '-1',
    '65536',
    '100000',
    '1.5',
    '1e3',
    '01',
    '0x10',
    'abc',
    '１',
    '1;2',
    'sign_event:1',
    '9'.repeat(400),
  ])('rejects the kind %s before any request', (kind) => {
    const result = pairingPermissions(
      explicit(['nip44_encrypt'], `1, ${kind}`),
    );
    expect(result).toMatchObject({ ok: false });
    if (!result.ok) {
      expect(result.error).toContain('0 to 65535');
    }
  });

  it('only produces permissions that the server accepts', () => {
    const selections: PermissionSelection[] = [
      explicit([...PERMISSION_METHODS], '1'),
      explicit(['nip04_encrypt', 'nip44_decrypt'], '0, 7, 65535'),
      explicit([], '30023'),
      explicit([]),
    ];
    for (const selection of selections) {
      const result = pairingPermissions(selection);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(() => parsePairingPermissions(result.permissions)).not.toThrow();
      }
    }
  });
});

describe('parseEventKinds', () => {
  it('parses kinds separated by commas or whitespace', () => {
    expect(parseEventKinds('')).toEqual({ ok: true, kinds: [] });
    expect(parseEventKinds(' 3,\t1\n2 ,, 3 ')).toEqual({
      ok: true,
      kinds: [1, 2, 3],
    });
  });

  it('names the first invalid kind', () => {
    expect(parseEventKinds('1, 70000, -2')).toEqual({
      ok: false,
      error: '"70000" is not an event kind: use whole numbers from 0 to 65535.',
    });
  });
});
