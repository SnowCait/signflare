import type { PairingPermissions } from './types';

// Pairing permissions chosen in the Admin UI (docs/design.md §16). This only
// catches mistakes before the request: the server validates permissions
// itself and is the authority on what a session may do.

export const PERMISSION_METHODS = [
  'sign_event',
  'nip04_encrypt',
  'nip04_decrypt',
  'nip44_encrypt',
  'nip44_decrypt',
] as const;

export type PermissionMethod = (typeof PERMISSION_METHODS)[number];

export const MAX_EVENT_KIND = 65_535;

export interface PermissionSelection {
  readonly mode: 'all' | 'explicit';
  // Methods granted in full. sign_event grants every event kind.
  readonly methods: readonly PermissionMethod[];
  // Event kinds for sign_event:<kind>, as typed: separated by commas or
  // whitespace.
  readonly kinds: string;
}

export type PermissionSelectionResult =
  | { readonly ok: true; readonly permissions: PairingPermissions }
  | { readonly ok: false; readonly error: string };

export type EventKindsResult =
  | { readonly ok: true; readonly kinds: number[] }
  | { readonly ok: false; readonly error: string };

// Decimal digits only, without a leading zero, as the server requires.
const EVENT_KIND = /^(0|[1-9][0-9]*)$/;

// The request value for a selection: "all", or the selected permissions
// without duplicates. sign_event:<kind> entries are left out when
// sign_event is selected, since it covers every kind.
export function pairingPermissions(
  selection: PermissionSelection,
): PermissionSelectionResult {
  if (selection.mode === 'all') {
    return { ok: true, permissions: 'all' };
  }
  const methods = PERMISSION_METHODS.filter((method) =>
    selection.methods.includes(method),
  );
  if (methods.includes('sign_event')) {
    return { ok: true, permissions: methods };
  }
  const kinds = parseEventKinds(selection.kinds);
  if (!kinds.ok) {
    return kinds;
  }
  return {
    ok: true,
    permissions: [
      ...kinds.kinds.map((kind) => `sign_event:${kind}`),
      ...methods,
    ],
  };
}

// Distinct event kinds in ascending order. Empty input yields no kinds.
export function parseEventKinds(text: string): EventKindsResult {
  const kinds = new Set<number>();
  for (const token of text.split(/[\s,]+/)) {
    if (token === '') {
      continue;
    }
    const kind = EVENT_KIND.test(token) ? Number(token) : Number.NaN;
    if (!(kind <= MAX_EVENT_KIND)) {
      return {
        ok: false,
        error: `"${token}" is not an event kind: use whole numbers from 0 to ${MAX_EVENT_KIND}.`,
      };
    }
    kinds.add(kind);
  }
  return { ok: true, kinds: [...kinds].sort((a, b) => a - b) };
}
