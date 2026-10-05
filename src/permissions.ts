// Session permissions (docs/design.md §16).
//
// Permission sets are handled in one canonical form: explicit v1 permissions
// only, without duplicates and without sign_event:<kind> entries that
// sign_event already covers, in PERMISSION_METHODS order with kinds ascending.
// Pairings and sessions store that form through serializePermissions().

export const PERMISSION_METHODS = [
  'sign_event',
  'nip04_encrypt',
  'nip04_decrypt',
  'nip44_encrypt',
  'nip44_decrypt',
] as const;

export type PermissionMethod = (typeof PERMISSION_METHODS)[number];

// sign_event grants every event kind, sign_event:<kind> only that kind.
export type Permission = PermissionMethod | `sign_event:${number}`;

// Admin API and UI convenience value for all of PERMISSION_METHODS. It is
// expanded before anything is stored and not accepted from NIP-46 clients.
export const ALL_PERMISSIONS = 'all';

// NIP-01 event kinds are integers between 0 and 65535.
export const MAX_EVENT_KIND = 65_535;

// Plain decimal digits only: no sign, leading zero, fraction, exponent, or
// whitespace, so that every kind has exactly one spelling.
const SIGN_EVENT_KIND = /^sign_event:(0|[1-9][0-9]{0,4})$/;

// The message never echoes the rejected input.
export class InvalidPermissionError extends Error {
  constructor() {
    super('Invalid permission');
    this.name = 'InvalidPermissionError';
  }
}

// A stored permission set that serializePermissions() did not write. It is
// never read as a smaller or empty grant.
export class MalformedPermissionsError extends Error {
  constructor() {
    super('Malformed stored permissions');
    this.name = 'MalformedPermissionsError';
  }
}

// Validates explicit permissions and returns their canonical form. Throws
// InvalidPermissionError for anything else, including "all".
export function canonicalizePermissions(
  permissions: readonly unknown[],
): Permission[] {
  const methods = new Set<PermissionMethod>();
  const kinds = new Set<number>();
  for (const permission of permissions) {
    if (isPermissionMethod(permission)) {
      methods.add(permission);
      continue;
    }
    const kind = signEventKind(permission);
    if (kind === null) {
      throw new InvalidPermissionError();
    }
    kinds.add(kind);
  }

  const canonical: Permission[] = [];
  for (const method of PERMISSION_METHODS) {
    if (methods.has(method)) {
      canonical.push(method);
    } else if (method === 'sign_event') {
      for (const kind of [...kinds].sort((a, b) => a - b)) {
        canonical.push(`sign_event:${kind}`);
      }
    }
  }
  return canonical;
}

// Administrator input (docs/design.md §30.8): "all", or an array of explicit
// permissions in which "all" may also appear.
export function parsePairingPermissions(input: unknown): Permission[] {
  if (input === ALL_PERMISSIONS) {
    return [...PERMISSION_METHODS];
  }
  if (!Array.isArray(input)) {
    throw new InvalidPermissionError();
  }
  return canonicalizePermissions(
    input.flatMap((permission: unknown) =>
      permission === ALL_PERMISSIONS ? PERMISSION_METHODS : [permission],
    ),
  );
}

// The optional_requested_perms parameter of NIP-46 connect: a comma-separated
// list of method[:params]. Clients that only need to pass client metadata
// send an empty string in its place, so an empty value means the same as an
// omitted one: no request, returned as null, and the session receives the
// pairing permissions (docs/design.md §16.1).
export function parseRequestedPermissions(
  requested: unknown,
): Permission[] | null {
  if (requested === undefined || requested === '') {
    return null;
  }
  if (typeof requested !== 'string') {
    throw new InvalidPermissionError();
  }
  return canonicalizePermissions(requested.split(','));
}

// Deny by default: only a valid explicit permission can be granted, either by
// the same permission or, for sign_event:<kind>, by sign_event.
export function isPermitted(
  granted: readonly Permission[],
  permission: string,
): boolean {
  const permissions: readonly string[] = granted;
  if (isPermissionMethod(permission)) {
    return permissions.includes(permission);
  }
  return (
    signEventKind(permission) !== null &&
    (permissions.includes(permission) || permissions.includes('sign_event'))
  );
}

// Everything both sets grant (docs/design.md §16.1). A sign_event:<kind> in
// one set is kept when the other has the same kind or sign_event, so
// sign_event and sign_event:1 intersect to sign_event:1.
export function intersectPermissions(
  a: readonly Permission[],
  b: readonly Permission[],
): Permission[] {
  return canonicalizePermissions([
    ...a.filter((permission) => isPermitted(b, permission)),
    ...b.filter((permission) => isPermitted(a, permission)),
  ]);
}

// The stored representation shared by pairings and sessions: the canonical
// set as a JSON array, for example ["sign_event:1","nip44_encrypt"].
export function serializePermissions(
  permissions: readonly Permission[],
): string {
  return JSON.stringify(canonicalizePermissions(permissions));
}

// Accepts exactly what serializePermissions() writes.
export function deserializePermissions(stored: unknown): Permission[] {
  if (typeof stored === 'string') {
    try {
      const parsed: unknown = JSON.parse(stored);
      if (Array.isArray(parsed)) {
        const permissions = canonicalizePermissions(parsed);
        if (JSON.stringify(permissions) === stored) {
          return permissions;
        }
      }
    } catch {
      // Not JSON or not valid permissions; reported below.
    }
  }
  throw new MalformedPermissionsError();
}

function isPermissionMethod(value: unknown): value is PermissionMethod {
  return (PERMISSION_METHODS as readonly unknown[]).includes(value);
}

function signEventKind(value: unknown): number | null {
  if (typeof value !== 'string') {
    return null;
  }
  const digits = SIGN_EVENT_KIND.exec(value)?.[1];
  if (digits === undefined) {
    return null;
  }
  const kind = Number(digits);
  return kind <= MAX_EVENT_KIND ? kind : null;
}
