import { hashPayload } from 'nostr-tools/nip98';
import { describe, expect, it } from 'vitest';
import {
  MAX_AUTHORIZATION_HEADER_LENGTH,
  NIP98_TIME_WINDOW_SECONDS,
  Nip98AuthError,
  type Nip98FailureReason,
  type Nip98Request,
  nip98EventExpiresAt,
  parseNip98Authorization,
  verifyNip98Event,
} from '../src/nip98';
import {
  encodeBase64,
  LOGIN_URL,
  nostrAuthorization,
  ORIGIN,
  randomKey,
  sha256Hex,
  signHttpAuthEvent,
  tamperHex,
} from './nostr-helpers';

const NOW = 1_700_000_000;
const admin = randomKey();
const other = randomKey();
const EMPTY = new Uint8Array();

function request(overrides: Partial<Nip98Request> = {}): Nip98Request {
  return {
    url: LOGIN_URL,
    method: 'POST',
    body: EMPTY,
    pubkey: admin.pubkey,
    now: NOW,
    ...overrides,
  };
}

function loginTags(...extra: string[][]): string[][] {
  return [['u', LOGIN_URL], ['method', 'POST'], ...extra];
}

function eventAt(createdAt: number, tags = loginTags()) {
  return signHttpAuthEvent(admin, { created_at: createdAt, tags });
}

function parseFailure(header: string | undefined): Nip98FailureReason | null {
  try {
    parseNip98Authorization(header);
    return null;
  } catch (error) {
    expect(error).toBeInstanceOf(Nip98AuthError);
    return (error as Nip98AuthError).reason;
  }
}

async function verifyFailure(
  event: Parameters<typeof verifyNip98Event>[0],
  overrides: Partial<Nip98Request> = {},
): Promise<Nip98FailureReason | null> {
  try {
    await verifyNip98Event(event, request(overrides));
    return null;
  } catch (error) {
    expect(error).toBeInstanceOf(Nip98AuthError);
    return (error as Nip98AuthError).reason;
  }
}

function omit(event: Record<string, unknown>, key: string) {
  const copy = { ...event };
  delete copy[key];
  return copy;
}

function base64Json(value: string): string {
  return `Nostr ${encodeBase64(new TextEncoder().encode(value))}`;
}

describe('parseNip98Authorization', () => {
  it('decodes a base64 event from the Nostr scheme', () => {
    const event = eventAt(NOW);
    expect(parseNip98Authorization(nostrAuthorization(event))).toEqual(event);
  });

  it('treats the scheme name case-insensitively', () => {
    const event = eventAt(NOW);
    const encoded = nostrAuthorization(event).slice('Nostr '.length);
    expect(parseNip98Authorization(`nostr ${encoded}`)).toEqual(event);
    expect(parseNip98Authorization(`NOSTR ${encoded}`)).toEqual(event);
  });

  it('reports a missing header', () => {
    expect(parseFailure(undefined)).toBe('missing');
    expect(parseFailure('')).toBe('missing');
  });

  it.each([
    ['another scheme', (encoded: string) => `Bearer ${encoded}`],
    ['no scheme', (encoded: string) => encoded],
    ['no credentials', () => 'Nostr '],
    ['the scheme alone', () => 'Nostr'],
    ['no separator', (encoded: string) => `Nostr${encoded}`],
    ['a tab separator', (encoded: string) => `Nostr\t${encoded}`],
    ['trailing data', (encoded: string) => `Nostr ${encoded} extra`],
    [
      'embedded whitespace',
      (encoded: string) => `Nostr ${encoded.slice(0, 8)} ${encoded.slice(8)}`,
    ],
    [
      'base64url characters',
      (encoded: string) => `Nostr ${encoded.replace(/[A-Z]/, '-')}`,
    ],
    ['missing padding', (encoded: string) => `Nostr ${encoded}A`],
    ['excess padding', () => 'Nostr AAAA===='],
    ['padding in the middle', (encoded: string) => `Nostr AA==${encoded}`],
  ])('rejects %s', (_case, header) => {
    const encoded = nostrAuthorization(eventAt(NOW)).slice('Nostr '.length);
    expect(parseFailure(header(encoded))).toBe('malformed');
  });

  it.each([
    [
      'invalid UTF-8',
      `Nostr ${encodeBase64(new Uint8Array([0x7b, 0xff, 0x7d, 0x00]))}`,
    ],
    ['text that is not JSON', base64Json('not json at all')],
    ['truncated JSON', base64Json('{"kind":27235')],
    ['a JSON array', base64Json('[]')],
    ['JSON null', base64Json('null')],
    ['a JSON string', base64Json('"event"')],
    ['a JSON number', base64Json('27235')],
    ['an empty object', base64Json('{}')],
    [
      'a byte order mark',
      `Nostr ${encodeBase64(new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode(JSON.stringify(eventAt(NOW)))]))}`,
    ],
  ])('rejects %s', (_case, header) => {
    expect(parseFailure(header)).toBe('malformed');
  });

  it.each([
    ['a missing id', (e: Record<string, unknown>) => omit(e, 'id')],
    ['a missing sig', (e: Record<string, unknown>) => omit(e, 'sig')],
    ['a missing pubkey', (e: Record<string, unknown>) => omit(e, 'pubkey')],
    ['a missing kind', (e: Record<string, unknown>) => omit(e, 'kind')],
    [
      'a missing created_at',
      (e: Record<string, unknown>) => omit(e, 'created_at'),
    ],
    ['a missing content', (e: Record<string, unknown>) => omit(e, 'content')],
    ['missing tags', (e: Record<string, unknown>) => omit(e, 'tags')],
    [
      'an uppercase id',
      (e: Record<string, unknown>) => ({
        ...e,
        id: String(e.id).toUpperCase(),
      }),
    ],
    [
      'a short id',
      (e: Record<string, unknown>) => ({ ...e, id: String(e.id).slice(1) }),
    ],
    ['a numeric id', (e: Record<string, unknown>) => ({ ...e, id: 1 })],
    [
      'a short sig',
      (e: Record<string, unknown>) => ({ ...e, sig: String(e.sig).slice(2) }),
    ],
    [
      'a non-hex sig',
      (e: Record<string, unknown>) => ({ ...e, sig: 'z'.repeat(128) }),
    ],
    [
      'an uppercase pubkey',
      (e: Record<string, unknown>) => ({
        ...e,
        pubkey: String(e.pubkey).toUpperCase(),
      }),
    ],
    [
      'a string kind',
      (e: Record<string, unknown>) => ({ ...e, kind: '27235' }),
    ],
    [
      'a fractional kind',
      (e: Record<string, unknown>) => ({ ...e, kind: 27235.5 }),
    ],
    [
      'a fractional created_at',
      (e: Record<string, unknown>) => ({ ...e, created_at: NOW + 0.5 }),
    ],
    [
      'a string created_at',
      (e: Record<string, unknown>) => ({ ...e, created_at: String(NOW) }),
    ],
    [
      'non-string tag values',
      (e: Record<string, unknown>) => ({ ...e, tags: [['u', 1]] }),
    ],
    [
      'tags that are not arrays',
      (e: Record<string, unknown>) => ({ ...e, tags: ['u'] }),
    ],
  ])('rejects an event with %s', (_case, mutate) => {
    const event = mutate({ ...eventAt(NOW) });
    expect(parseFailure(nostrAuthorization(event))).toBe('malformed');
  });

  it(`rejects headers longer than ${MAX_AUTHORIZATION_HEADER_LENGTH} characters`, () => {
    // The header is "Nostr " plus 4 base64 characters per 3 bytes of JSON.
    const maxJsonLength =
      Math.floor((MAX_AUTHORIZATION_HEADER_LENGTH - 'Nostr '.length) / 4) * 3;
    const withContent = (length: number) =>
      signHttpAuthEvent(admin, {
        created_at: NOW,
        content: 'x'.repeat(length),
      });
    const fill = maxJsonLength - JSON.stringify(withContent(0)).length;

    const longest = withContent(fill);
    const longestHeader = nostrAuthorization(longest);
    expect(longestHeader.length).toBeLessThanOrEqual(
      MAX_AUTHORIZATION_HEADER_LENGTH,
    );
    expect(longestHeader.length).toBeGreaterThan(
      MAX_AUTHORIZATION_HEADER_LENGTH - 4,
    );
    expect(parseNip98Authorization(longestHeader)).toEqual(longest);

    const tooLongHeader = nostrAuthorization(withContent(fill + 1));
    expect(tooLongHeader.length).toBeGreaterThan(
      MAX_AUTHORIZATION_HEADER_LENGTH,
    );
    expect(parseFailure(tooLongHeader)).toBe('malformed');
  });

  it('keeps a typical login header far below the limit', async () => {
    const event = eventAt(NOW, loginTags(['payload', await sha256Hex('{}')]));
    expect(nostrAuthorization(event).length).toBeLessThan(
      MAX_AUTHORIZATION_HEADER_LENGTH / 4,
    );
  });
});

describe('verifyNip98Event', () => {
  it('accepts an event that authorizes exactly this request', async () => {
    expect(await verifyFailure(eventAt(NOW))).toBeNull();
  });

  it('rejects another kind', async () => {
    const event = signHttpAuthEvent(admin, { kind: 1, created_at: NOW });
    expect(await verifyFailure(event)).toBe('kind');
  });

  it('rejects an event signed by another pubkey', async () => {
    const event = signHttpAuthEvent(other, { created_at: NOW });
    expect(await verifyFailure(event)).toBe('pubkey');
  });

  it(`accepts created_at less than ${NIP98_TIME_WINDOW_SECONDS} seconds away`, async () => {
    for (const offset of [-59, -1, 0, 1, 59]) {
      expect(await verifyFailure(eventAt(NOW + offset))).toBeNull();
    }
  });

  it('rejects created_at too far in the past', async () => {
    for (const offset of [-60, -61, -3600]) {
      expect(await verifyFailure(eventAt(NOW + offset))).toBe('created_at');
    }
  });

  it('rejects created_at too far in the future', async () => {
    for (const offset of [60, 61, 3600]) {
      expect(await verifyFailure(eventAt(NOW + offset))).toBe('created_at');
    }
  });

  it.each([
    ['another host', 'https://other.example/admin/api/login'],
    ['another scheme', 'http://signflare.example/admin/api/login'],
    ['an explicit port', 'https://signflare.example:8443/admin/api/login'],
    ['a path only', '/admin/api/login'],
    ['another path', `${ORIGIN}/admin/api/logout`],
    ['a trailing slash', `${LOGIN_URL}/`],
    ['an added query', `${LOGIN_URL}?next=1`],
    ['an empty query', `${LOGIN_URL}?`],
    ['a fragment', `${LOGIN_URL}#login`],
    ['different letter case', LOGIN_URL.toUpperCase()],
  ])('rejects a u tag with %s', async (_case, url) => {
    const event = eventAt(NOW, [
      ['u', url],
      ['method', 'POST'],
    ]);
    expect(await verifyFailure(event)).toBe('url');
  });

  it('compares the query component of the request URL too', async () => {
    const url = `${LOGIN_URL}?next=1`;
    const event = eventAt(NOW, [
      ['u', url],
      ['method', 'POST'],
    ]);
    expect(await verifyFailure(event, { url })).toBeNull();
    expect(await verifyFailure(event, { url: `${LOGIN_URL}?next=2` })).toBe(
      'url',
    );
    expect(await verifyFailure(eventAt(NOW), { url })).toBe('url');
  });

  it('rejects a missing or duplicated u tag', async () => {
    expect(await verifyFailure(eventAt(NOW, [['method', 'POST']]))).toBe('url');
    expect(await verifyFailure(eventAt(NOW, [['u'], ['method', 'POST']]))).toBe(
      'url',
    );
    expect(await verifyFailure(eventAt(NOW, loginTags(['u', LOGIN_URL])))).toBe(
      'url',
    );
  });

  it.each(['GET', 'post', 'PUT', ''])(
    'rejects a method tag of %j',
    async (method) => {
      const event = eventAt(NOW, [
        ['u', LOGIN_URL],
        ['method', method],
      ]);
      expect(await verifyFailure(event)).toBe('method');
    },
  );

  it('rejects a missing or duplicated method tag', async () => {
    expect(await verifyFailure(eventAt(NOW, [['u', LOGIN_URL]]))).toBe(
      'method',
    );
    expect(
      await verifyFailure(eventAt(NOW, loginTags(['method', 'POST']))),
    ).toBe('method');
  });

  it('requires a payload tag when the request has a body', async () => {
    const body = new TextEncoder().encode('{}');
    expect(await verifyFailure(eventAt(NOW), { body })).toBe('payload');
  });

  it('accepts a payload tag with the SHA-256 of the raw body', async () => {
    const raw = '{ "note":  "bytes as sent" }\n';
    const body = new TextEncoder().encode(raw);
    const event = eventAt(NOW, loginTags(['payload', await sha256Hex(raw)]));
    expect(await verifyFailure(event, { body })).toBeNull();
  });

  it('accepts a binary body', async () => {
    const body = crypto.getRandomValues(new Uint8Array(64));
    const event = eventAt(NOW, loginTags(['payload', await sha256Hex(body)]));
    expect(await verifyFailure(event, { body })).toBeNull();
  });

  it('rejects a payload hash of a re-serialized body', async () => {
    const raw = '{"note": "spaced"}';
    // nostr-tools hashes JSON.stringify of the value, not the bytes sent.
    const reserialized = hashPayload(JSON.parse(raw));
    expect(reserialized).not.toBe(await sha256Hex(raw));
    const event = eventAt(NOW, loginTags(['payload', reserialized]));
    expect(
      await verifyFailure(event, { body: new TextEncoder().encode(raw) }),
    ).toBe('payload');
  });

  it('rejects a payload tag that does not match the body', async () => {
    const body = new TextEncoder().encode('{"a":1}');
    for (const payload of [
      await sha256Hex('{"a":2}'),
      tamperHex(await sha256Hex(body)),
      (await sha256Hex(body)).toUpperCase(),
      '',
    ]) {
      const event = eventAt(NOW, loginTags(['payload', payload]));
      expect(await verifyFailure(event, { body })).toBe('payload');
    }
    expect(
      await verifyFailure(eventAt(NOW, loginTags(['payload'])), { body }),
    ).toBe('payload');
  });

  it('rejects duplicated payload tags', async () => {
    const body = new TextEncoder().encode('{}');
    const hash = await sha256Hex(body);
    const event = eventAt(NOW, loginTags(['payload', hash], ['payload', hash]));
    expect(await verifyFailure(event, { body })).toBe('payload');
  });

  it('checks a payload tag against an empty body', async () => {
    const empty = eventAt(NOW, loginTags(['payload', await sha256Hex('')]));
    expect(await verifyFailure(empty)).toBeNull();
    const nonEmpty = eventAt(
      NOW,
      loginTags(['payload', await sha256Hex('{}')]),
    );
    expect(await verifyFailure(nonEmpty)).toBe('payload');
  });

  it('rejects an invalid signature', async () => {
    const event = eventAt(NOW);
    expect(
      await verifyFailure({ ...event, sig: tamperHex(event.sig, 10) }),
    ).toBe('signature');
    const foreign = signHttpAuthEvent(other, { created_at: NOW });
    expect(await verifyFailure({ ...event, sig: foreign.sig })).toBe(
      'signature',
    );
  });

  it('rejects an id that is not the hash of the event', async () => {
    const event = eventAt(NOW);
    expect(await verifyFailure({ ...event, id: tamperHex(event.id) })).toBe(
      'signature',
    );
    // A content change keeps the original id and signature.
    expect(await verifyFailure({ ...event, content: 'changed' })).toBe(
      'signature',
    );
  });

  it('rejects a valid signature over a different event', async () => {
    const event = eventAt(NOW);
    const sibling = eventAt(NOW + 1);
    expect(
      await verifyFailure({ ...event, id: sibling.id, sig: sibling.sig }),
    ).toBe('signature');
  });
});

describe('nip98EventExpiresAt', () => {
  it('is the first second outside the authentication window', async () => {
    const event = eventAt(NOW);
    const expiresAt = nip98EventExpiresAt(event);
    expect(expiresAt).toBe(NOW + NIP98_TIME_WINDOW_SECONDS);
    expect(await verifyFailure(event, { now: expiresAt - 1 })).toBeNull();
    expect(await verifyFailure(event, { now: expiresAt })).toBe('created_at');
  });

  it('covers events dated in the future', async () => {
    const event = eventAt(NOW + 30);
    expect(await verifyFailure(event)).toBeNull();
    expect(nip98EventExpiresAt(event)).toBe(NOW + 90);
    expect(
      await verifyFailure(event, { now: nip98EventExpiresAt(event) - 1 }),
    ).toBeNull();
  });
});

describe('Nip98AuthError', () => {
  it('does not echo the authorization', () => {
    const header = nostrAuthorization(eventAt(NOW));
    try {
      parseNip98Authorization(`${header}!`);
      expect.unreachable();
    } catch (error) {
      expect((error as Error).message).toBe('Invalid NIP-98 authorization');
      expect(String((error as Error).stack)).not.toContain(header.slice(6, 40));
    }
  });
});
