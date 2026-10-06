import { finalizeEvent } from 'nostr-tools/pure';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  encodeBase64,
  HTTP_AUTH_KIND,
  InvalidSignedEventError,
  loginEventTemplate,
  loginUrl,
  type Nip07Signer,
  NoSignerError,
  nostrAuthorization,
  type SignedEvent,
  signLoginEvent,
  SignerRejectedError,
  unixNow,
} from '../../admin/lib/nip98';
import { parseNip98Authorization, verifyNip98Event } from '../../src/nip98';
import { randomKey } from '../nostr-helpers';
import { LOGIN_URL, nip07Signer, ORIGIN } from './fake-server';

const admin = randomKey();
const NOW = 1_800_000_000;

function decodeAuthorization(header: string): unknown {
  const bytes = Uint8Array.from(atob(header.replace(/^Nostr /, '')), (c) =>
    c.charCodeAt(0),
  );
  return JSON.parse(new TextDecoder().decode(bytes));
}

function consoleSpies() {
  return (['log', 'info', 'warn', 'error', 'debug'] as const).map((method) =>
    vi.spyOn(console, method).mockImplementation(() => {}),
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('loginUrl', () => {
  it.each([
    [`${ORIGIN}/admin/`, LOGIN_URL],
    [`${ORIGIN}/admin`, LOGIN_URL],
    [`${ORIGIN}/admin/identities/x?tab=1#top`, LOGIN_URL],
    ['http://localhost:5173/admin/', 'http://localhost:5173/admin/api/login'],
    [
      'https://SIGNFLARE.Example:8443/admin/',
      'https://signflare.example:8443/admin/api/login',
    ],
  ])('is absolute and same-origin for %s', (page, expected) => {
    expect(loginUrl(page)).toBe(expected);
    expect(new URL(loginUrl(page)).origin).toBe(new URL(page).origin);
  });
});

describe('loginEventTemplate', () => {
  it('is the NIP-98 event for POST /admin/api/login without a body', () => {
    expect(loginEventTemplate(LOGIN_URL, NOW)).toStrictEqual({
      kind: 27235,
      created_at: NOW,
      tags: [
        ['u', LOGIN_URL],
        ['method', 'POST'],
      ],
      content: '',
    });
    expect(HTTP_AUTH_KIND).toBe(27235);
  });

  it('has no payload tag', () => {
    const { tags } = loginEventTemplate(LOGIN_URL, NOW);
    expect(tags.map(([name]) => name)).toEqual(['u', 'method']);
  });

  it('is signed with the current Unix time in seconds', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW * 1000 + 999);
    expect(unixNow()).toBe(NOW);
    const signEvent = vi.fn(nip07Signer(admin).signEvent);
    await signLoginEvent({ signEvent }, LOGIN_URL, unixNow());
    expect(signEvent).toHaveBeenCalledWith(loginEventTemplate(LOGIN_URL, NOW));
  });
});

describe('signLoginEvent', () => {
  it('asks the NIP-07 signer to sign exactly the login template', async () => {
    const signEvent = vi.fn(nip07Signer(admin).signEvent);
    const event = await signLoginEvent({ signEvent }, LOGIN_URL, NOW);
    expect(signEvent).toHaveBeenCalledTimes(1);
    expect(signEvent).toHaveBeenCalledWith({
      kind: 27235,
      created_at: NOW,
      tags: [
        ['u', LOGIN_URL],
        ['method', 'POST'],
      ],
      content: '',
    });
    expect(event).toMatchObject({
      pubkey: admin.pubkey,
      kind: 27235,
      created_at: NOW,
      content: '',
      tags: [
        ['u', LOGIN_URL],
        ['method', 'POST'],
      ],
    });
  });

  it('produces an Authorization header that the server accepts', async () => {
    const event = await signLoginEvent(
      nip07Signer(admin),
      LOGIN_URL,
      unixNow(),
    );
    const header = nostrAuthorization(event);
    expect(header).toMatch(/^Nostr [A-Za-z0-9+/]+={0,2}$/);
    const parsed = parseNip98Authorization(header);
    expect(parsed).toStrictEqual(event);
    await expect(
      verifyNip98Event(parsed, {
        url: LOGIN_URL,
        method: 'POST',
        body: new Uint8Array(),
        pubkey: admin.pubkey,
        now: unixNow(),
      }),
    ).resolves.toBeUndefined();
  });

  it('sends only the NIP-01 fields that the signer returns', async () => {
    const signer: Nip07Signer = {
      signEvent: async (template) => ({
        ...finalizeEvent({ ...template }, admin.secretKey),
        extension: { session: 'internal' },
      }),
    };
    const event = await signLoginEvent(signer, LOGIN_URL, NOW);
    expect(
      Object.keys(
        decodeAuthorization(nostrAuthorization(event)) as object,
      ).sort(),
    ).toEqual(['content', 'created_at', 'id', 'kind', 'pubkey', 'sig', 'tags']);
  });

  it.each<[string, Nip07Signer | undefined]>([
    ['no window.nostr', undefined],
    ['window.nostr without signEvent', {} as Nip07Signer],
    [
      'window.nostr whose signEvent is not a function',
      { signEvent: 'nope' } as unknown as Nip07Signer,
    ],
  ])('requires a NIP-07 signer: %s', async (_case, signer) => {
    await expect(signLoginEvent(signer, LOGIN_URL, NOW)).rejects.toBeInstanceOf(
      NoSignerError,
    );
  });

  it('reports a rejected signature without what the signer threw', async () => {
    const spies = consoleSpies();
    const thrown = new Error(`User rejected ${LOGIN_URL} for ${admin.pubkey}`);
    const result = signLoginEvent(
      { signEvent: () => Promise.reject(thrown) },
      LOGIN_URL,
      NOW,
    );
    await expect(result).rejects.toBeInstanceOf(SignerRejectedError);
    const error = await result.catch((caught: unknown) => caught);
    expect(String(error)).not.toContain(admin.pubkey);
    expect((error as Error).cause).toBeUndefined();
    for (const spy of spies) {
      expect(spy).not.toHaveBeenCalled();
    }
  });

  it('treats a signer that throws synchronously as a rejection', async () => {
    const signer: Nip07Signer = {
      signEvent: () => {
        throw new Error('locked');
      },
    };
    await expect(signLoginEvent(signer, LOGIN_URL, NOW)).rejects.toBeInstanceOf(
      SignerRejectedError,
    );
  });

  it.each<[string, (event: SignedEvent) => unknown]>([
    ['nothing', () => undefined],
    ['a string', (event) => JSON.stringify(event)],
    [
      'no signature',
      (event) => {
        const unsigned: Record<string, unknown> = { ...event };
        delete unsigned.sig;
        return unsigned;
      },
    ],
    ['a malformed id', (event) => ({ ...event, id: 'x' })],
    [
      'an uppercase pubkey',
      (event) => ({ ...event, pubkey: event.pubkey.toUpperCase() }),
    ],
    ['another kind', (event) => ({ ...event, kind: 1 })],
    [
      'another time',
      (event) => ({ ...event, created_at: event.created_at + 1 }),
    ],
    ['content', (event) => ({ ...event, content: 'x' })],
    [
      'another u tag',
      (event) => ({
        ...event,
        tags: [
          ['u', `${ORIGIN}/admin/api/identities`],
          ['method', 'POST'],
        ],
      }),
    ],
    [
      'a payload tag',
      (event) => ({ ...event, tags: [...event.tags, ['payload', 'e3b0']] }),
    ],
    [
      'tags in another order',
      (event) => ({ ...event, tags: [...event.tags].reverse() }),
    ],
  ])('rejects a signer that returns %s', async (_case, change) => {
    const signer: Nip07Signer = {
      signEvent: async (template) =>
        change(finalizeEvent({ ...template }, admin.secretKey) as SignedEvent),
    };
    await expect(signLoginEvent(signer, LOGIN_URL, NOW)).rejects.toBeInstanceOf(
      InvalidSignedEventError,
    );
  });

  it('is not affected by a signer that changes the object it is given', async () => {
    const signer: Nip07Signer = {
      signEvent: async (template) => {
        (template.tags as string[][]).push(['client', 'extension']);
        return finalizeEvent({ ...template }, admin.secretKey);
      },
    };
    await expect(signLoginEvent(signer, LOGIN_URL, NOW)).rejects.toBeInstanceOf(
      InvalidSignedEventError,
    );
  });
});

describe('nostrAuthorization', () => {
  it('base64-encodes the UTF-8 JSON of the event', async () => {
    const event = await signLoginEvent(nip07Signer(admin), LOGIN_URL, NOW);
    const header = nostrAuthorization(event);
    expect(header.startsWith('Nostr ')).toBe(true);
    expect(decodeAuthorization(header)).toStrictEqual(event);
  });

  it('keeps characters beyond Latin-1 intact', async () => {
    const event = finalizeEvent(
      {
        kind: 27235,
        created_at: unixNow(),
        tags: [
          ['u', LOGIN_URL],
          ['method', 'POST'],
          ['t', 'ü日本語🔑'],
        ],
        content: 'こんにちは 🔑',
      },
      admin.secretKey,
    );
    const signed = JSON.parse(JSON.stringify(event)) as SignedEvent;
    const header = nostrAuthorization(signed);
    expect(decodeAuthorization(header)).toStrictEqual(signed);
    // The server decodes it to the same, validly signed event.
    expect(parseNip98Authorization(header)).toStrictEqual(signed);
  });
});

describe('encodeBase64', () => {
  it('encodes bytes rather than text', () => {
    expect(encodeBase64(new TextEncoder().encode('ü日本語🔑'))).toBe(
      'w7zml6XmnKzoqp7wn5SR',
    );
    expect(
      encodeBase64(
        new TextEncoder().encode(JSON.stringify({ content: 'こんにちは 🔑' })),
      ),
    ).toBe('eyJjb250ZW50Ijoi44GT44KT44Gr44Gh44GvIPCflJEifQ==');
    expect(encodeBase64(new Uint8Array())).toBe('');
  });

  it('encodes input larger than one chunk', () => {
    const bytes = Uint8Array.from({ length: 100_003 }, (_, i) => (i * 7) % 256);
    const decoded = Uint8Array.from(atob(encodeBase64(bytes)), (c) =>
      c.charCodeAt(0),
    );
    expect(decoded).toEqual(bytes);
  });
});
