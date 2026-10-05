import { describe, expect, it } from 'vitest';
import { relayUrl } from '../src/relay-url';

const PAIRINGS_PATH = `/admin/api/identities/${'ab'.repeat(32)}/pairings`;

describe('relayUrl', () => {
  it.each<[string, string]>([
    [`https://example.com${PAIRINGS_PATH}`, 'wss://example.com/'],
    [`http://localhost:5173${PAIRINGS_PATH}`, 'ws://localhost:5173/'],
    [`https://example.com:8443${PAIRINGS_PATH}`, 'wss://example.com:8443/'],
    [`http://127.0.0.1:8787${PAIRINGS_PATH}`, 'ws://127.0.0.1:8787/'],
    [`http://[::1]:8787${PAIRINGS_PATH}`, 'ws://[::1]:8787/'],
    [`https://signer.example.com${PAIRINGS_PATH}`, 'wss://signer.example.com/'],
    ['https://example.com/', 'wss://example.com/'],
    ['https://example.com', 'wss://example.com/'],
  ])('derives the relay URL of %s', (requestUrl, expected) => {
    expect(relayUrl(requestUrl)).toBe(expected);
  });

  it('keeps an explicit port and drops a default one', () => {
    expect(relayUrl('https://example.com:443/a')).toBe('wss://example.com/');
    expect(relayUrl('http://example.com:80/a')).toBe('ws://example.com/');
    expect(relayUrl('http://example.com:443/a')).toBe('ws://example.com:443/');
    expect(relayUrl('https://example.com:80/a')).toBe('wss://example.com:80/');
  });

  it('leaves out the path, query, and fragment', () => {
    const relay = relayUrl(
      `https://example.com${PAIRINGS_PATH}?relay=wss%3A%2F%2Fevil.example%2F&x=1#fragment`,
    );
    expect(relay).toBe('wss://example.com/');
    const { pathname, search, hash } = new URL(relay);
    expect([pathname, search, hash]).toEqual(['/', '', '']);
  });

  it('leaves out credentials', () => {
    expect(relayUrl('https://user:password@example.com/a')).toBe(
      'wss://example.com/',
    );
  });

  it('uses the host as the URL parser normalizes it', () => {
    expect(relayUrl('https://EXAMPLE.com/a')).toBe('wss://example.com/');
  });

  it.each<[string, string]>([
    ['ws:', 'ws://example.com/'],
    ['wss:', 'wss://example.com/'],
    ['ftp:', 'ftp://example.com/a'],
    ['file:', 'file:///admin/api/identities'],
    ['data:', 'data:text/plain,hello'],
    ['blob:', 'blob:https://example.com/0f1e'],
    ['bunker:', `bunker://${'ab'.repeat(32)}`],
    ['javascript:', 'javascript:void(0)'],
  ])('rejects the %s protocol', (_protocol, requestUrl) => {
    expect(() => relayUrl(requestUrl)).toThrow(TypeError);
    expect(() => relayUrl(requestUrl)).toThrow(
      'Request URL is neither http: nor https:',
    );
  });

  it.each(['', PAIRINGS_PATH, 'example.com', 'https://'])(
    'rejects %j, which is not an absolute URL',
    (value) => {
      expect(() => relayUrl(value)).toThrow(TypeError);
    },
  );
});
