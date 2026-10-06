import { afterEach, describe, expect, it, vi } from 'vitest';
import { copyText } from '../../admin/lib/clipboard';

const BUNKER_URL = `bunker://${'e'.repeat(64)}?relay=wss%3A%2F%2Fsignflare.example%2F&secret=${'5'.repeat(64)}`;

afterEach(() => {
  vi.restoreAllMocks();
});

describe('copyText', () => {
  it('writes the text to the clipboard', async () => {
    const writeText = vi.fn(async () => {});
    expect(await copyText({ writeText }, BUNKER_URL)).toBe(true);
    expect(writeText).toHaveBeenCalledExactlyOnceWith(BUNKER_URL);
  });

  it('reports a failure without throwing or logging the text', async () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map(
      (method) => vi.spyOn(console, method).mockImplementation(() => {}),
    );
    const writeText = vi.fn(() =>
      Promise.reject(
        new DOMException(`Write of ${BUNKER_URL} denied`, 'NotAllowedError'),
      ),
    );
    expect(await copyText({ writeText }, BUNKER_URL)).toBe(false);
    for (const spy of spies) {
      expect(spy).not.toHaveBeenCalled();
    }
  });

  it('reports a missing clipboard as a failure', async () => {
    expect(await copyText(undefined, BUNKER_URL)).toBe(false);
  });
});
