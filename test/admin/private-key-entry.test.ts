import { describe, expect, it, vi } from 'vitest';
import {
  hasPrivateKeyInput,
  type PrivateKeyField,
  submitPrivateKey,
} from '../../admin/lib/private-key-entry';

const PRIVATE_KEY =
  'nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsmhltgl';

// The form state of the registration form, as the Svelte component keeps it.
function field(initial: string): PrivateKeyField & { value: string } {
  return {
    value: initial,
    read() {
      return this.value;
    },
    clear() {
      this.value = '';
    },
  };
}

describe('submitPrivateKey', () => {
  it('passes the key to the request only, with the field already cleared', async () => {
    const form = field(PRIVATE_KEY);
    const register = vi.fn(async (privateKey: string) => {
      expect(form.value).toBe('');
      return privateKey.length;
    });
    expect(await submitPrivateKey(form, register)).toBe(PRIVATE_KEY.length);
    expect(register).toHaveBeenCalledExactlyOnceWith(PRIVATE_KEY);
  });

  it('leaves the field empty after the request succeeds', async () => {
    const form = field(PRIVATE_KEY);
    await submitPrivateKey(form, async () => ({ ok: true }));
    expect(form.value).toBe('');
  });

  it('leaves the field empty after the request fails', async () => {
    const form = field(PRIVATE_KEY);
    await submitPrivateKey(form, async () => ({
      ok: false,
      message: 'invalid',
    }));
    expect(form.value).toBe('');
  });

  it('leaves the field empty when the request throws', async () => {
    const form = field(PRIVATE_KEY);
    await expect(
      submitPrivateKey(form, async () => {
        form.value = 'typed while pending';
        throw new Error('network');
      }),
    ).rejects.toThrow('network');
    expect(form.value).toBe('');
  });
});

describe('hasPrivateKeyInput', () => {
  it.each([
    ['', false],
    ['   \n\t', false],
    [PRIVATE_KEY, true],
    [` ${PRIVATE_KEY} `, true],
  ])('%j → %s', (value, expected) => {
    expect(hasPrivateKeyInput(value)).toBe(expected);
  });
});
