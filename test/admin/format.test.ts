import { describe, expect, it } from 'vitest';
import {
  formatBytes,
  formatCountdown,
  formatExactBytes,
  formatTime,
  isoTime,
  MAX_METADATA_DISPLAY_LENGTH,
  metadataText,
  shortKey,
} from '../../admin/lib/format';

describe('formatBytes', () => {
  it.each([
    [0, '0 bytes'],
    [1, '1 byte'],
    [1023, '1,023 bytes'],
    [1024, '1.0 KiB'],
    [65_536, '64.0 KiB'],
    [1_048_576, '1.0 MiB'],
    [1_572_864, '1.5 MiB'],
    [10 * 1024 ** 3, '10.0 GiB'],
    [5 * 1024 ** 4, '5.0 TiB'],
    [2048 * 1024 ** 4, '2,048.0 TiB'],
  ])('shows %i bytes as %s', (bytes, text) => {
    expect(formatBytes(bytes, 'en-US')).toBe(text);
  });
});

describe('formatExactBytes', () => {
  it.each([
    [1, '1 byte'],
    [65_536, '65,536 bytes'],
    [10_737_418_240, '10,737,418,240 bytes'],
  ])('shows %i bytes as %s', (bytes, text) => {
    expect(formatExactBytes(bytes, 'en-US')).toBe(text);
  });
});

describe('times', () => {
  it('formats Unix seconds', () => {
    expect(isoTime(1_800_000_000)).toBe('2027-01-15T08:00:00.000Z');
    expect(formatTime(1_800_000_000, 'en-US', 'UTC')).toBe(
      'Jan 15, 2027, 8:00:00 AM',
    );
  });

  it.each([
    [600, '10:00'],
    [599.9, '9:59'],
    [65, '1:05'],
    [0, '0:00'],
    [-30, '0:00'],
  ])('counts %s seconds down as %s', (seconds, text) => {
    expect(formatCountdown(seconds)).toBe(text);
  });
});

describe('shortKey', () => {
  it('keeps the start and end of a key', () => {
    expect(
      shortKey(
        '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      ),
    ).toBe('79be667e…16f81798');
    expect(shortKey('abcd')).toBe('abcd');
  });
});

describe('metadataText', () => {
  it('returns client metadata unchanged, for escaped display as text', () => {
    expect(metadataText('<img src=x onerror=alert(1)>')).toBe(
      '<img src=x onerror=alert(1)>',
    );
    expect(metadataText('javascript:alert(1)')).toBe('javascript:alert(1)');
    expect(metadataText('')).toBe('');
    expect(metadataText(null)).toBeNull();
  });

  it('shortens long values without splitting characters', () => {
    const long = '🔑'.repeat(MAX_METADATA_DISPLAY_LENGTH + 5);
    const shown = metadataText(long) ?? '';
    expect(shown).toBe(`${'🔑'.repeat(MAX_METADATA_DISPLAY_LENGTH)}…`);
    expect(metadataText('🔑'.repeat(MAX_METADATA_DISPLAY_LENGTH))).toBe(
      '🔑'.repeat(MAX_METADATA_DISPLAY_LENGTH),
    );
  });
});
