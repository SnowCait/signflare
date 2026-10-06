// Display formatting for Admin API values.

const BYTE_UNITS = ['KiB', 'MiB', 'GiB', 'TiB'] as const;

// Untrusted client metadata is shortened to this many characters.
export const MAX_METADATA_DISPLAY_LENGTH = 200;

// A byte count in binary units, e.g. "1.5 MiB", or in bytes below 1 KiB.
export function formatBytes(bytes: number, locale?: string): string {
  if (bytes < 1024) {
    return formatExactBytes(bytes, locale);
  }
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const rounded = new Intl.NumberFormat(locale, {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  }).format(value);
  return `${rounded} ${BYTE_UNITS[unit]}`;
}

// A byte count in bytes, e.g. "1,572,864 bytes".
export function formatExactBytes(bytes: number, locale?: string): string {
  return `${new Intl.NumberFormat(locale).format(bytes)} ${bytes === 1 ? 'byte' : 'bytes'}`;
}

// The first and last 8 characters of a hex key, e.g. "79be667e…16f81798".
export function shortKey(hex: string): string {
  return hex.length > 20 ? `${hex.slice(0, 8)}…${hex.slice(-8)}` : hex;
}

// Unix seconds as an ISO 8601 UTC timestamp, for <time datetime>.
export function isoTime(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

// Unix seconds as a date and time in the viewer's locale and time zone.
export function formatTime(
  seconds: number,
  locale?: string,
  timeZone?: string,
): string {
  return new Intl.DateTimeFormat(locale, {
    dateStyle: 'medium',
    timeStyle: 'medium',
    timeZone,
  }).format(new Date(seconds * 1000));
}

// A non-negative number of seconds as m:ss, e.g. "9:05".
export function formatCountdown(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(total / 60);
  const rest = total % 60;
  return `${minutes}:${String(rest).padStart(2, '0')}`;
}

// Client metadata for display as plain text: null when absent, and cut to
// MAX_METADATA_DISPLAY_LENGTH characters. Cuts never split a character.
export function metadataText(value: string | null): string | null {
  if (value === null) {
    return null;
  }
  const characters = Array.from(value);
  return characters.length > MAX_METADATA_DISPLAY_LENGTH
    ? `${characters.slice(0, MAX_METADATA_DISPLAY_LENGTH).join('')}…`
    : value;
}
