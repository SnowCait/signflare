// Safe to surface to administrative callers: it carries no SQL, bound values,
// or key material.
export class StorageFullError extends Error {
  constructor() {
    super('Durable Object storage is full');
    this.name = 'StorageFullError';
  }
}

// Cloudflare documents that writes to a SQLite-backed Durable Object at its
// storage limit fail with "database or disk is full: SQLITE_FULL", while reads
// and deletes keep working.
export function isStorageFullError(error: unknown): boolean {
  return error instanceof Error && error.message.includes('SQLITE_FULL');
}

// Wrap write paths only. Reads and deletes must stay usable when storage is
// full, so they do not depend on this.
export function withStorageFullDetection<T>(write: () => T): T {
  try {
    return write();
  } catch (error) {
    if (isStorageFullError(error)) {
      throw new StorageFullError();
    }
    throw error;
  }
}
