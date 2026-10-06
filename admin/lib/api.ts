import {
  type AdminSession,
  type AdminStatus,
  type ClientSession,
  type Identity,
  type Pairing,
  type PairingPermissions,
  parseAdminSession,
  parseAdminStatus,
  parseClientSessions,
  parseIdentities,
  parseIdentity,
  parsePairing,
} from './types';

// Client for the same-origin Admin API (docs/design.md §30). Requests rely on
// the HttpOnly admin session cookie, which the browser attaches by itself:
// no token is ever read, stored, or sent from here.

export const ADMIN_API_PATH = '/admin/api';

// The error codes of the Admin API's {"error": "..."} responses.
export const API_ERROR_CODES = [
  'unauthorized',
  'forbidden',
  'not found',
  'invalid request',
  'invalid private key',
  'invalid pubkey',
  'invalid permissions',
  'identity already exists',
  'payload too large',
  'insufficient storage',
  'server configuration error',
  'internal error',
] as const;

export type ApiErrorCode = (typeof API_ERROR_CODES)[number];

// Neither the message nor any property carries a request or response body.
export class ApiError extends Error {
  constructor(
    // null when no response was received.
    readonly status: number | null,
    // The server's error code, when it is one of API_ERROR_CODES.
    readonly code: ApiErrorCode | null = null,
  ) {
    super(
      status === null
        ? 'Admin API request failed'
        : `Admin API request failed with status ${status}`,
    );
    this.name = 'ApiError';
  }
}

export interface ApiRequestInit {
  readonly method: 'GET' | 'POST' | 'DELETE';
  readonly headers: Record<string, string>;
  readonly body?: string;
  readonly credentials: 'same-origin';
  readonly cache: 'no-store';
}

export interface ApiResponse {
  readonly status: number;
  readonly headers: { get(name: string): string | null };
  text(): Promise<string>;
}

export type ApiFetch = (
  url: string,
  init: ApiRequestInit,
) => Promise<ApiResponse>;

export interface AdminApiOptions {
  readonly fetch: ApiFetch;
  // Called whenever a request that needs the admin session gets 401, which
  // means that the session has expired or was invalidated.
  readonly onUnauthorized: () => void;
}

interface RequestOptions {
  readonly url?: string;
  readonly body?: string;
  readonly authorization?: string;
  readonly requiresSession?: boolean;
}

export class AdminApi {
  readonly #fetch: ApiFetch;
  readonly #onUnauthorized: () => void;

  constructor(options: AdminApiOptions) {
    this.#fetch = options.fetch;
    this.#onUnauthorized = options.onUnauthorized;
  }

  getSession(): Promise<AdminSession> {
    return this.#request('GET', '/session', parseAdminSession);
  }

  // `url` is the absolute login URL that the NIP-98 event signs, so the
  // request goes exactly there. A 401 here is a rejected login.
  login(url: string, authorization: string): Promise<AdminSession> {
    return this.#request('POST', '/login', parseAdminSession, {
      url,
      authorization,
      requiresSession: false,
    });
  }

  logout(): Promise<void> {
    return this.#request('POST', '/logout', null);
  }

  getStatus(): Promise<AdminStatus> {
    return this.#request('GET', '/status', parseAdminStatus);
  }

  listIdentities(): Promise<Identity[]> {
    return this.#request('GET', '/identities', parseIdentities);
  }

  // The private key goes into the request body only, and is not kept.
  registerIdentity(privateKey: string): Promise<Identity> {
    return this.#request('POST', '/identities', parseIdentity, {
      body: JSON.stringify({ privateKey }),
    });
  }

  deleteIdentity(pubkey: string): Promise<void> {
    return this.#request('DELETE', `/identities/${pathSegment(pubkey)}`, null);
  }

  createPairing(
    pubkey: string,
    permissions: PairingPermissions,
  ): Promise<Pairing> {
    return this.#request(
      'POST',
      `/identities/${pathSegment(pubkey)}/pairings`,
      parsePairing,
      { body: JSON.stringify({ permissions }) },
    );
  }

  listSessions(pubkey: string): Promise<ClientSession[]> {
    return this.#request(
      'GET',
      `/identities/${pathSegment(pubkey)}/sessions`,
      parseClientSessions,
    );
  }

  revokeSession(clientPubkey: string): Promise<void> {
    return this.#request(
      'DELETE',
      `/sessions/${pathSegment(clientPubkey)}`,
      null,
    );
  }

  // `parse` is null for endpoints that answer 204 No Content.
  async #request<T>(
    method: ApiRequestInit['method'],
    path: string,
    parse: ((value: unknown) => T | null) | null,
    options: RequestOptions = {},
  ): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    if (options.authorization !== undefined) {
      headers.Authorization = options.authorization;
    }

    let response: ApiResponse;
    try {
      response = await this.#fetch(options.url ?? `${ADMIN_API_PATH}${path}`, {
        method,
        headers,
        body: options.body,
        credentials: 'same-origin',
        cache: 'no-store',
      });
    } catch {
      // The cause is dropped: it is of no use to the UI.
      throw new ApiError(null);
    }

    if (response.status === 401 && options.requiresSession !== false) {
      this.#onUnauthorized();
    }
    if (response.status < 200 || response.status > 299) {
      throw new ApiError(response.status, await readErrorCode(response));
    }
    if (parse === null) {
      if (response.status !== 204) {
        throw new ApiError(response.status);
      }
      return undefined as T;
    }
    const result = parse(await readJson(response));
    if (result === null) {
      throw new ApiError(response.status);
    }
    return result;
  }
}

function pathSegment(value: string): string {
  return encodeURIComponent(value);
}

// The parsed body of a JSON response, or undefined for any other body.
// Parser messages can quote the body, so they are dropped.
async function readJson(response: ApiResponse): Promise<unknown> {
  const type = response.headers.get('Content-Type') ?? '';
  if (!/^application\/json\b/i.test(type)) {
    return undefined;
  }
  try {
    return JSON.parse(await response.text());
  } catch {
    return undefined;
  }
}

async function readErrorCode(
  response: ApiResponse,
): Promise<ApiErrorCode | null> {
  const body = await readJson(response);
  if (typeof body !== 'object' || body === null) {
    return null;
  }
  const code: unknown = (body as Record<string, unknown>).error;
  return (API_ERROR_CODES as readonly unknown[]).includes(code)
    ? (code as ApiErrorCode)
    : null;
}
