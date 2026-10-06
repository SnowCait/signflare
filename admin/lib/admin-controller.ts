import { AdminApi, type ApiFetch } from './api';
import {
  errorMessage,
  isConfigurationError,
  isNotFound,
  type Operation,
} from './messages';
import {
  loginUrl,
  type Nip07Signer,
  nostrAuthorization,
  signLoginEvent,
  unixNow,
} from './nip98';
import type {
  AdminSession,
  AdminStatus,
  ClientSession,
  Identity,
  PairingPermissions,
} from './types';

// State and actions of the Admin SPA. Everything is kept in memory: nothing
// is written to browser storage, and a reload starts over from the session
// check. The admin session itself is an HttpOnly cookie that only the
// browser and the server handle.

export type AuthState =
  | { readonly status: 'loading' }
  | { readonly status: 'unauthenticated' }
  | { readonly status: 'authenticated'; readonly session: AdminSession }
  // The session check failed in a way that a retry may fix.
  | { readonly status: 'error'; readonly message: string }
  | { readonly status: 'configuration_error'; readonly message: string };

export interface SessionsState {
  readonly loading: boolean;
  // null until the first successful load.
  readonly sessions: readonly ClientSession[] | null;
  readonly error: string | null;
}

// A pairing created on this page. Its connection token is held here only,
// and dropped once the pairing has expired.
export interface PairingState {
  readonly bunkerUrl: string | null;
  readonly expiresAt: number;
}

export interface Notice {
  readonly kind: 'success' | 'error';
  readonly message: string;
}

export interface PendingState {
  readonly login: boolean;
  readonly logout: boolean;
  readonly refresh: boolean;
  readonly register: boolean;
  // Identity pubkeys.
  readonly deleting: readonly string[];
  readonly pairing: readonly string[];
  // Client pubkeys.
  readonly revoking: readonly string[];
}

export interface AdminState {
  readonly auth: AuthState;
  // null until loaded.
  readonly status: AdminStatus | null;
  readonly identities: readonly Identity[] | null;
  // Why the last status or identity refresh failed.
  readonly dashboardError: string | null;
  // By identity pubkey.
  readonly sessions: Readonly<Record<string, SessionsState>>;
  readonly pairings: Readonly<Record<string, PairingState>>;
  readonly pending: PendingState;
  readonly notice: Notice | null;
  readonly loginError: string | null;
}

export type ActionResult =
  { readonly ok: true } | { readonly ok: false; readonly message: string };

export interface AdminControllerOptions {
  readonly fetch: ApiFetch;
  // window.nostr, looked up when it is needed.
  readonly signer: () => Nip07Signer | undefined;
  // The URL of the current page.
  readonly pageUrl: () => string;
  readonly now?: () => number;
}

const IDLE: PendingState = {
  login: false,
  logout: false,
  refresh: false,
  register: false,
  deleting: [],
  pairing: [],
  revoking: [],
};

const SIGNED_OUT: AdminState = {
  auth: { status: 'unauthenticated' },
  status: null,
  identities: null,
  dashboardError: null,
  sessions: {},
  pairings: {},
  pending: IDLE,
  notice: null,
  loginError: null,
};

const SESSION_ENDED: Notice = {
  kind: 'error',
  message:
    'Your admin session has expired or is no longer valid. Sign in again.',
};

const BUSY: ActionResult = {
  ok: false,
  message: 'Another request is in progress. Try again once it has finished.',
};

export class AdminController {
  readonly #fetch: ApiFetch;
  readonly #signer: () => Nip07Signer | undefined;
  readonly #pageUrl: () => string;
  readonly #now: () => number;
  readonly #subscribers = new Set<(state: AdminState) => void>();
  #state: AdminState = { ...SIGNED_OUT, auth: { status: 'loading' } };
  // Bumped whenever the admin session ends, so that responses to requests
  // made before can no longer change the state.
  #epoch = 0;
  #api: AdminApi;
  #refreshes = 0;
  readonly #sessionLoads = new Map<string, number>();

  constructor(options: AdminControllerOptions) {
    this.#fetch = options.fetch;
    this.#signer = options.signer;
    this.#pageUrl = options.pageUrl;
    this.#now = options.now ?? unixNow;
    this.#api = this.#createApi(this.#epoch);
  }

  get state(): AdminState {
    return this.#state;
  }

  // The Svelte store contract.
  subscribe(run: (state: AdminState) => void): () => void {
    this.#subscribers.add(run);
    run(this.#state);
    return () => {
      this.#subscribers.delete(run);
    };
  }

  // Asks the server whether the browser already has an admin session.
  async start(): Promise<void> {
    const epoch = this.#reset({ ...SIGNED_OUT, auth: { status: 'loading' } });
    let session: AdminSession;
    try {
      session = await this.#api.getSession();
    } catch (error) {
      // A 401 has already switched to the login view.
      if (this.#isCurrent(epoch)) {
        this.#set({
          auth: isConfigurationError(error)
            ? {
                status: 'configuration_error',
                message: errorMessage(error, 'session'),
              }
            : { status: 'error', message: errorMessage(error, 'session') },
        });
      }
      return;
    }
    if (this.#isCurrent(epoch)) {
      this.#set({ auth: { status: 'authenticated', session } });
      await this.refresh();
    }
  }

  async login(): Promise<void> {
    const { auth, pending } = this.#state;
    if (auth.status !== 'unauthenticated' || pending.login) {
      return;
    }
    const epoch = this.#epoch;
    this.#set({
      loginError: null,
      notice: null,
      pending: { ...pending, login: true },
    });
    let session: AdminSession;
    try {
      const url = loginUrl(this.#pageUrl());
      const event = await signLoginEvent(this.#signer(), url, this.#now());
      session = await this.#api.login(url, nostrAuthorization(event));
    } catch (error) {
      if (this.#isCurrent(epoch)) {
        this.#set({
          loginError: errorMessage(error, 'login'),
          pending: { ...this.#state.pending, login: false },
        });
      }
      return;
    }
    if (this.#isCurrent(epoch)) {
      this.#set({ auth: { status: 'authenticated', session }, pending: IDLE });
      await this.refresh();
    }
  }

  // The server invalidates the session and clears the HttpOnly cookie.
  async logout(): Promise<void> {
    const { auth, pending } = this.#state;
    if (auth.status !== 'authenticated' || pending.logout) {
      return;
    }
    const epoch = this.#epoch;
    this.#setPending({ logout: true });
    try {
      await this.#api.logout();
    } catch (error) {
      if (this.#isCurrent(epoch)) {
        this.#set({
          notice: { kind: 'error', message: errorMessage(error, 'logout') },
          pending: { ...this.#state.pending, logout: false },
        });
      }
      return;
    }
    if (this.#isCurrent(epoch)) {
      this.#reset({
        ...SIGNED_OUT,
        notice: { kind: 'success', message: 'Signed out.' },
      });
    }
  }

  // Reloads the status and the identity list. Data of identities that are no
  // longer listed, including their connection tokens, is dropped.
  async refresh(): Promise<void> {
    if (this.#state.auth.status !== 'authenticated') {
      return;
    }
    const epoch = this.#epoch;
    const refresh = ++this.#refreshes;
    this.#setPending({ refresh: true });
    const [status, identities] = await Promise.allSettled([
      this.#api.getStatus(),
      this.#api.listIdentities(),
    ]);
    // Only the latest refresh applies its results.
    if (!this.#isCurrent(epoch) || refresh !== this.#refreshes) {
      return;
    }
    const failure = [status, identities].find(
      (result) => result.status === 'rejected',
    );
    let patch: Partial<AdminState> = {
      dashboardError: failure ? errorMessage(failure.reason, 'refresh') : null,
      pending: { ...this.#state.pending, refresh: false },
    };
    if (status.status === 'fulfilled') {
      patch = { ...patch, status: status.value };
    }
    if (identities.status === 'fulfilled') {
      const listed = new Set(identities.value.map(({ pubkey }) => pubkey));
      patch = {
        ...patch,
        identities: identities.value,
        sessions: pick(this.#state.sessions, listed),
        pairings: pick(this.#state.pairings, listed),
      };
    }
    this.#set(patch);
  }

  // The caller clears its input; the key is only passed on to the request.
  async registerIdentity(privateKey: string): Promise<ActionResult> {
    const { auth, pending } = this.#state;
    if (auth.status !== 'authenticated' || pending.register) {
      return BUSY;
    }
    const epoch = this.#epoch;
    this.#setPending({ register: true });
    let identity: Identity;
    try {
      identity = await this.#api.registerIdentity(privateKey);
    } catch (error) {
      if (this.#isCurrent(epoch)) {
        this.#setPending({ register: false });
      }
      return failed(error, 'register');
    }
    if (this.#isCurrent(epoch)) {
      this.#set({
        notice: {
          kind: 'success',
          message: `Registered identity ${identity.npub}.`,
        },
        pending: { ...this.#state.pending, register: false },
      });
      await this.refresh();
    }
    return { ok: true };
  }

  async deleteIdentity(pubkey: string): Promise<void> {
    const { auth, pending } = this.#state;
    if (
      auth.status !== 'authenticated' ||
      pending.deleting.includes(pubkey) ||
      pending.pairing.includes(pubkey)
    ) {
      return;
    }
    const epoch = this.#epoch;
    this.#setPending({ deleting: [...pending.deleting, pubkey] });
    let notice: Notice;
    let deleted = true;
    try {
      await this.#api.deleteIdentity(pubkey);
      notice = {
        kind: 'success',
        message:
          'Identity deleted. Its sessions were revoked and its pairings deleted.',
      };
    } catch (error) {
      deleted = isNotFound(error);
      notice = { kind: 'error', message: errorMessage(error, 'delete') };
    }
    if (!this.#isCurrent(epoch)) {
      return;
    }
    if (deleted) {
      // A session list still loading for the identity is not applied.
      this.#sessionLoads.delete(pubkey);
    }
    const current = this.#state;
    this.#set({
      notice,
      pending: {
        ...current.pending,
        deleting: current.pending.deleting.filter((item) => item !== pubkey),
      },
      ...(deleted && {
        identities:
          current.identities?.filter(
            (identity) => identity.pubkey !== pubkey,
          ) ?? null,
        sessions: omit(current.sessions, pubkey),
        pairings: omit(current.pairings, pubkey),
      }),
    });
    await this.refresh();
  }

  async createPairing(
    pubkey: string,
    permissions: PairingPermissions,
  ): Promise<ActionResult> {
    const { auth, pending } = this.#state;
    if (
      auth.status !== 'authenticated' ||
      pending.pairing.includes(pubkey) ||
      pending.deleting.includes(pubkey)
    ) {
      return BUSY;
    }
    const epoch = this.#epoch;
    this.#setPending({ pairing: [...pending.pairing, pubkey] });
    let result: ActionResult;
    let pairing: PairingState | null = null;
    let changed = true;
    try {
      const created = await this.#api.createPairing(pubkey, permissions);
      pairing = { bunkerUrl: created.bunkerUrl, expiresAt: created.expiresAt };
      result = { ok: true };
    } catch (error) {
      // Not found: the identity has been deleted in the meantime.
      changed = isNotFound(error);
      result = failed(error, 'pairing');
    }
    // A token that arrives after the session has ended is dropped.
    if (!this.#isCurrent(epoch)) {
      return result;
    }
    const current = this.#state;
    this.#set({
      pending: {
        ...current.pending,
        pairing: current.pending.pairing.filter((item) => item !== pubkey),
      },
      ...(pairing !== null && {
        pairings: { ...current.pairings, [pubkey]: pairing },
      }),
    });
    if (changed) {
      await this.refresh();
    }
    return result;
  }

  dismissPairing(pubkey: string): void {
    if (Object.hasOwn(this.#state.pairings, pubkey)) {
      this.#set({ pairings: omit(this.#state.pairings, pubkey) });
    }
  }

  // Drops the connection token of an expired pairing and keeps its expiry.
  expirePairing(pubkey: string): void {
    if (!Object.hasOwn(this.#state.pairings, pubkey)) {
      return;
    }
    const pairing = this.#state.pairings[pubkey];
    if (pairing.bunkerUrl !== null) {
      this.#set({
        pairings: {
          ...this.#state.pairings,
          [pubkey]: { bunkerUrl: null, expiresAt: pairing.expiresAt },
        },
      });
    }
  }

  async loadSessions(pubkey: string): Promise<void> {
    if (this.#state.auth.status !== 'authenticated') {
      return;
    }
    const epoch = this.#epoch;
    const load = (this.#sessionLoads.get(pubkey) ?? 0) + 1;
    this.#sessionLoads.set(pubkey, load);
    this.#updateSessions(pubkey, { loading: true, error: null });
    let sessions: ClientSession[];
    try {
      sessions = await this.#api.listSessions(pubkey);
    } catch (error) {
      if (this.#isCurrent(epoch) && this.#sessionLoads.get(pubkey) === load) {
        this.#updateSessions(pubkey, {
          loading: false,
          error: errorMessage(error, 'sessions'),
        });
      }
      return;
    }
    // Only the latest load for the identity applies its result.
    if (this.#isCurrent(epoch) && this.#sessionLoads.get(pubkey) === load) {
      this.#updateSessions(pubkey, { loading: false, sessions, error: null });
    }
  }

  async revokeSession(
    identityPubkey: string,
    clientPubkey: string,
  ): Promise<void> {
    const { auth, pending } = this.#state;
    if (
      auth.status !== 'authenticated' ||
      pending.revoking.includes(clientPubkey)
    ) {
      return;
    }
    const epoch = this.#epoch;
    this.#setPending({ revoking: [...pending.revoking, clientPubkey] });
    let notice: Notice;
    try {
      await this.#api.revokeSession(clientPubkey);
      notice = {
        kind: 'success',
        message:
          'Session revoked. Signflare rejects every further request from that client.',
      };
    } catch (error) {
      notice = { kind: 'error', message: errorMessage(error, 'revoke') };
    }
    if (!this.#isCurrent(epoch)) {
      return;
    }
    const current = this.#state;
    this.#set({
      notice,
      pending: {
        ...current.pending,
        revoking: current.pending.revoking.filter(
          (item) => item !== clientPubkey,
        ),
      },
    });
    await Promise.all([this.loadSessions(identityPubkey), this.refresh()]);
  }

  dismissNotice(): void {
    if (this.#state.notice !== null) {
      this.#set({ notice: null });
    }
  }

  // Every request that needs the admin session ends up here on 401: the
  // session has expired, was logged out elsewhere, or was issued to an
  // administrator other than the configured ADMIN_PUBKEY.
  #sessionEnded(): void {
    const wasAuthenticated = this.#state.auth.status === 'authenticated';
    this.#reset({
      ...SIGNED_OUT,
      notice: wasAuthenticated ? SESSION_ENDED : null,
    });
  }

  // A 401 to a request made before the current epoch says nothing about the
  // current session, so it is ignored.
  #createApi(epoch: number): AdminApi {
    return new AdminApi({
      fetch: this.#fetch,
      onUnauthorized: () => {
        if (this.#isCurrent(epoch)) {
          this.#sessionEnded();
        }
      },
    });
  }

  // Replaces the whole state, discarding all administrative data, and returns
  // the new epoch.
  #reset(state: AdminState): number {
    this.#epoch += 1;
    this.#api = this.#createApi(this.#epoch);
    this.#sessionLoads.clear();
    this.#state = state;
    this.#notify();
    return this.#epoch;
  }

  #isCurrent(epoch: number): boolean {
    return epoch === this.#epoch;
  }

  #set(patch: Partial<AdminState>): void {
    this.#state = { ...this.#state, ...patch };
    this.#notify();
  }

  #setPending(patch: Partial<PendingState>): void {
    this.#set({ pending: { ...this.#state.pending, ...patch } });
  }

  #updateSessions(pubkey: string, patch: Partial<SessionsState>): void {
    const current = this.#state.sessions[pubkey] ?? {
      loading: false,
      sessions: null,
      error: null,
    };
    this.#set({
      sessions: { ...this.#state.sessions, [pubkey]: { ...current, ...patch } },
    });
  }

  #notify(): void {
    for (const run of [...this.#subscribers]) {
      run(this.#state);
    }
  }
}

function failed(error: unknown, operation: Operation): ActionResult {
  return { ok: false, message: errorMessage(error, operation) };
}

function omit<T>(
  record: Readonly<Record<string, T>>,
  key: string,
): Record<string, T> {
  const rest = { ...record };
  delete rest[key];
  return rest;
}

function pick<T>(
  record: Readonly<Record<string, T>>,
  keys: ReadonlySet<string>,
): Record<string, T> {
  return Object.fromEntries(
    Object.entries(record).filter(([key]) => keys.has(key)),
  );
}
