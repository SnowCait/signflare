import { type Filter, matchFilters } from 'nostr-tools/filter';
import { NostrConnect } from 'nostr-tools/kinds';
import { type NostrEvent, verifyEvent } from 'nostr-tools/pure';
import type { SignflareBindings } from './config';
import * as nip46 from './nip46';
import { isSignedEvent } from './nostr-events';
import { MAX_EVENT_KIND } from './permissions';
import {
  RemoteSignerConfigurationError,
  remoteSignerPubkey,
} from './remote-signer';

// The restricted NIP-01 relay that carries NIP-46 traffic (docs/design.md
// §17, §18). It stores no events: request events are answered, and response
// events are only delivered live to matching subscriptions.
//
// Every incoming message is untrusted. Rejections never echo the message or
// carry library errors, and nothing of a message is logged.

// Incoming messages longer than this many UTF-16 code units are rejected
// before they are parsed. That leaves room for a request with a parameter of
// nip46.MAX_PARAM_LENGTH printable ASCII characters.
export const MAX_MESSAGE_LENGTH = 512 * 1024;

// NIP-01 limits subscription ids to 64 characters.
export const MAX_SUBSCRIPTION_ID_LENGTH = 64;

// Subscriptions live in the WebSocket attachment, which Cloudflare limits to
// 16,384 serialized bytes. At the following limits, the largest attachment
// takes less than half of that.
//
// Subscriptions per connection.
export const MAX_SUBSCRIPTIONS = 8;
// Filters per REQ.
export const MAX_FILTERS = 2;
// Values in each kinds, authors, and #p list of a filter.
export const MAX_FILTER_VALUES = 4;

// The attachment of every relay WebSocket: all the state a connection needs
// after the SignerHub has hibernated. It never holds authorization state.
export interface ConnectionState {
  readonly subscriptions: readonly Subscription[];
}

export interface Subscription {
  readonly id: string;
  // Each filter is restricted as subscriptionFilter() requires.
  readonly filters: Filter[];
}

type ClientMessage =
  | { readonly type: 'EVENT'; readonly event: unknown }
  | {
      readonly type: 'REQ';
      readonly subscriptionId: string;
      readonly filters: readonly unknown[];
    }
  | { readonly type: 'CLOSE'; readonly subscriptionId: string }
  // A message the relay does not act on, answered with this NOTICE.
  | { readonly type: 'NOTICE'; readonly notice: string };

// EVENT messages are built by deliver().
type RelayMessage =
  | ['OK', string, boolean, string]
  | ['EOSE', string]
  | ['CLOSED', string, string]
  | ['NOTICE', string];

const HEX_64 = /^[0-9a-f]{64}$/;

const FILTER_FIELDS: ReadonlySet<string> = new Set([
  'kinds',
  'authors',
  '#p',
  'since',
  'until',
  'limit',
]);

const SERVER_CONFIGURATION_ERROR = 'error: server configuration error';
const MALFORMED_FILTER = 'invalid: malformed filter';
const KINDS_RESTRICTION = 'restricted: filters must be limited to kind 24133';
const AUTHORS_RESTRICTION =
  'restricted: filters must be limited to the remote-signer author';
const CLIENT_RESTRICTION =
  'restricted: filters must include a #p client pubkey';

// A GET request to upgrade to the WebSocket protocol. The Workers runtime
// accepts no other Upgrade value for a WebSocket response.
export function isWebSocketUpgrade(request: Request): boolean {
  return (
    request.method === 'GET' &&
    request.headers.get('Upgrade')?.toLowerCase() === 'websocket'
  );
}

// Handles one message from a relay WebSocket. Never throws.
export async function handleMessage(
  ctx: DurableObjectState,
  env: SignflareBindings,
  ws: WebSocket,
  message: string | ArrayBuffer,
): Promise<void> {
  try {
    const parsed = parseClientMessage(message);
    switch (parsed.type) {
      case 'EVENT':
        await handleEvent(ctx, env, ws, parsed.event);
        return;
      case 'REQ':
        handleReq(env, ws, parsed.subscriptionId, parsed.filters);
        return;
      case 'CLOSE':
        handleClose(ws, parsed.subscriptionId);
        return;
      case 'NOTICE':
        send(ws, ['NOTICE', parsed.notice]);
        return;
    }
  } catch (error) {
    // Only the name is logged: messages and stacks could carry message data.
    console.error('Relay message failed:', errorName(error));
    send(ws, ['NOTICE', 'error: internal error']);
  }
}

function parseClientMessage(message: string | ArrayBuffer): ClientMessage {
  if (typeof message !== 'string') {
    return notice('invalid: binary messages are not supported');
  }
  if (message.length > MAX_MESSAGE_LENGTH) {
    return notice('invalid: message too large');
  }
  let value: unknown;
  try {
    value = JSON.parse(message);
  } catch {
    // Parser messages can quote the input, so they are discarded.
    return notice('invalid: malformed JSON');
  }
  if (!Array.isArray(value) || typeof value[0] !== 'string') {
    return notice('invalid: malformed message');
  }
  switch (value[0]) {
    case 'EVENT':
      return value.length === 2
        ? { type: 'EVENT', event: value[1] }
        : notice('invalid: malformed EVENT message');
    case 'REQ':
      return isSubscriptionId(value[1])
        ? { type: 'REQ', subscriptionId: value[1], filters: value.slice(2) }
        : notice('invalid: malformed REQ message');
    case 'CLOSE':
      return value.length === 2 && isSubscriptionId(value[1])
        ? { type: 'CLOSE', subscriptionId: value[1] }
        : notice('invalid: malformed CLOSE message');
    default:
      return notice('invalid: unsupported message type');
  }
}

// The NIP-46 restriction of docs/design.md §17.3 for one filter of a REQ:
// kind 24133, the remote-signer pubkey as the only author, and the client
// pubkeys in #p. Returns the filter as it is stored and matched, or the
// CLOSED message that refuses it.
function subscriptionFilter(
  value: unknown,
  remoteSigner: string,
): Filter | string {
  if (!isRecord(value)) {
    return MALFORMED_FILTER;
  }
  const kinds = filterValues(value.kinds, isEventKind, KINDS_RESTRICTION);
  if (typeof kinds === 'string') {
    return kinds;
  }
  if (kinds.some((kind) => kind !== NostrConnect)) {
    return KINDS_RESTRICTION;
  }
  const authors = filterValues(value.authors, isHex64, AUTHORS_RESTRICTION);
  if (typeof authors === 'string') {
    return authors;
  }
  if (authors.some((author) => author !== remoteSigner)) {
    return AUTHORS_RESTRICTION;
  }
  const clientPubkeys = filterValues(value['#p'], isHex64, CLIENT_RESTRICTION);
  if (typeof clientPubkeys === 'string') {
    return clientPubkeys;
  }
  if (Object.keys(value).some((field) => !FILTER_FIELDS.has(field))) {
    return 'restricted: unsupported filter field';
  }
  const { since, until, limit } = value;
  if (![since, until, limit].every(isOptionalNonNegativeInteger)) {
    return MALFORMED_FILTER;
  }
  // No events are stored, so limit, which applies to stored events only, is
  // not kept.
  const filter: Filter = {
    kinds: [NostrConnect],
    authors: [remoteSigner],
    '#p': [...new Set(clientPubkeys)],
  };
  if (since !== undefined) {
    filter.since = since as number;
  }
  if (until !== undefined) {
    filter.until = until as number;
  }
  return filter;
}

// Subscriptions are read from the attachment on every use, so they survive
// hibernation.
function readSubscriptions(ws: WebSocket): readonly Subscription[] {
  const state: unknown = ws.deserializeAttachment();
  return isConnectionState(state) ? state.subscriptions : [];
}

// Delivers `event` to every matching subscription of every connection. A
// connection that fails does not keep it from the others.
function deliver(sockets: readonly WebSocket[], event: NostrEvent): void {
  const serialized = JSON.stringify(event);
  for (const ws of sockets) {
    try {
      for (const { id, filters } of readSubscriptions(ws)) {
        if (matchFilters(filters, event)) {
          ws.send(`["EVENT",${JSON.stringify(id)},${serialized}]`);
        }
      }
    } catch {
      // The connection is closing or gone.
    }
  }
}

// docs/design.md §18, steps 2 to 9.
async function handleEvent(
  ctx: DurableObjectState,
  env: SignflareBindings,
  ws: WebSocket,
  value: unknown,
): Promise<void> {
  if (!isSignedEvent(value)) {
    const id = eventId(value);
    send(
      ws,
      id === null
        ? ['NOTICE', 'invalid: malformed event']
        : ['OK', id, false, 'invalid: malformed event'],
    );
    return;
  }
  const event = value;
  if (event.kind !== NostrConnect) {
    send(ws, [
      'OK',
      event.id,
      false,
      'restricted: only kind 24133 is accepted',
    ]);
    return;
  }
  // Also requires id to be the event hash. A freshly parsed event never
  // carries the verification flag that verifyEvent() trusts.
  if (!verifyEvent(event)) {
    send(ws, ['OK', event.id, false, 'invalid: bad event id or signature']);
    return;
  }

  let opened: nip46.OpenedRequest;
  try {
    opened = nip46.openRequest(env.REMOTE_SIGNER_PRIVATE_KEY, event);
  } catch (error) {
    if (error instanceof RemoteSignerConfigurationError) {
      logRemoteSignerConfigurationError();
      send(ws, ['OK', event.id, false, SERVER_CONFIGURATION_ERROR]);
      return;
    }
    throw error;
  }
  switch (opened.status) {
    case 'not_addressed':
      send(ws, [
        'OK',
        event.id,
        false,
        'restricted: not addressed to this remote signer',
      ]);
      return;
    case 'undecryptable':
      send(ws, ['OK', event.id, false, 'invalid: content cannot be decrypted']);
      return;
    case 'malformed':
      send(ws, ['OK', event.id, false, 'invalid: malformed NIP-46 request']);
      return;
  }

  // The event is a NIP-46 request. Failures from here on are NIP-46 errors,
  // answered in the response rather than by the relay.
  send(ws, ['OK', event.id, true, '']);
  const now = Math.floor(Date.now() / 1000);
  const outcome =
    opened.status === 'invalid'
      ? nip46.errorOutcome(opened.id, 'invalid request')
      : await nip46.handleRequest(
          {
            storage: ctx.storage,
            env,
            remoteSignerPubkey: opened.remoteSignerPubkey,
            clientPubkey: event.pubkey,
            now,
          },
          opened.request,
        );
  try {
    // Response events are not stored, only delivered to live subscriptions.
    deliver(
      ctx.getWebSockets(),
      nip46.sealResponse(
        env.REMOTE_SIGNER_PRIVATE_KEY,
        event.pubkey,
        outcome.response,
        now,
      ),
    );
  } finally {
    outcome.afterResponse?.();
  }
}

// A REQ replaces the subscription with the same id on this connection, if
// any (NIP-01). A refused REQ therefore closes it as well.
function handleReq(
  env: SignflareBindings,
  ws: WebSocket,
  subscriptionId: string,
  values: readonly unknown[],
): void {
  const current = readSubscriptions(ws);
  const others = current.filter(({ id }) => id !== subscriptionId);
  const refuse = (reason: string) => {
    if (others.length !== current.length) {
      writeSubscriptions(ws, others);
    }
    send(ws, ['CLOSED', subscriptionId, reason]);
  };

  if (values.length === 0) {
    refuse('invalid: REQ without filters');
    return;
  }
  if (values.length > MAX_FILTERS) {
    refuse('restricted: too many filters');
    return;
  }
  let remoteSigner: string;
  try {
    remoteSigner = remoteSignerPubkey(env.REMOTE_SIGNER_PRIVATE_KEY);
  } catch (error) {
    if (error instanceof RemoteSignerConfigurationError) {
      logRemoteSignerConfigurationError();
      refuse(SERVER_CONFIGURATION_ERROR);
      return;
    }
    throw error;
  }
  const filters: Filter[] = [];
  for (const value of values) {
    const filter = subscriptionFilter(value, remoteSigner);
    if (typeof filter === 'string') {
      refuse(filter);
      return;
    }
    filters.push(filter);
  }
  if (others.length >= MAX_SUBSCRIPTIONS) {
    refuse('restricted: too many subscriptions');
    return;
  }

  writeSubscriptions(ws, [...others, { id: subscriptionId, filters }]);
  // No events are stored, so the stored events end right away.
  send(ws, ['EOSE', subscriptionId]);
}

// Only this connection's subscription is removed (NIP-01).
function handleClose(ws: WebSocket, subscriptionId: string): void {
  const current = readSubscriptions(ws);
  const others = current.filter(({ id }) => id !== subscriptionId);
  if (others.length !== current.length) {
    writeSubscriptions(ws, others);
  }
}

function writeSubscriptions(
  ws: WebSocket,
  subscriptions: readonly Subscription[],
): void {
  ws.serializeAttachment({ subscriptions } satisfies ConnectionState);
}

function send(ws: WebSocket, message: RelayMessage): void {
  try {
    ws.send(JSON.stringify(message));
  } catch {
    // The connection is closing or gone.
  }
}

function notice(message: string): ClientMessage {
  return { type: 'NOTICE', notice: message };
}

// The values of a filter list, or the CLOSED message that refuses them:
// `missing` when there is no list.
function filterValues<T>(
  value: unknown,
  isItem: (item: unknown) => item is T,
  missing: string,
): T[] | string {
  if (value === undefined) {
    return missing;
  }
  if (!Array.isArray(value) || value.length === 0 || !value.every(isItem)) {
    return MALFORMED_FILTER;
  }
  return value.length > MAX_FILTER_VALUES
    ? 'restricted: too many filter values'
    : value;
}

function isSubscriptionId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_SUBSCRIPTION_ID_LENGTH
  );
}

function isEventKind(value: unknown): value is number {
  return (
    Number.isInteger(value) &&
    (value as number) >= 0 &&
    (value as number) <= MAX_EVENT_KIND
  );
}

function isHex64(value: unknown): value is string {
  return typeof value === 'string' && HEX_64.test(value);
}

function isOptionalNonNegativeInteger(value: unknown): boolean {
  return (
    value === undefined ||
    (Number.isSafeInteger(value) && (value as number) >= 0)
  );
}

function isConnectionState(value: unknown): value is ConnectionState {
  return (
    isRecord(value) &&
    Array.isArray((value as Partial<ConnectionState>).subscriptions)
  );
}

// The id of a malformed event, when it has one that an OK can carry.
function eventId(value: unknown): string | null {
  return isRecord(value) && isHex64(value.id) ? value.id : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function logRemoteSignerConfigurationError(): void {
  console.error(
    'REMOTE_SIGNER_PRIVATE_KEY must be set to an nsec or a 64-character hex private key',
  );
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : typeof error;
}
