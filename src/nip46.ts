import { NostrConnect } from 'nostr-tools/kinds';
import * as nip04 from 'nostr-tools/nip04';
import * as nip44 from 'nostr-tools/nip44';
import {
  type EventTemplate,
  finalizeEvent,
  type NostrEvent,
  type VerifiedEvent,
} from 'nostr-tools/pure';
import { parseMasterEncryptionKey, type SignflareBindings } from './config';
import { getIdentity } from './identities';
import { isPermitted, MAX_EVENT_KIND } from './permissions';
import {
  PrivateKeyDecryptionError,
  withDecryptedPrivateKey,
} from './private-key-encryption';
import { withRemoteSignerKey } from './remote-signer';
import {
  type ClientMetadata,
  establishSession,
  getSession,
  revokeSession,
  type Session,
  touchSession,
} from './sessions';
import { StorageFullError } from './storage-errors';

// NIP-46 request handling (docs/design.md §18 to §29): opening request
// events, dispatching their methods, and sealing the responses.
//
// The NIP-46 transport uses the remote-signer keypair. The user methods
// nip04_* and nip44_* use the session identity's keypair instead.

// Every request parameter is limited to this many UTF-16 code units. Event
// templates and NIP-04 or NIP-44 texts of real clients fit well within it.
export const MAX_PARAM_LENGTH = 128 * 1024;

// Stable error categories, safe to send to untrusted clients
// (docs/design.md §38.2).
export type Nip46Error =
  | 'invalid request'
  | 'invalid secret'
  | 'pairing expired'
  | 'already connected'
  | 'not connected'
  | 'permission denied'
  | 'unsupported method'
  | 'decryption failed'
  | 'internal error';

export interface Nip46Request {
  readonly id: string;
  readonly method: string;
  readonly params: readonly string[];
}

// The response payload. An error response carries an empty result.
export type Nip46Response =
  | { readonly id: string; readonly result: string }
  | { readonly id: string; readonly result: ''; readonly error: Nip46Error };

export interface Nip46Outcome {
  readonly response: Nip46Response;
  // Runs once the response has been published. logout removes the session
  // here, after its acknowledgement (docs/design.md §28).
  readonly afterResponse?: () => void;
}

export type OpenedRequest =
  // No p tag addresses the remote signer, so the content was not decrypted.
  | { readonly status: 'not_addressed' }
  // The content is not a NIP-44 payload from the author to the remote signer.
  | { readonly status: 'undecryptable' }
  // The plaintext has no request id that a response could answer.
  | { readonly status: 'malformed' }
  // The request has an id but is not well-formed otherwise.
  | { readonly status: 'invalid'; readonly id: string }
  | {
      readonly status: 'valid';
      readonly request: Nip46Request;
      readonly remoteSignerPubkey: string;
    };

export interface Nip46Context {
  readonly storage: DurableObjectStorage;
  // Read only once a user private key has to be decrypted.
  readonly env: Pick<SignflareBindings, 'MASTER_ENCRYPTION_KEY'>;
  readonly remoteSignerPubkey: string;
  // The pubkey of the request event.
  readonly clientPubkey: string;
  readonly now: number;
}

const PUBKEY = /^[0-9a-f]{64}$/;

const CLIENT_METADATA_FIELDS = ['name', 'url', 'image'] as const;

type OperationResult =
  { readonly result: string } | { readonly error: Nip46Error };

// A method other than connect, with validated parameters.
type Operation =
  // Needs an established session and nothing else (docs/design.md §16.2).
  | { readonly type: 'session'; readonly run: (session: Session) => string }
  | { readonly type: 'logout' }
  // Needs a permission and the private key of the session identity, which is
  // decrypted only after the permission check.
  | {
      readonly type: 'user_key';
      readonly permission: string;
      readonly run: (secretKey: Uint8Array) => OperationResult;
    };

// Steps 5 to 7 of docs/design.md §18, for an event whose structure, kind, id,
// and signature the relay has already validated. The content is decrypted
// only for an event addressed to the remote signer.
//
// Throws RemoteSignerConfigurationError.
export function openRequest(
  remoteSignerPrivateKey: unknown,
  event: NostrEvent,
): OpenedRequest {
  const opened = withRemoteSignerKey(remoteSignerPrivateKey, (key) => {
    if (!isAddressedTo(event, key.pubkey)) {
      return null;
    }
    let plaintext: string | null;
    try {
      plaintext = withConversationKey(
        key.secretKey,
        event.pubkey,
        (conversationKey) => nip44.decrypt(event.content, conversationKey),
      );
    } catch {
      // Library messages can quote the payload, so they are discarded.
      plaintext = null;
    }
    return { plaintext, remoteSignerPubkey: key.pubkey };
  });
  if (opened === null) {
    return { status: 'not_addressed' };
  }
  if (opened.plaintext === null) {
    return { status: 'undecryptable' };
  }
  return parseRequest(opened.plaintext, opened.remoteSignerPubkey);
}

// Steps 8 and 9 of docs/design.md §18. Never throws: unexpected failures are
// answered with "internal error".
export async function handleRequest(
  context: Nip46Context,
  request: Nip46Request,
): Promise<Nip46Outcome> {
  try {
    return await dispatch(context, request);
  } catch (error) {
    // Only the name is logged: messages and stacks could carry request data.
    console.error('NIP-46 request failed:', errorName(error));
    return errorOutcome(request.id, 'internal error');
  }
}

export function errorOutcome(id: string, error: Nip46Error): Nip46Outcome {
  return { response: { id, result: '', error } };
}

// A kind 24133 event from the remote signer to the client carrying the NIP-44
// encrypted response (docs/design.md §29).
//
// Throws RemoteSignerConfigurationError.
export function sealResponse(
  remoteSignerPrivateKey: unknown,
  clientPubkey: string,
  response: Nip46Response,
  now: number,
): VerifiedEvent {
  return withRemoteSignerKey(remoteSignerPrivateKey, ({ secretKey }) =>
    finalizeEvent(
      {
        kind: NostrConnect,
        created_at: now,
        tags: [['p', clientPubkey]],
        content: withConversationKey(
          secretKey,
          clientPubkey,
          (conversationKey) =>
            nip44.encrypt(JSON.stringify(response), conversationKey),
        ),
      },
      secretKey,
    ),
  );
}

// A request p-tags the remote-signer pubkey and nothing else.
function isAddressedTo(event: NostrEvent, pubkey: string): boolean {
  const recipients = event.tags.filter((tag) => tag[0] === 'p');
  return recipients.length === 1 && recipients[0][1] === pubkey;
}

// The decrypted request is untrusted input (docs/design.md §19).
function parseRequest(
  plaintext: string,
  remoteSignerPubkey: string,
): OpenedRequest {
  let value: unknown;
  try {
    value = JSON.parse(plaintext);
  } catch {
    return { status: 'malformed' };
  }
  if (!isRecord(value)) {
    return { status: 'malformed' };
  }
  const { id, method, params } = value;
  if (typeof id !== 'string' || id === '') {
    return { status: 'malformed' };
  }
  if (
    typeof method !== 'string' ||
    !Array.isArray(params) ||
    !params.every(
      (param) => typeof param === 'string' && param.length <= MAX_PARAM_LENGTH,
    )
  ) {
    return { status: 'invalid', id };
  }
  return {
    status: 'valid',
    request: { id, method, params: params as string[] },
    remoteSignerPubkey,
  };
}

async function dispatch(
  context: Nip46Context,
  { id, method, params }: Nip46Request,
): Promise<Nip46Outcome> {
  if (method === 'connect') {
    return connect(context, id, params);
  }
  const operation = parseOperation(method, params);
  if (typeof operation === 'string') {
    return errorOutcome(id, operation);
  }

  // The session row is the only source of authorization (docs/design.md §21).
  const { sql } = context.storage;
  const session = getSession(sql, context.clientPubkey);
  if (session === null) {
    return errorOutcome(id, 'not connected');
  }
  switch (operation.type) {
    case 'logout':
      // Removed only once the acknowledgement has been published.
      return {
        response: { id, result: 'ack' },
        afterResponse: () => {
          revokeSession(sql, context.clientPubkey);
        },
      };
    case 'session': {
      const result = operation.run(session);
      recordUse(context);
      return { response: { id, result } };
    }
    case 'user_key': {
      if (!isPermitted(session.permissions, operation.permission)) {
        return errorOutcome(id, 'permission denied');
      }
      const outcome = await withUserKey(context, session, operation.run);
      if ('error' in outcome) {
        return errorOutcome(id, outcome.error);
      }
      // The session may have been revoked, or its identity deleted, while the
      // key was being decrypted. Its result is then withheld.
      if (!recordUse(context)) {
        return errorOutcome(id, 'not connected');
      }
      return { response: { id, result: outcome.result } };
    }
  }
}

// docs/design.md §20. The params are [remote-signer-pubkey, optional_secret,
// optional_requested_perms, optional_client_metadata].
async function connect(
  context: Nip46Context,
  id: string,
  params: readonly string[],
): Promise<Nip46Outcome> {
  if (params.length < 1 || params.length > 4) {
    return errorOutcome(id, 'invalid request');
  }
  const [remoteSignerPubkey, secret = '', requestedPermissions, metadata] =
    params;
  if (remoteSignerPubkey !== context.remoteSignerPubkey) {
    return errorOutcome(id, 'invalid request');
  }
  const clientMetadata = parseClientMetadata(metadata);
  if (clientMetadata === null) {
    return errorOutcome(id, 'invalid request');
  }
  const result = await establishSession(context.storage, {
    secret,
    clientPubkey: context.clientPubkey,
    requestedPermissions,
    clientMetadata,
    now: context.now,
  });
  switch (result.status) {
    case 'created':
      return { response: { id, result: 'ack' } };
    case 'invalid_permissions':
      return errorOutcome(id, 'invalid request');
    case 'invalid_secret':
      return errorOutcome(id, 'invalid secret');
    case 'pairing_expired':
      return errorOutcome(id, 'pairing expired');
    case 'already_connected':
      return errorOutcome(id, 'already connected');
    case 'storage_full':
      console.error('NIP-46 connect failed: storage is full');
      return errorOutcome(id, 'internal error');
  }
}

// optional_client_metadata is a JSON object whose name, url, and image are
// strings when present. Other fields are ignored, and none of them affects
// authorization (docs/design.md §15). Returns null when it is malformed.
function parseClientMetadata(
  value: string | undefined,
): Partial<ClientMetadata> | null {
  if (value === undefined || value === '') {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) {
    return null;
  }
  const metadata: { -readonly [K in keyof ClientMetadata]?: string } = {};
  for (const field of CLIENT_METADATA_FIELDS) {
    const fieldValue = Object.hasOwn(parsed, field) ? parsed[field] : null;
    if (fieldValue === null || fieldValue === undefined) {
      continue;
    }
    if (typeof fieldValue !== 'string') {
      return null;
    }
    metadata[field] = fieldValue;
  }
  return metadata;
}

function parseOperation(
  method: string,
  params: readonly string[],
): Operation | Nip46Error {
  switch (method) {
    case 'ping':
      return params.length === 0
        ? { type: 'session', run: () => 'pong' }
        : 'invalid request';
    case 'get_public_key':
      // The user pubkey, never the remote-signer pubkey (docs/design.md §22).
      return params.length === 0
        ? { type: 'session', run: (session) => session.identityPubkey }
        : 'invalid request';
    case 'switch_relays':
      // v1 serves only its own relay, so there is never anything to switch
      // to. The result is the JSON null (docs/design.md §27).
      return params.length === 0
        ? { type: 'session', run: () => 'null' }
        : 'invalid request';
    case 'logout':
      return params.length === 0 ? { type: 'logout' } : 'invalid request';
    case 'sign_event':
      return signEvent(params);
    case 'nip04_encrypt':
      return cipher(params, 'nip04_encrypt', 'invalid request', nip04.encrypt);
    case 'nip04_decrypt':
      return cipher(
        params,
        'nip04_decrypt',
        'decryption failed',
        nip04.decrypt,
      );
    case 'nip44_encrypt':
      // NIP-44 cannot encrypt an empty plaintext.
      return params[1] === ''
        ? 'invalid request'
        : cipher(
            params,
            'nip44_encrypt',
            'invalid request',
            (secretKey, pubkey, text) =>
              withConversationKey(secretKey, pubkey, (conversationKey) =>
                nip44.encrypt(text, conversationKey),
              ),
          );
    case 'nip44_decrypt':
      return cipher(
        params,
        'nip44_decrypt',
        'decryption failed',
        (secretKey, pubkey, payload) =>
          withConversationKey(secretKey, pubkey, (conversationKey) =>
            nip44.decrypt(payload, conversationKey),
          ),
      );
    default:
      return 'unsupported method';
  }
}

// docs/design.md §23. The event is built from the validated template fields
// only, so a pubkey, id, or sig the client supplies is ignored.
function signEvent(params: readonly string[]): Operation | Nip46Error {
  const template = params.length === 1 ? parseEventTemplate(params[0]) : null;
  if (template === null) {
    return 'invalid request';
  }
  return {
    type: 'user_key',
    permission: `sign_event:${template.kind}`,
    run: (secretKey) => ({
      result: JSON.stringify(finalizeEvent(template, secretKey)),
    }),
  };
}

function parseEventTemplate(value: string): EventTemplate | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) {
    return null;
  }
  const { kind, content, tags, created_at } = parsed;
  if (
    !Number.isInteger(kind) ||
    (kind as number) < 0 ||
    (kind as number) > MAX_EVENT_KIND ||
    typeof content !== 'string' ||
    !isTagList(tags) ||
    !Number.isSafeInteger(created_at) ||
    (created_at as number) < 0
  ) {
    return null;
  }
  return {
    kind: kind as number,
    content,
    tags: tags.map((tag) => [...tag]),
    created_at: created_at as number,
  };
}

// nip04_* and nip44_* take [third_party_pubkey, text] and use the private key
// of the session identity (docs/design.md §24, §25). `failure` is reported
// when the library rejects the input.
function cipher(
  params: readonly string[],
  permission: string,
  failure: Nip46Error,
  run: (secretKey: Uint8Array, pubkey: string, text: string) => string,
): Operation | Nip46Error {
  if (params.length !== 2 || !PUBKEY.test(params[0])) {
    return 'invalid request';
  }
  const [pubkey, text] = params;
  return {
    type: 'user_key',
    permission,
    run: (secretKey) => {
      try {
        return { result: run(secretKey, pubkey, text) };
      } catch {
        // Library messages can quote the input, so they are discarded.
        return { error: failure };
      }
    },
  };
}

// Decrypts the private key of the session identity for `run` only. The key
// and MASTER_ENCRYPTION_KEY bytes are overwritten afterwards, as a best
// effort.
async function withUserKey(
  context: Nip46Context,
  session: Session,
  run: (secretKey: Uint8Array) => OperationResult,
): Promise<OperationResult> {
  // Identity deletion removes the sessions in the same transaction, so the
  // identity of an existing session exists unless storage was altered.
  const identity = getIdentity(context.storage.sql, session.identityPubkey);
  if (identity === null) {
    return { error: 'internal error' };
  }
  const masterKey = parseMasterEncryptionKey(context.env.MASTER_ENCRYPTION_KEY);
  if (masterKey === null) {
    console.error(
      'MASTER_ENCRYPTION_KEY must be set to a secret of at least 32 bytes',
    );
    return { error: 'internal error' };
  }
  try {
    return await withDecryptedPrivateKey(
      masterKey,
      identity.pubkey,
      identity.encryptedPrivateKey,
      run,
    );
  } catch (error) {
    if (error instanceof PrivateKeyDecryptionError) {
      console.error('NIP-46 request failed: identity key decryption failed');
      return { error: 'internal error' };
    }
    throw error;
  } finally {
    masterKey.fill(0);
  }
}

// Updates last_used_at after a successful authorized operation
// (docs/design.md §14) and tells whether the session still exists. Full
// storage only keeps the use from being recorded.
function recordUse(context: Nip46Context): boolean {
  const { sql } = context.storage;
  try {
    return touchSession(sql, context.clientPubkey, context.now);
  } catch (error) {
    if (!(error instanceof StorageFullError)) {
      throw error;
    }
    console.error('NIP-46 session use was not recorded: storage is full');
    return getSession(sql, context.clientPubkey) !== null;
  }
}

// The conversation key is derived for one operation and overwritten
// afterwards, as a best effort.
function withConversationKey<T>(
  secretKey: Uint8Array,
  pubkey: string,
  use: (conversationKey: Uint8Array) => T,
): T {
  const conversationKey = nip44.getConversationKey(secretKey, pubkey);
  try {
    return use(conversationKey);
  } finally {
    conversationKey.fill(0);
  }
}

function isTagList(value: unknown): value is string[][] {
  return (
    Array.isArray(value) &&
    value.every(
      (tag) =>
        Array.isArray(tag) && tag.every((item) => typeof item === 'string'),
    )
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : typeof error;
}
