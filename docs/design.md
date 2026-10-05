# Signflare Design

## Status

This document defines the v1 architecture and implementation requirements for Signflare.

Signflare is a self-hostable Nostr remote signer designed to run on Cloudflare Workers. It implements NIP-46 remote signing, provides its own minimal relay transport, and supports registering multiple Nostr user private keys after deployment.

This document is intended to be the source of truth for v1 implementation decisions. When this document conflicts with implementation details, the implementation should be treated as incorrect unless the design is intentionally revised.

Normative terms such as **MUST**, **MUST NOT**, **SHOULD**, and **MAY** indicate implementation requirements within Signflare. They do not imply requirements in the referenced NIPs unless explicitly stated.

---

## 1. Goals

Signflare v1 MUST:

- run on Cloudflare Workers;
- be deployable by third parties as a self-hosted service;
- provide a Deploy to Cloudflare button;
- implement NIP-46 remote signing;
- implement NIP-11 relay information for the restricted NIP-46 relay endpoint;
- support the bunker-initiated `bunker://` connection flow;
- allow user private keys to be added and removed after deployment without redeploying the Worker;
- support multiple user identities in a single deployment;
- avoid a hard-coded limit on the number of registered identities;
- encrypt user private keys before storing them;
- use a single deployment-wide remote-signer keypair;
- enforce per-session permissions;
- provide an administrative HTTP API;
- provide a browser-based administrative UI built with Svelte;
- authenticate administrators with Nostr rather than a static bearer token;
- provide a minimal Nostr relay transport for NIP-46 traffic;
- use a SQLite-backed Durable Object for persistent state;
- use the Durable Objects WebSocket Hibernation API;
- handle storage exhaustion explicitly and keep deletion available for recovery.

## 2. Non-goals

Signflare v1 will not implement:

- the client-initiated `nostrconnect://` flow;
- NIP-05 signer discovery;
- NIP-89 signer announcements;
- persistent storage of Nostr events;
- a general-purpose Nostr relay;
- outbound persistent WebSocket connections to external relays;
- user-key export or backup;
- user-key import from an encrypted backup format;
- an automated master-key rotation command;
- multiple or per-identity remote-signer keypairs;
- email, webhook, or other out-of-band administrative notifications;
- user profile management;
- a command-line administration client.

These features may be added in later versions without changing the core v1 storage and session model.

---

## 3. Terminology

Signflare uses the following application-level terms in addition to the terminology defined by NIP-46:

- **identity**: a registered Nostr user keypair controlled by Signflare;
- **pairing**: a Signflare-specific, one-time authorization that binds an identity, an allowed permission set, an expiration time, and a one-time secret before a client connects;
- **connection token**: the NIP-46 `bunker://...` value generated from a pairing and given to the client;
- **session**: the persistent authorization state created after a successful NIP-46 `connect`;
- **permissions**: the operations granted to a session;
- **secret**: the one-time value carried in the NIP-46 connection token and validated against the pairing.

A pairing is not itself the NIP-46 connection token. A pairing is Signflare's server-side authorization object; creating a pairing produces a NIP-46 connection token.

The intended lifecycle is:

```text
identity
   |
   v
pairing
   |
   | generates
   v
NIP-46 connection token (bunker://...)
   |
   | successful connect
   v
session
```

---

## 4. External Protocol Requirements

### 4.1 NIP-46

Signflare MUST follow the current NIP-46 remote-signing protocol.

NIP-46 defines:

- `remote-signer-keypair` separately from `user-keypair`;
- request and response events using kind `24133`;
- NIP-44 encryption for NIP-46 request and response payloads;
- a `bunker://` flow initiated by the remote signer;
- a `nostrconnect://` flow initiated by the client;
- the methods:
  - `connect`
  - `sign_event`
  - `ping`
  - `get_public_key`
  - `nip04_encrypt`
  - `nip04_decrypt`
  - `nip44_encrypt`
  - `nip44_decrypt`
  - `switch_relays`
  - `logout`;
- optional requested permissions on `connect`;
- optional client metadata;
- one-time use semantics for a successful bunker connection secret;
- `get_public_key` as the mechanism by which the client learns the user public key after connecting.

Signflare v1 MUST support the bunker-initiated flow and all methods listed above.

Reference:

https://github.com/nostr-protocol/nips/blob/master/46.md

### 4.2 NIP-44

NIP-46 request and response payloads MUST use NIP-44.

Before decrypting an incoming NIP-44 payload from a Nostr event, Signflare MUST validate the outer Nostr event's public key and signature.

Signflare SHOULD use a maintained library implementation of NIP-44 rather than implementing NIP-44 cryptographic primitives directly.

Reference:

https://github.com/nostr-protocol/nips/blob/master/44.md

### 4.3 NIP-01

Signflare's relay transport MUST follow the NIP-01 WebSocket message model needed by NIP-46.

Kind `24133` is in the ephemeral event range defined by NIP-01. Signflare MUST NOT persist NIP-46 request or response events as relay event history.

Reference:

https://github.com/nostr-protocol/nips/blob/master/01.md

### 4.4 NIP-11

Signflare v1 MUST implement NIP-11 on the same URI used for the Nostr WebSocket endpoint.

An HTTP request to `/` with:

```http
Accept: application/nostr+json
```

MUST return a NIP-11 Relay Information Document.

The response MUST advertise Signflare as a restricted relay rather than a general-purpose Nostr relay.

The response MUST include:

```json
{
  "name": "Signflare",
  "description": "Restricted relay for Signflare NIP-46 remote signing.",
  "pubkey": "<admin-pubkey>",
  "supported_nips": [1, 11, 46],
  "software": "https://github.com/SnowCait/signflare",
  "limitation": {
    "restricted_writes": true
  }
}
```

The exact `version` MAY be added from the deployed application version.

The NIP-11 `pubkey` field MUST use the configured administrator public key.

The NIP-11 response MUST satisfy the CORS requirements defined by NIP-11.

Reference:

https://github.com/nostr-protocol/nips/blob/master/11.md

---

## 5. High-level Architecture

A deployment consists of one Worker and one logical `SignerHub` Durable Object instance.

```text
Nostr client
    |
    | WebSocket / NIP-01
    | kind:24133 / NIP-44
    v
Cloudflare Worker
    |
    +-- GET /                    landing page
    +-- GET / + NIP-11 Accept   relay information JSON
    +-- GET / + WebSocket       NIP-46 relay transport
    +-- /admin/*                Svelte administrative SPA
    +-- /admin/api/*            authenticated Admin API
            |
            v
      SignerHub Durable Object
            |
            +-- SQLite storage
            |     +-- identities
            |     +-- pairings
            |     +-- sessions
            |
            +-- minimal relay transport
            +-- NIP-46 dispatcher
            +-- permission enforcement
            +-- user-key encryption/decryption
```

The Worker MUST route all signer state to the same Durable Object instance, for example by using a stable name such as `signer`.

A deployment therefore represents one Signflare service containing zero or more user identities.

D1, Workers KV, and R2 are not required for v1.

---

## 6. Cloudflare Durable Object Model

Signflare MUST use a SQLite-backed Durable Object.

The Durable Object is responsible for:

- persistent identity storage;
- persistent pairing storage;
- persistent session storage;
- NIP-46 protocol processing;
- WebSocket connection state;
- NIP-01 subscription state;
- dispatching response events to connected clients.

The implementation MUST persist any state that must survive Durable Object eviction or restart.

The WebSocket implementation MUST use the Durable Objects Hibernation WebSocket API so that connected clients can remain connected while the Durable Object is evicted from memory.

Per-WebSocket transient state that is required after hibernation SHOULD be stored using WebSocket serialized attachments when it fits within Cloudflare's attachment limit. Larger or longer-lived state MUST be kept in Durable Object storage.

Cloudflare references:

- SQLite-backed Durable Object Storage  
  https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/
- Durable Object storage guidance  
  https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/
- WebSocket Hibernation  
  https://developers.cloudflare.com/durable-objects/best-practices/websockets/
- Durable Object class configuration  
  https://developers.cloudflare.com/durable-objects/reference/durable-objects-migrations/

---

## 7. Deployment Secrets and Configuration

The deployment MUST have the following Worker secrets:

```text
MASTER_ENCRYPTION_KEY
REMOTE_SIGNER_PRIVATE_KEY
```

The deployment MUST also define the following non-secret configuration value:

```text
ADMIN_PUBKEY
```

### 7.1 `MASTER_ENCRYPTION_KEY`

`MASTER_ENCRYPTION_KEY` is the root secret used to derive encryption keys for stored user private keys.

It MUST NOT be stored in the Durable Object database.

It MUST NOT be logged or returned by any API.

The value MUST contain at least 256 bits of cryptographically random key material.

### 7.2 `REMOTE_SIGNER_PRIVATE_KEY`

`REMOTE_SIGNER_PRIVATE_KEY` is the private key for the deployment-wide NIP-46 remote-signer keypair.

Using one remote-signer keypair for the entire deployment is a Signflare v1 design decision, not a requirement imposed by NIP-46. NIP-46 defines the remote-signer keypair separately from the user keypair and does not require a one-to-one mapping between them.

Signflare v1 intentionally shares one remote-signer keypair across all registered user identities because this keeps:

- `bunker://` addressing stable for the deployment;
- incoming NIP-46 `p`-tag routing simple;
- remote-signer secret management independent of the number of registered identities;
- identity registration independent of Worker redeployment;
- the NIP-46 transport layer separate from user-key storage.

The remote-signer keypair MUST be distinct in purpose from registered user private keys.

The corresponding remote-signer public key is used in:

- `bunker://` URLs;
- NIP-46 `p`-tag validation;
- NIP-46 response events;
- NIP-46 request/response encryption.

The remote-signer public key is connection material, not general public metadata. Signflare v1 MUST NOT publish it on the public landing page or in the NIP-11 document. It is disclosed to a client through a pairing-generated NIP-46 `bunker://` connection token.

This design has an explicit security tradeoff: compromise of the deployment-wide remote-signer private key affects the confidentiality and authenticity boundary of NIP-46 transport for all identities in that deployment. NIP-44 does not provide forward secrecy or post-compromise security, so recorded or future NIP-44 traffic may be affected by compromise of the relevant long-term transport key.

Compromise of `REMOTE_SIGNER_PRIVATE_KEY` alone MUST NOT provide the ability to decrypt registered user private keys at rest. At-rest user-key encryption uses the separate `MASTER_ENCRYPTION_KEY`.

The data model and session model MUST NOT assume that a remote-signer key and a user identity are the same keypair. This preserves the ability to introduce per-identity or multiple remote-signer keypairs in a future version.

The secret MUST NOT be stored in the Durable Object database.

It MUST NOT be logged or returned by administrative APIs.

### 7.3 `ADMIN_PUBKEY`

`ADMIN_PUBKEY` is the lowercase hexadecimal Nostr public key authorized to administer the deployment.

It is public configuration, not a secret.

It is used for:

- NIP-98 administrative login authorization;
- the NIP-11 `pubkey` field;
- display of the administrator identity on the public landing page.

Signflare v1 supports one administrator public key.

The corresponding administrator private key MUST NOT be provided to Signflare and MUST remain under the administrator's control.

Cloudflare Workers secret reference:

https://developers.cloudflare.com/workers/configuration/secrets/

---

## 8. User Identity Model

An identity represents one Nostr user keypair controlled by Signflare.

Each identity has exactly one Nostr user public key and one encrypted private key.

A deployment MAY contain many identities.

Signflare MUST NOT impose an application-level identity-count limit in v1.

The actual number of identities is bounded by available Durable Object storage and operational constraints.

The primary identifier for an identity is the lowercase hexadecimal Nostr public key.

Signflare MAY display or accept an `npub` representation at user-facing boundaries, but persistent and protocol-facing identity references SHOULD use the hexadecimal public key.

---

## 9. User Private-key Registration

The administrative API MUST accept either:

- an `nsec` value; or
- a 32-byte hexadecimal Nostr private key.

On registration, Signflare MUST:

1. decode and validate the private key;
2. derive the corresponding Nostr public key;
3. reject the registration if the public key already exists;
4. encrypt the private key;
5. store only the encrypted representation and required encryption metadata;
6. return the public identity information;
7. never return the private key.

The Web Admin UI MUST submit the private key only in the HTTPS request body.

The private key MUST NOT be placed in:

- the request URL or query string;
- browser history;
- `localStorage`;
- `sessionStorage`;
- IndexedDB;
- client-readable cookies.

The private-key input MUST be cleared after the registration request completes or fails.

---

## 10. Encryption of Stored User Private Keys

Durable Object storage encryption at rest is not treated as the only protection for user private keys.

Signflare MUST additionally encrypt each user private key before storing it.

NIP-44 MUST NOT be reused as the at-rest storage format. NIP-44 is used for NIP-46 transport between Nostr keypairs; Signflare's storage encryption instead uses a deployment-controlled symmetric root key and standard Web Crypto primitives. Transport encryption and storage encryption are separate security domains.

### 10.1 Key derivation

For each identity, Signflare MUST generate a cryptographically random KDF salt.

An identity-specific AES-256-GCM key MUST be derived from `MASTER_ENCRYPTION_KEY` using HKDF-SHA-256.

The HKDF context MUST bind the derived key to the identity and key version.

The HKDF context MUST use:

```text
signflare:identity:<pubkey>:v<key_version>
```

This value is normative for v1.

### 10.2 Encryption algorithm

The stored private key MUST be encrypted using AES-256-GCM.

For each encryption operation:

- a fresh random IV MUST be generated;
- the public key and encryption-key version MUST be authenticated as additional authenticated data;
- the ciphertext, IV, salt, and key version MUST be stored.

The Worker runtime's Web Crypto implementation supports HKDF and AES-GCM and SHOULD be used for these operations.

Cloudflare Web Crypto reference:

https://developers.cloudflare.com/workers/runtime-apis/web-crypto/

### 10.3 Key version

Every encrypted identity record MUST contain an integer `key_version`.

v1 records use:

```text
key_version = 1
```

The schema MUST preserve this field so a future release can rotate the master encryption key without changing the identity model.

Automated master-key rotation is not part of v1.

### 10.4 Decryption lifetime

The decrypted user private key SHOULD exist in memory only for the cryptographic operation that requires it.

The implementation SHOULD overwrite mutable byte buffers after use where practical.

JavaScript runtimes do not provide a guarantee that sensitive data has been physically erased from all memory copies; Signflare MUST NOT claim otherwise.

---

## 11. Persistent Storage Schema

The implementation MAY evolve column names during implementation, but the following logical data model is normative.

### 11.1 `identities`

```sql
CREATE TABLE identities (
  pubkey TEXT PRIMARY KEY,
  encrypted_private_key BLOB NOT NULL,
  iv BLOB NOT NULL,
  kdf_salt BLOB NOT NULL,
  key_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
```

Requirements:

- `pubkey` MUST be the lowercase hexadecimal Nostr public key.
- plaintext private keys MUST NOT be stored.
- `key_version` MUST be stored for every row.

### 11.2 `pairings`

```sql
CREATE TABLE pairings (
  id TEXT PRIMARY KEY,
  identity_pubkey TEXT NOT NULL,
  secret_hash BLOB NOT NULL UNIQUE,
  permissions TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX pairings_identity_pubkey
ON pairings(identity_pubkey);
```

Requirements:

- the one-time pairing secret itself MUST NOT be stored;
- only a cryptographic hash of the secret MUST be stored;
- permissions MUST be stored in a deterministic/canonical representation;
- each pairing belongs to one identity;
- each pairing expires;
- each pairing can establish at most one successful session.

### 11.3 `sessions`

```sql
CREATE TABLE sessions (
  client_pubkey TEXT PRIMARY KEY,
  identity_pubkey TEXT NOT NULL,
  permissions TEXT NOT NULL,

  client_name TEXT,
  client_url TEXT,
  client_image TEXT,

  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL
);

CREATE INDEX sessions_identity_pubkey
ON sessions(identity_pubkey);
```

The primary lookup key is the NIP-46 client public key because incoming NIP-46 requests identify the client by the outer event's `pubkey`.

With a deployment-wide shared remote-signer keypair, one client public key MUST map to at most one user identity at a time.

A client that needs concurrent sessions for multiple identities should use distinct client keypairs, which is compatible with the NIP-46 client-keypair model.

### 11.4 `admin_sessions`

```sql
CREATE TABLE admin_sessions (
  token_hash BLOB PRIMARY KEY,
  admin_pubkey TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
```

Requirements:

- the raw browser session token MUST NOT be stored;
- only a cryptographic hash of the session token MUST be stored;
- `admin_pubkey` MUST equal the configured `ADMIN_PUBKEY` when the session is created;
- the session lifetime MUST be exactly 12 hours from creation in v1;
- activity MUST NOT extend the session lifetime;
- every authenticated Admin API request MUST verify that the stored `admin_pubkey` still equals the currently configured `ADMIN_PUBKEY`;
- changing `ADMIN_PUBKEY` therefore invalidates sessions issued to the previous administrator;
- expired administrative sessions MUST be rejected and MAY be removed lazily.

### 11.5 `admin_auth_events`

```sql
CREATE TABLE admin_auth_events (
  event_id TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
```

This table prevents replay of NIP-98 login events.

Requirements:

- a successfully consumed NIP-98 login event ID MUST be recorded before the login is accepted;
- the same event ID MUST NOT authenticate a second login;
- insertion of the event ID and issuance of the administrative session MUST be coordinated so concurrent replay attempts cannot both succeed;
- rows MAY be removed lazily after the NIP-98 authentication window has elapsed.

### 11.6 Schema migrations

The implementation MUST have an explicit schema initialization/migration mechanism.

Future schema changes MUST be possible without deleting existing identities.

---

## 12. Identity Deletion

Deleting an identity MUST remove the identity from active application state.

The deletion operation MUST remove:

1. sessions associated with the identity;
2. unused pairings associated with the identity;
3. the encrypted identity record.

These changes SHOULD occur atomically.

After deletion:

- the user private key MUST no longer be available through Signflare;
- existing NIP-46 clients for that identity MUST no longer be authorized;
- existing pairing secrets for that identity MUST no longer work.

The documentation MUST NOT describe identity deletion as guaranteed physical secure erasure.

SQLite-backed Durable Objects provide Point-in-Time Recovery, and infrastructure-level recovery may retain historical database states for the provider-defined recovery window.

Cloudflare PITR reference:

https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/

---

## 13. Pairing Model

Signflare v1 uses remote-signer-initiated `bunker://` connections.

An administrator creates a pairing for a specific identity and permission set.

The pairing MUST:

- contain a cryptographically random secret;
- expire 10 minutes after creation;
- be usable for one successful session only.

The returned connection URL has the form:

```text
bunker://<remote-signer-pubkey>?relay=<relay-url>&secret=<one-time-secret>
```

The raw pairing secret MUST be returned only when the pairing is created.

The database MUST store only a hash of the pairing secret.

After a successful connection, the pairing MUST be consumed so the same secret cannot establish another session.

The pairing and its `bunker://` connection token are initial authorization material. They are not required for later WebSocket reconnections while the resulting session remains valid.

The client MUST NOT rely on the one-time pairing secret after a successful connection. Subsequent use is based on the persisted client keypair, the remote-signer public key, the relay URL, and the server-side session.

Expired pairings MAY be removed lazily during pairing creation, connection processing, or other administrative operations. A scheduled cleanup job is not required for v1.

---

## 14. Session Model

A NIP-46 session binds:

```text
client pubkey -> user identity -> granted permissions
```

Sessions are persistent.

A session remains valid until one of the following occurs:

- the client sends `logout`;
- an administrator revokes the session;
- the identity is deleted.

v1 does not impose an automatic session expiration time.

A pairing is required only to establish a new session. Once a session exists, the client MAY reconnect to the WebSocket relay using the same client keypair and continue using that session without creating another pairing or sending another NIP-46 `connect`.

WebSocket reconnection and NIP-46 session establishment are separate concepts:

```text
WebSocket disconnected
        |
        v
WebSocket reconnect with the same client keypair
        |
        v
existing Signflare session remains valid
```

After a successful initial pairing, the client SHOULD persist the connection information required by its NIP-46 implementation, including the client keypair, remote-signer public key, and relay URL. The one-time pairing secret is no longer required and MUST NOT be reusable.

A new pairing is required when:

- the client keypair is lost or intentionally replaced;
- the client sends `logout`;
- an administrator revokes the session;
- the identity is deleted;
- a new client or device needs its own session;
- the existing session is revoked in order to establish a different permission set.

Each successful authorized operation SHOULD update `last_used_at`.

Client metadata MAY be stored for administrative display.

---

## 15. Client Metadata

NIP-46 allows optional client metadata containing fields such as:

- `name`
- `url`
- `image`

Signflare MAY persist these fields with the session.

Client metadata is unauthenticated input.

It MUST be treated only as a display hint.

It MUST NOT affect:

- identity selection;
- permission grants;
- pairing validation;
- authorization decisions.

---

## 16. Permission Model

Signflare uses deny-by-default authorization.

A pairing contains the maximum permissions an administrator is willing to grant.

Supported v1 permission forms are:

```text
sign_event
sign_event:<kind>
nip04_encrypt
nip04_decrypt
nip44_encrypt
nip44_decrypt
```

`sign_event` grants permission to sign any event kind.

`sign_event:<kind>` grants permission only for the specified event kind.

The administrative API and Web Admin UI MAY support the convenience value:

```text
all
```

`all` MUST expand to the explicit v1 permission set:

```text
sign_event
nip04_encrypt
nip04_decrypt
nip44_encrypt
nip44_decrypt
```

The stored permission representation SHOULD contain the expanded permissions rather than the string `all`.

### 16.1 Requested permissions

NIP-46 requested permissions are optional.

If the client supplies requested permissions during `connect`, the session permissions MUST be the intersection of:

```text
requested permissions
∩
pairing permissions
```

Permission intersection MUST account for the relationship between:

```text
sign_event
```

and:

```text
sign_event:<kind>
```

If the client omits requested permissions, the session MUST receive the pairing permissions.

An omitted requested-permissions field MUST NOT create a session with an empty permission set solely because the field was absent.

### 16.2 Control methods

The following methods do not require an additional explicit session permission:

- `ping`
- `get_public_key`
- `switch_relays`
- `logout`

They still require an established session.

`connect` is the method used to establish a session and is handled separately.

---

## 17. Minimal Relay Transport

Signflare provides its own Nostr WebSocket relay endpoint for NIP-46 traffic.

The same deployment URL MAY serve HTTP and WebSocket traffic, with WebSocket Upgrade requests routed to the `SignerHub` Durable Object.

The relay is intentionally not a general-purpose Nostr relay.

It MUST NOT persist Nostr events.

### 17.1 Supported NIP-01 messages

The v1 relay MUST support the subset required for NIP-46 clients:

Client to relay:

```text
EVENT
REQ
CLOSE
```

Relay to client:

```text
EVENT
OK
EOSE
CLOSED
NOTICE
```

### 17.2 Subscriptions

A client can subscribe to NIP-46 response events using NIP-01 filters.

Because Signflare stores no historical NIP-46 events, a valid `REQ` MUST receive `EOSE` promptly after the initial query phase.

The subscription MUST remain active for matching live response events until:

- the client sends `CLOSE`;
- the WebSocket closes; or
- the subscription is replaced according to NIP-01 behavior.

Subscription state needed after Durable Object hibernation MUST be reconstructable from persistent or serialized WebSocket state.

### 17.3 Relay filtering

The relay is restricted to NIP-46 traffic and MUST reject generic Nostr subscriptions.

Every accepted `REQ` filter MUST:

- be restricted to kind `24133`;
- specify the deployment's remote-signer public key in `authors`;
- include a `#p` filter identifying the client public key that should receive the response.

A filter that permits kinds other than `24133`, omits the remote-signer author restriction, or omits `#p` MUST be rejected.

The relay does not need to prove ownership of the `#p` value at subscription time. NIP-01 `REQ` messages are not signed. Authorization of NIP-46 operations is enforced separately through signed request events, pairings, sessions, and permissions.

The relay MUST NOT become an event storage service or general-purpose query relay as a side effect of filter support.

---

## 18. Incoming EVENT Processing

For an incoming `EVENT`, Signflare MUST perform validation in this order:

1. parse the NIP-01 message;
2. validate the event structure;
3. require kind `24133`;
4. validate the event ID and Schnorr signature;
5. require a `p` tag addressed to the deployment's remote-signer public key;
6. decrypt the NIP-44 content using the remote-signer private key and client public key;
7. parse and validate the NIP-46 request;
8. dispatch the NIP-46 method;
9. create and publish a signed NIP-46 response event.

NIP-44 decryption MUST NOT occur before the outer event's signature has been validated.

Malformed or invalid events MUST be rejected without leaking secret data or internal stack traces.

---

## 19. NIP-46 Request Validation

A decrypted request has the logical form:

```json
{
  "id": "<request-id>",
  "method": "<method>",
  "params": ["..."]
}
```

Signflare MUST validate:

- `id` is a non-empty string;
- `method` is a string;
- `params` is an array of strings;
- the parameter count and content are valid for the requested method.

Unknown or unsupported methods MUST produce a NIP-46 error response.

---

## 20. `connect`

`connect` establishes a new persistent session.

The request MUST be processed approximately as follows:

```text
incoming kind:24133 event
        |
        v
validate outer event
        |
        v
decrypt NIP-44 payload
        |
        v
validate remote-signer pubkey parameter
        |
        v
validate pairing secret
        |
        +-- invalid/expired --> error
        |
        v
check existing client session
        |
        +-- already connected --> error
        |
        v
calculate granted permissions
        |
        v
create session + consume pairing atomically
        |
        v
return connect response
```

The remote-signer public key parameter MUST match the deployment's remote-signer public key.

A valid one-time secret MUST correspond to an unexpired pairing.

Session creation and pairing consumption MUST be atomic.

The successful response MUST follow NIP-46 secret-acknowledgement semantics for the bunker flow.

After success, reuse of the same pairing secret MUST fail.

---

## 21. Session-required Requests

Every NIP-46 method other than `connect` requires an existing session.

For such requests:

- the outer event's `pubkey` is the client public key;
- Signflare MUST look up the session by that client public key;
- Signflare MUST resolve the session's identity and permissions;
- requests without a session MUST be rejected as not connected.

---

## 22. `get_public_key`

`get_public_key` MUST return the user public key for the identity bound to the session.

It MUST NOT return the deployment's remote-signer public key unless the two happen to represent the same keypair, which v1 does not require and should not assume.

---

## 23. `sign_event`

`sign_event` receives a JSON-stringified unsigned event template.

The request MUST validate at least:

- `kind`
- `content`
- `tags`
- `created_at`

Signflare MUST NOT trust client-supplied values for:

- `pubkey`
- `id`
- `sig`

if present.

The final signed event MUST be constructed and signed using the private key of the session's user identity.

The operation requires either:

```text
sign_event
```

or:

```text
sign_event:<event-kind>
```

The response is the JSON-stringified signed event required by NIP-46.

---

## 24. NIP-04 Methods

Signflare MUST implement:

- `nip04_encrypt`
- `nip04_decrypt`

The operation MUST use:

- the user private key associated with the session; and
- the third-party public key supplied by the request.

Each method requires its corresponding permission.

The implementation SHOULD use a maintained Nostr library implementation rather than implementing NIP-04 primitives directly.

---

## 25. NIP-44 Methods

Signflare MUST implement:

- `nip44_encrypt`
- `nip44_decrypt`

The operation MUST use:

- the user private key associated with the session; and
- the third-party public key supplied by the request.

Each method requires its corresponding permission.

The implementation SHOULD use a maintained Nostr library implementation rather than implementing NIP-44 primitives directly.

---

## 26. `ping`

`ping` requires an established session but no additional permission.

It MUST return:

```text
pong
```

---

## 27. `switch_relays`

v1 exposes only the Signflare-hosted relay and does not maintain alternate outbound relay connections.

For an already connected client using the Signflare relay, `switch_relays` SHOULD return `null` unless the deployment later gains a different configured relay set.

The implementation MUST preserve the method so compatible NIP-46 clients can call it.

---

## 28. `logout`

`logout` requires an established session.

Signflare MUST send an acknowledgement before removing the session, consistent with NIP-46.

After the acknowledgement is prepared/sent, the session MUST be deleted.

Further requests from the same client public key MUST fail until a new `connect` succeeds.

`logout` is not the only session revocation mechanism; administrators can revoke sessions independently.

---

## 29. NIP-46 Responses

A response event MUST:

- use kind `24133`;
- be authored by the deployment's remote-signer keypair;
- contain a `p` tag identifying the client public key;
- contain a NIP-44 encrypted response payload;
- be signed as a valid Nostr event.

The decrypted response payload has the NIP-46 form:

```json
{
  "id": "<request-id>",
  "result": "<result-string>",
  "error": "<optional-error-string>"
}
```

Error strings MUST be safe for untrusted clients.

They MUST NOT contain:

- stack traces;
- Worker secrets;
- user private keys;
- decrypted unrelated payloads;
- database internals that expose sensitive information.

---

## 30. Administrative API and Authentication

Administrative endpoints are served under `/admin/api/*`.

Except for the login endpoint, administrative API requests MUST require a valid administrative session cookie.

The browser UI and Admin API are same-origin. v1 does not require cross-origin CORS support for administrative endpoints.

No administrative endpoint may return:

- `MASTER_ENCRYPTION_KEY`;
- `REMOTE_SIGNER_PRIVATE_KEY`;
- a plaintext registered user private key;
- stored encrypted key material unless explicitly required for a future backup format;
- an administrative session token after its initial cookie issuance.

### 30.1 NIP-98 login

```text
POST /admin/api/login
```

Login MUST use NIP-98 HTTP authentication.

The browser SHOULD obtain the administrator signature through a NIP-07 provider using `window.nostr.signEvent()`.

The server MUST validate:

- the Nostr event signature;
- `kind === 27235`;
- `created_at` within 60 seconds;
- the `u` tag exactly matches the absolute login request URL;
- the `method` tag matches `POST`;
- `event.pubkey === ADMIN_PUBKEY`.

If the login request has a body, Signflare MUST require and validate the NIP-98 `payload` tag for that body.

A valid NIP-98 login event MUST be single-use. Before accepting the login, Signflare MUST atomically ensure that the event ID has not already been consumed and record it as consumed. A replay of the same event ID MUST return `401 Unauthorized`.

After successful authentication, Signflare MUST generate a cryptographically random administrative session token, store only its hash, and return the raw token only as a cookie.

The cookie MUST use `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/admin`.

The administrative session lifetime MUST be exactly 12 hours from login in v1. Activity MUST NOT extend the expiration time.

Every authenticated Admin API request MUST verify that the session's stored administrator public key still equals the current `ADMIN_PUBKEY`.

The raw NIP-98 authorization event and administrative session token MUST NOT be logged.

### 30.2 Current administrative session

```text
GET /admin/api/session
```

This endpoint reports whether the browser has a valid administrative session and MAY return the administrator public key.

It MUST NOT return the session token.

### 30.3 Logout

```text
POST /admin/api/logout
```

Logout MUST invalidate the current administrative session and clear the session cookie.

### 30.4 Status

```text
GET /admin/api/status
```

The response SHOULD include:

```json
{
  "identities": 123,
  "sessions": 15,
  "pairings": 2,
  "databaseSize": 1048576
}
```

The remote-signer public key MUST NOT be included in this general administrative status response unless required for an explicit connection-material operation.

`databaseSize` SHOULD use the SQLite-backed Durable Object database-size API.

### 30.5 Add identity

```text
POST /admin/api/identities
```

Request:

```json
{
  "privateKey": "nsec1... or 64-char hex"
}
```

Success response SHOULD include:

```json
{
  "pubkey": "<hex>",
  "npub": "npub1...",
  "createdAt": 1234567890
}
```

Expected errors:

- invalid key: `400 Bad Request`;
- duplicate identity: `409 Conflict`;
- storage full: `507 Insufficient Storage`.

### 30.6 List identities

```text
GET /admin/api/identities
```

The response MUST expose public identity information only.

It MUST NOT expose encrypted private-key ciphertext, IVs, KDF salts, or plaintext private keys.

### 30.7 Delete identity

```text
DELETE /admin/api/identities/:pubkey
```

The endpoint MUST remove the identity and its related sessions and pairings.

Successful deletion SHOULD return `204 No Content`.

### 30.8 Create pairing

```text
POST /admin/api/identities/:pubkey/pairings
```

Request example:

```json
{
  "permissions": [
    "sign_event:1",
    "nip44_encrypt",
    "nip44_decrypt"
  ]
}
```

Convenience request:

```json
{
  "permissions": "all"
}
```

Success response:

```json
{
  "bunkerUrl": "bunker://...",
  "expiresAt": 1234567890
}
```

The raw pairing secret and remote-signer public key are connection material and MUST be exposed only through the newly generated pairing response or equivalent explicit connection-material UI.

### 30.9 List sessions

```text
GET /admin/api/identities/:pubkey/sessions
```

The response MAY include client public key, granted permissions, stored client metadata, creation time, and last-used time.

### 30.10 Revoke session

```text
DELETE /admin/api/sessions/:clientPubkey
```

Revocation MUST take effect immediately for subsequent NIP-46 requests.

### 30.11 Browser request protections

State-changing administrative requests MUST be same-origin.

In addition to `SameSite=Strict` cookies, the server SHOULD validate the `Origin` header for state-changing browser requests.

Third-party scripts are not required for administrative authentication or operation and MUST NOT be loaded by the v1 Admin UI.

---

## 31. Web Administration UI

Signflare v1 provides a browser-based administrative interface at `/admin/*`.

The Admin UI is a client-side Svelte application.

The frontend stack is:

```text
Svelte
Vite
TypeScript
Workers Static Assets
```

SvelteKit MUST NOT be used in v1.

Hono remains the server-side framework responsible for:

- HTTP routing;
- `/admin/api/*`;
- NIP-11;
- public landing-page routing;
- WebSocket upgrade routing.

Svelte is responsible only for browser UI.

### 31.1 Deployment model

The Svelte application MUST be built as static assets and deployed with the same Cloudflare Worker deployment using Workers Static Assets.

The `/admin/*` browser routes SHOULD use SPA fallback behavior.

Requests to server-controlled routes such as `/`, `/admin/api/*`, and WebSocket upgrade traffic MUST be routed through the Worker as required by this design.

### 31.2 Authentication UI

When no administrative session exists, `/admin` MUST present a Nostr login action.

The login flow SHOULD:

1. detect `window.nostr`;
2. obtain or verify the administrator public key;
3. create the NIP-98 event for `POST /admin/api/login`;
4. request the signature through NIP-07;
5. submit the NIP-98 authorization to Signflare;
6. rely on the resulting HttpOnly administrative session cookie for later requests.

The Svelte application MUST NOT store the administrator private key.

The Svelte application MUST NOT persist authentication tokens in `localStorage`, `sessionStorage`, IndexedDB, or client-readable cookies.

If no NIP-07 provider is available, the UI SHOULD explain that a NIP-07-capable browser signer is required for v1 administration.

### 31.3 Administrative features

The v1 Admin UI MUST provide:

- deployment status;
- identity list;
- identity registration;
- identity deletion;
- pairing creation with permission selection;
- display/copy of the newly created `bunker://` connection token;
- session list;
- session revocation;
- administrator logout.

A pairing connection token SHOULD be visually treated as sensitive connection material because it contains a one-time secret.

### 31.4 Private-key input

Identity registration MUST use a password-style input control or equivalent obscured entry.

The Admin UI MUST NOT persist the entered private key in browser storage.

The UI MUST clear the input after the registration request completes or fails.

The v1 Admin UI MUST NOT include analytics, advertising, third-party JavaScript, remote component libraries, or CDN-hosted scripts.

### 31.5 UI scope

The Admin UI SHOULD remain small and functional.

v1 does not require:

- server-side rendering;
- search-engine optimization for `/admin`;
- a component framework in addition to Svelte;
- a client-side state-management dependency;
- a separate frontend deployment.

---

## 32. Storage Exhaustion

Signflare MUST NOT impose an arbitrary maximum identity count.

Instead, it relies on the Durable Object's actual storage capacity.

When a SQLite-backed Durable Object reaches its storage limit, Cloudflare documents that writes fail with `SQLITE_FULL`, while reads and deletes continue to work.

Signflare MUST:

- detect storage-full write failures;
- surface them to the administrative caller;
- return `507 Insufficient Storage` for an identity-registration failure caused by full storage;
- keep identity deletion functional so an administrator can recover capacity;
- log a safe administrative error without secret material.

Signflare MAY report the current database size in administrative status/error information.

Cloudflare references:

- Durable Object limits and storage exhaustion behavior  
  https://developers.cloudflare.com/durable-objects/reference/faq/
- SQLite database size API  
  https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/

As of the design date, Cloudflare documents per-object SQLite storage limits of 10 GB on Workers Paid and 1 GB on Workers Free. These are infrastructure limits, not Signflare identity-count limits, and may change independently of Signflare.

---

## 33. Operational Safety

Signflare handles long-lived private keys and MUST treat all administrative and protocol inputs as untrusted.

The implementation MUST:

- validate Nostr signatures before NIP-44 decryption;
- validate public-key and private-key encodings;
- validate method parameters;
- validate permission syntax;
- reject unknown methods;
- prevent pairing reuse;
- prevent expired pairing use;
- prevent unauthorized signing/encryption/decryption;
- avoid secret values in logs;
- avoid stack traces in protocol errors;
- reject clearly unreasonable input sizes before expensive cryptographic processing.

Exact size limits may be selected during implementation based on Workers runtime limits and compatibility testing, but they MUST be documented in code and tested.

---

## 34. Logging

Logs MAY contain:

- request class/method;
- public keys;
- identity counts;
- session counts;
- safe error categories;
- database size;
- timing/operational metadata.

Logs MUST NOT contain:

- user private keys;
- `nsec` values;
- `MASTER_ENCRYPTION_KEY`;
- `REMOTE_SIGNER_PRIVATE_KEY`;
- raw pairing secrets;
- decrypted NIP-46 plaintext unless explicitly proven non-sensitive;
- plaintext from `nip04_decrypt` or `nip44_decrypt`.

---

## 35. Development Baseline

Signflare v1 uses the following implementation baseline:

- TypeScript for application code;
- Node.js 24 for local tooling;
- Wrangler for Cloudflare development and deployment;
- Hono for server-side HTTP routing;
- Svelte for the browser-based Admin UI;
- Vite for frontend development and build;
- Workers Static Assets for serving the built Svelte application;
- Cloudflare native Durable Object APIs for signer state and WebSocket handling;
- `ctx.storage.sql` directly for SQLite-backed Durable Object persistence;
- `nostr-tools` for Nostr primitives and interoperability testing where its current APIs support the required behavior;
- Cloudflare Workers Web Crypto for at-rest key protection;
- Vitest with `@cloudflare/vitest-plugin` for Worker-runtime testing;
- ESLint and Prettier for static analysis and formatting.

SvelteKit MUST NOT be used in v1. Hono owns the server/API/WebSocket layer; Svelte owns browser UI only.

Exact dependency versions are intentionally not specified in this document. `package.json` and the lockfile are the source of truth for installed versions.

### 35.1 Dependency policy

Signflare handles long-lived private keys, so the runtime dependency surface SHOULD remain small.

v1 MUST NOT introduce an additional dependency when the required functionality is already provided by the Cloudflare runtime, the JavaScript/Node.js standard platform available to the project, or an already selected dependency.

In particular, v1 uses:

```text
Server routing               Hono
Browser UI                   Svelte
Frontend build               Vite
Static frontend delivery     Workers Static Assets
Nostr primitives             nostr-tools
Durable Object persistence   ctx.storage.sql
WebSocket handling           Cloudflare Durable Object APIs
At-rest cryptography         Workers Web Crypto
Worker-runtime testing       Vitest + @cloudflare/vitest-plugin
```

The following are intentionally excluded from v1 unless a concrete implementation requirement demonstrates that they are necessary:

- SvelteKit;
- ORM or database abstraction frameworks;
- additional WebSocket libraries;
- additional cryptography libraries for at-rest key encryption;
- additional client-side state-management frameworks;
- UI component frameworks;
- general-purpose dependency injection frameworks.

No ORM is used in v1. SQL schema initialization, migrations, queries, and transactions SHOULD use the Durable Object SQLite API directly.

No additional WebSocket library is used in v1. NIP-46 relay connections SHOULD use the Cloudflare Durable Objects WebSocket Hibernation API directly.

No additional at-rest cryptography library is used in v1. The Signflare storage envelope MUST use the Web Crypto primitives defined in this document.

### 35.2 Frontend boundary

Svelte MUST be compiled as a client-side application.

The browser application communicates with Signflare through same-origin `/admin/api/*` requests.

The Admin UI MUST NOT contain Worker secrets, registered user private keys after submission, the deployment remote-signer private key, or any other server-side secret.

SvelteKit server routes, server-side rendering, and SvelteKit adapters are outside the v1 architecture.

### 35.3 Library boundaries

`nostr-tools` SHOULD be used for established Nostr operations such as:

- public-key derivation;
- Nostr event validation and signing;
- NIP-04 encryption and decryption;
- NIP-44 encryption and decryption;
- NIP-98 token construction/validation where its current API is suitable;
- `nsec` / `npub` encoding and decoding where supported;
- NIP-46 client-side interoperability tests.

Signflare MUST still implement its own server-side application logic for identity selection, pairing authorization, session persistence, permission enforcement, NIP-46 request dispatch, administrative authorization policy, and administrative operations.

The project SHOULD prefer maintained protocol implementations over reimplementing Nostr cryptographic primitives.

Signflare MUST NOT implement custom cryptographic primitives.

The at-rest key-protection mechanism is a Signflare-specific storage envelope built exclusively from standard Web Crypto primitives defined in this document: HKDF-SHA-256 for key derivation and AES-256-GCM for authenticated encryption. Signflare code may define the storage format, domain-separation context, and metadata layout, but MUST NOT implement its own cipher, MAC, hash, KDF, or random-number generator.

---

## 36. Deploy to Cloudflare

The repository README MUST include a Deploy to Cloudflare button.

The deployment requires:

Secrets:

```dotenv
MASTER_ENCRYPTION_KEY=
REMOTE_SIGNER_PRIVATE_KEY=
```

Non-secret configuration:

```dotenv
ADMIN_PUBKEY=
```

The deployment documentation MUST explain:

- how to generate valid random values for the two secrets;
- that `ADMIN_PUBKEY` is the Nostr public key authorized to access the Admin UI;
- that the administrator private key is never uploaded to Signflare;
- that a NIP-07-capable browser signer is required for v1 Web Admin login.

The Svelte Admin UI MUST be deployed as Workers Static Assets in the same deployment as the Worker.

Adding or deleting identities after deployment MUST NOT require a Worker redeployment.

Cloudflare references:

- Deploy to Cloudflare buttons  
  https://developers.cloudflare.com/workers/platform/deploy-buttons/
- Workers Static Assets  
  https://developers.cloudflare.com/workers/static-assets/
- SPA routing  
  https://developers.cloudflare.com/workers/static-assets/routing/single-page-application/
- Cloudflare Vite plugin  
  https://developers.cloudflare.com/workers/vite-plugin/

---

## 37. Public Root Endpoint

The root URI `/` serves three roles, selected by request headers.

Routing priority MUST be:

1. WebSocket Upgrade requests;
2. NIP-11 requests with `Accept: application/nostr+json`;
3. ordinary HTTP requests.

### 37.1 WebSocket

A request to `/` with a valid WebSocket Upgrade MUST be routed to the restricted NIP-46 relay transport.

The WebSocket endpoint is the relay URL used in generated NIP-46 `bunker://` connection tokens.

### 37.2 NIP-11

A request to `/` with:

```http
Accept: application/nostr+json
```

MUST return the NIP-11 Relay Information Document defined in this design.

The response MUST advertise:

```json
{
  "name": "Signflare",
  "description": "Restricted relay for Signflare NIP-46 remote signing.",
  "pubkey": "<admin-pubkey>",
  "supported_nips": [1, 11, 46],
  "software": "https://github.com/SnowCait/signflare",
  "limitation": {
    "restricted_writes": true
  }
}
```

The response MUST include the CORS headers required by NIP-11.

The NIP-11 document MUST omit `self` in v1. The deployment-wide remote-signer public key MUST NOT be exposed through NIP-11.

### 37.3 Landing page

An ordinary browser request to `/` MUST return a small HTML landing page.

The landing page is informational only. It is not an administration interface.

It SHOULD show:

- the Signflare name;
- a short description such as `Self-hosted Nostr remote signer running on Cloudflare Workers.`;
- an explicit statement that the endpoint is a restricted NIP-46 relay and is not a general-purpose Nostr relay;
- the administrator public key;
- the WebSocket relay URL;
- NIP-46 compatibility;
- a link to the Signflare source repository;
- a Deploy to Cloudflare link or button.

The landing page MUST NOT expose:

- registered identity counts;
- session counts;
- pairing counts;
- database size;
- Admin API credentials or operational details;
- permissions for existing sessions or pairings;
- any private key or other secret material.

Rendering the landing page SHOULD NOT require a Durable Object or SQLite read. Static HTML plus deployment-level public information is sufficient.

A dedicated `/health` or `/healthz` endpoint is not part of v1.

---

## 38. Error Model

### 38.1 Administrative HTTP errors

Suggested mapping:

```text
400  invalid request
401  unauthorized
404  resource not found
409  duplicate or conflicting state
507  insufficient storage
500  unexpected internal error
```

### 38.2 NIP-46 errors

The protocol layer SHOULD expose stable safe categories such as:

```text
invalid request
invalid secret
pairing expired
already connected
not connected
permission denied
unsupported method
internal error
```

Internal exceptions MUST be mapped to safe protocol errors.

---

## 39. Testing Requirements

v1 MUST have automated tests covering the following areas.

### 39.1 At-rest cryptography

- valid key encryption/decryption round trip;
- different identities derive independent encryption contexts;
- incorrect master key fails decryption;
- modified ciphertext fails authentication;
- modified authenticated metadata fails authentication;
- `key_version` participates in the encryption context.

### 39.2 Identity management

- register from `nsec`;
- register from hex;
- reject invalid key;
- reject duplicate key;
- list identities without exposing secret material;
- delete identity;
- delete identity removes associated sessions and pairings;
- storage-full registration returns the administrative storage error.

### 39.3 Pairing lifecycle

- create pairing;
- enforce 10-minute expiration;
- valid secret establishes a session;
- wrong secret fails;
- expired secret fails;
- successful pairing cannot be reused;
- pairing consumption is atomic with session creation.

### 39.4 Permissions

- deny by default;
- exact method permission;
- `sign_event:<kind>`;
- `sign_event` wildcard;
- requested permissions intersect pairing permissions;
- omitted requested permissions use pairing permissions;
- `all` expands to the explicit permission set;
- unauthorized operations fail.

### 39.5 Sessions

- connect creates a persistent session;
- request without session fails;
- revoke removes authorization;
- logout acknowledges then removes authorization;
- request after logout fails;
- identity deletion removes authorization;
- WebSocket reconnect with the same client keypair reuses the existing session without a new pairing or NIP-46 `connect`;
- a revoked or logged-out session requires a new pairing before that client can establish a new session.

### 39.6 NIP-46 methods

- `connect`;
- `ping`;
- `get_public_key`;
- `sign_event`;
- `nip04_encrypt`;
- `nip04_decrypt`;
- `nip44_encrypt`;
- `nip44_decrypt`;
- `switch_relays`;
- `logout`;
- unknown method error.

### 39.7 Protocol validation

- invalid event signature;
- invalid event ID;
- wrong event kind;
- missing remote-signer `p` tag;
- malformed NIP-44 payload;
- malformed NIP-46 request;
- response is signed by the remote-signer key;
- response contains the client `p` tag.

### 39.8 Relay behavior

- WebSocket upgrade;
- valid NIP-46-specific `REQ`;
- rejection of `REQ` that allows kinds other than `24133`;
- rejection of `REQ` without the remote-signer `authors` restriction;
- rejection of `REQ` without `#p`;
- `EOSE`;
- live matching response delivery;
- `CLOSE`;
- accepted `EVENT`;
- rejected `EVENT`;
- state restoration after Durable Object hibernation where test tooling permits.

### 39.9 Public root and NIP-11

- ordinary `GET /` returns the landing page;
- WebSocket Upgrade on `/` takes precedence over ordinary HTTP handling;
- `Accept: application/nostr+json` returns NIP-11 JSON;
- NIP-11 advertises `supported_nips: [1, 11, 46]`;
- NIP-11 advertises `limitation.restricted_writes: true`;
- NIP-11 `pubkey` equals the administrator public key;
- NIP-11 omits `self`;
- NIP-11 does not expose the remote-signer public key;
- NIP-11 response includes required CORS headers;
- landing page does not require identity/session/pairing database reads;
- landing page does not expose the remote-signer public key.

### 39.10 Administrative authentication

- NIP-98 login accepts a valid event signed by `ADMIN_PUBKEY`;
- login rejects another pubkey;
- login rejects an invalid signature;
- login rejects the wrong kind;
- login rejects a timestamp outside the 60-second window;
- login rejects a mismatched absolute URL;
- login rejects a mismatched HTTP method;
- request bodies require a valid NIP-98 payload hash;
- reuse of the same NIP-98 event ID is rejected;
- concurrent replay attempts cannot both create administrative sessions;
- successful login issues an HttpOnly, Secure, SameSite=Strict cookie;
- only the hash of the administrative session token is stored;
- administrative sessions expire exactly 12 hours after creation;
- activity does not extend administrative session expiration;
- changing `ADMIN_PUBKEY` invalidates sessions issued to the previous administrator;
- logout invalidates the administrative session;
- expired administrative sessions are rejected;
- state-changing Admin API requests enforce same-origin protections.

### 39.11 Web Admin UI

- `/admin` serves the Svelte application;
- unauthenticated state presents Nostr login;
- authenticated state can list identities, create pairings, list sessions, and revoke sessions;
- identity registration does not persist the entered private key in browser storage;
- the application does not store administrative session tokens in client-readable storage;
- the Admin UI loads no third-party JavaScript or analytics;
- `/admin/api/*` is handled by the Worker rather than SPA fallback.

### 39.12 Client compatibility

An end-to-end acceptance test SHOULD use the current `nostr-tools` NIP-46 client implementation when practical.

The test should verify at least:

```text
bunker:// connection
-> connect
-> get_public_key
-> sign_event
-> logout
```

---

## 40. v1 Acceptance Criteria

v1 is complete when all of the following are true:

1. A new Signflare deployment can be created on Cloudflare Workers.
2. The deployment uses a SQLite-backed Durable Object.
3. The deployment uses Durable Object WebSocket Hibernation.
4. The README provides a Deploy to Cloudflare button.
5. Required deployment secrets are documented.
6. An administrator can register an identity after deployment without redeploying.
7. An administrator can register multiple identities.
8. Signflare contains no hard-coded maximum identity count.
9. Registered user private keys are not stored in plaintext.
10. `bunker://` pairings can be created for a selected identity.
11. Pairing secrets expire after 10 minutes.
12. A successful pairing is single-use.
13. A compatible NIP-46 client can establish a session.
14. `get_public_key` returns the selected user identity's public key.
15. Per-session permissions are enforced.
16. All NIP-46 methods listed in this document are implemented.
17. NIP-46 sessions remain valid until logout, administrative revocation, or identity deletion; WebSocket reconnection alone does not require a new pairing.
18. Identity deletion removes associated pairings and sessions.
19. NIP-46 request and response events are not persisted as relay history.
20. No persistent outbound relay WebSocket is required.
21. Storage exhaustion is reported as an administrative error.
22. Reads and identity deletion remain usable for recovery from storage exhaustion.
23. Secret material is excluded from normal logs and API responses.
24. Compromise of the remote-signer transport key alone does not reveal the at-rest encryption root key or directly decrypt stored user private keys.
25. The root WebSocket endpoint accepts only the restricted NIP-46 relay behavior defined in this document.
26. NIP-46 `REQ` filters are restricted to kind `24133`, the remote-signer author, and a required `#p` filter.
27. NIP-11 is available from the relay URI with `supported_nips` containing `1`, `11`, and `46` and `restricted_writes: true`.
28. An ordinary `GET /` returns an informational landing page without exposing administrative state or secrets.
29. The Admin UI is implemented as a Svelte + Vite client application served through Workers Static Assets.
30. SvelteKit is not used in v1.
31. Administrative login uses NIP-98 signed by `ADMIN_PUBKEY` through a NIP-07 browser signer.
32. Administrative requests after login use a server-side session represented by an HttpOnly, Secure, SameSite=Strict cookie.
33. No static `ADMIN_TOKEN` is required by v1.
34. After a successful pairing, a client using the same client keypair can reconnect to the relay and reuse the existing session without another pairing or NIP-46 `connect`.
35. NIP-98 login events are single-use and replay of the same event ID is rejected.
36. Administrative sessions expire exactly 12 hours after login and are not extended by activity.
37. Changing `ADMIN_PUBKEY` invalidates administrative sessions issued to the previous administrator.
38. Automated tests cover the security-critical flows listed above.
39. Linting, type checking, and tests pass in CI.
---

## 41. Future Work

Potential post-v1 work includes:

- `nostrconnect://`;
- NIP-05 discovery;
- NIP-89 signer announcement;
- encrypted backup/export/import;
- master encryption-key rotation tooling;
- remote-signer key rotation;
- multiple configured relays;
- optional external relay interoperability;
- richer administrative monitoring;
- optional out-of-band alerts;
- optional command-line administration client.

These are intentionally excluded from v1 and should not block the initial implementation.

---

## 42. References

### Nostr

- NIP-01 — Basic protocol flow  
  https://github.com/nostr-protocol/nips/blob/master/01.md

- NIP-07 — `window.nostr` capability for web browsers  
  https://github.com/nostr-protocol/nips/blob/master/07.md

- NIP-11 — Relay Information Document  
  https://github.com/nostr-protocol/nips/blob/master/11.md

- NIP-44 — Encrypted Payloads  
  https://github.com/nostr-protocol/nips/blob/master/44.md

- NIP-46 — Nostr Remote Signing  
  https://github.com/nostr-protocol/nips/blob/master/46.md

- NIP-98 — HTTP Auth  
  https://github.com/nostr-protocol/nips/blob/master/98.md

- nostr-tools  
  https://github.com/nbd-wtf/nostr-tools

### Cloudflare

- SQLite-backed Durable Object Storage  
  https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/

- Access Durable Objects Storage  
  https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/

- Use WebSockets with Durable Objects  
  https://developers.cloudflare.com/durable-objects/best-practices/websockets/

- Durable Objects FAQ and storage exhaustion behavior  
  https://developers.cloudflare.com/durable-objects/reference/faq/

- Durable Object limits  
  https://developers.cloudflare.com/durable-objects/platform/limits/

- Durable Object class exports and migrations  
  https://developers.cloudflare.com/durable-objects/reference/durable-objects-migrations/

- Workers Web Crypto  
  https://developers.cloudflare.com/workers/runtime-apis/web-crypto/

- Workers Secrets  
  https://developers.cloudflare.com/workers/configuration/secrets/

- Deploy to Cloudflare buttons  
  https://developers.cloudflare.com/workers/platform/deploy-buttons/

### Frontend

- Svelte documentation  
  https://svelte.dev/docs/svelte/overview

- Vite documentation  
  https://vite.dev/

- Workers Static Assets  
  https://developers.cloudflare.com/workers/static-assets/

- Workers SPA routing  
  https://developers.cloudflare.com/workers/static-assets/routing/single-page-application/

- Cloudflare Vite plugin  
  https://developers.cloudflare.com/workers/vite-plugin/
