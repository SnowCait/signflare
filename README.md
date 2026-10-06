# Signflare

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/SnowCait/signflare)

Self-hosted Nostr remote signer running on Cloudflare Workers.

Signflare keeps Nostr private keys in your own Cloudflare account and signs for
Nostr clients over [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md).
One deployment holds any number of identities. You register them and pair them
with clients in a browser-based Admin UI, without redeploying. Clients connect
with a `bunker://` connection token to the deployment's own restricted relay.

[docs/design.md](docs/design.md) is the source of truth for the design of
Signflare v1.

## How it works

```text
Nostr client                       Browser (administrator)
    |                                  |
    | WebSocket, NIP-46 (kind 24133)   | /admin, NIP-07 signer
    v                                  v
Cloudflare Worker (Hono)
    +-- GET /                    landing page
    +-- GET /, NIP-11 Accept     relay information document
    +-- GET /, WebSocket         restricted NIP-46 relay
    +-- /admin/*                 Admin UI (Svelte, Workers Static Assets)
    +-- /admin/api/*             Admin API
            |
            v
SignerHub Durable Object (SQLite)
    identities (encrypted), pairings, sessions
```

- One Worker serves the public root, the Admin UI as Workers Static Assets, and
  the Admin API.
- One SQLite-backed Durable Object, `SignerHub`, holds all state and runs the
  relay WebSockets through the WebSocket Hibernation API.
- The relay is not a general-purpose Nostr relay. It accepts only NIP-46
  requests and responses for this deployment's remote signer, and stores no
  events.
- Identity private keys are encrypted before they are stored, with AES-256-GCM
  keys derived from `MASTER_ENCRYPTION_KEY`.
- One remote-signer keypair, `REMOTE_SIGNER_PRIVATE_KEY`, carries the NIP-46
  transport for every identity of the deployment.

## Requirements

- Node.js 24 and npm. `.node-version` pins Node.js 24.
- A Cloudflare account to deploy to.
- A NIP-07 browser signer, such as a browser extension that provides
  `window.nostr`, holding the administrator's key. The Admin UI has no other
  way to sign in.

## Configuration

Every deployment sets three values (docs/design.md §7):

| Name                        | Kind                     | Purpose                                                 |
| --------------------------- | ------------------------ | ------------------------------------------------------- |
| `ADMIN_PUBKEY`              | Public variable (`vars`) | The administrator's Nostr public key                    |
| `MASTER_ENCRYPTION_KEY`     | Worker secret            | Root key material for encrypting identity keys at rest  |
| `REMOTE_SIGNER_PRIVATE_KEY` | Worker secret            | Private key of the deployment-wide NIP-46 remote signer |

[`wrangler.jsonc`](wrangler.jsonc) declares all of them, so that
`wrangler types` generates their types, but holds no real value:

- `vars.ADMIN_PUBKEY` is an empty placeholder that each deployment replaces.
- `secrets.required` lists the two secrets. Their values are set on the Worker,
  and `wrangler deploy` refuses to deploy while either is missing.

| Name                        | Local development | Deployment                      |
| --------------------------- | ----------------- | ------------------------------- |
| `ADMIN_PUBKEY`              | `.dev.vars`       | `vars` in your `wrangler.jsonc` |
| `MASTER_ENCRYPTION_KEY`     | `.dev.vars`       | Worker secret                   |
| `REMOTE_SIGNER_PRIVATE_KEY` | `.dev.vars`       | Worker secret                   |

While a value is missing or malformed, the requests that need it fail, and
the HTTP endpoints answer with a server configuration error. The Worker log
names the value to fix, never the value itself.

### `ADMIN_PUBKEY`

The administrator's Nostr **public** key, as 64 lowercase hexadecimal
characters. Only this key can sign in to the Admin UI. The landing page and
the NIP-11 document show it as the administrative contact.

It is not a private key. The administrator's private key stays in the
administrator's NIP-07 browser signer: never upload, import, or register it in
Signflare.

If you only have your `npub`, convert it in a clone of this repository after
`npm install`:

```sh
node --input-type=module -e "import { decode } from 'nostr-tools/nip19'; const { type, data } = decode(process.argv[1]); if (type !== 'npub') throw new Error('Expected an npub'); console.log(data)" npub1...
```

Changing `ADMIN_PUBKEY` ends the Admin UI sessions of the previous
administrator.

### `MASTER_ENCRYPTION_KEY`

A secret with at least 256 bits of cryptographically random key material. It
is the root from which Signflare derives a key for each stored identity
(HKDF-SHA-256, then AES-256-GCM). Signflare uses the exact UTF-8 bytes of the
value as key material: it does not decode hex or base64, and it rejects values
shorter than 32 bytes.

If it is lost, or replaced after identities have been registered, the stored
identities can no longer be decrypted. Cloudflare does not show a secret's
value again once it is set.

### `REMOTE_SIGNER_PRIVATE_KEY`

A secret Nostr private key, as 64 hexadecimal characters or an `nsec`, for the
remote-signer keypair that the whole deployment shares. It signs and encrypts
the NIP-46 transport of every identity, and its public key appears in every
`bunker://` connection token. Generate a new key for this purpose only: it is
neither the administrator's key nor the key of a registered identity.

Replacing it changes the remote-signer public key, so clients that were paired
before can no longer reach the signer.

## Generate the secrets

Generate new secrets for each deployment, and separate ones for local
development. Run these commands with Node.js 24 in a clone of this repository
after `npm install`. They print the value to your terminal only.

`MASTER_ENCRYPTION_KEY`: 32 random bytes from Node.js's cryptographically
secure generator, as 64 hexadecimal characters, which carry 256 bits of
randomness and are 64 bytes long as text:

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

`openssl rand -hex 32` gives a value of the same kind.

`REMOTE_SIGNER_PRIVATE_KEY`: a new private key from `nostr-tools`, whose
`generateSecretKey()` maps random bytes to a valid secp256k1 private key:

```sh
node --input-type=module -e "import { generateSecretKey } from 'nostr-tools/pure'; import { bytesToHex } from 'nostr-tools/utils'; console.log(bytesToHex(generateSecretKey()))"
```

Do not take an arbitrary 64-character hex value instead: not every 256-bit
number is a valid secp256k1 private key. Signflare rejects invalid keys with a
server configuration error.

Keep the values out of the repository, issue trackers, and chats.

## Local development

```sh
npm install
cp .dev.vars.example .dev.vars
```

Then edit `.dev.vars`:

- Replace the `replace-me` placeholders of `MASTER_ENCRYPTION_KEY` and
  `REMOTE_SIGNER_PRIVATE_KEY` with values generated as in
  [Generate the secrets](#generate-the-secrets).
- Add a line for `ADMIN_PUBKEY` with the hex public key of your NIP-07 signer.

The result has this shape:

```dotenv
ADMIN_PUBKEY=<64 lowercase hex characters>
MASTER_ENCRYPTION_KEY=<generated value>
REMOTE_SIGNER_PRIVATE_KEY=<generated value>
```

Start the development server:

```sh
npm run dev
```

- `http://localhost:5173/` serves the landing page, and the relay at
  `ws://localhost:5173/`.
- `http://localhost:5173/admin/` serves the Admin UI. Sign in with the NIP-07
  signer that holds the key of `ADMIN_PUBKEY`.

How the local configuration is read:

- git ignores `.dev.vars`, along with `.dev.vars.*` and `.env*` files. Only
  `.dev.vars.example` is tracked. Never commit your `.dev.vars`.
- Wrangler and the Cloudflare Vite plugin read `.dev.vars` next to
  `wrangler.jsonc`. Because `wrangler.jsonc` declares `secrets.required`, they
  read only the names that it declares: the two secrets, and `ADMIN_PUBKEY`,
  which overrides the empty placeholder of `vars`. Other names are ignored, and
  a missing secret is reported as `Missing required secrets` when the server
  starts.
- Without a `.dev.vars`, the same names are read from a `.env` file or from
  environment variables instead.
- The local Durable Object state is kept under `.wrangler/`, which git
  ignores.

`npm run preview` serves the production build. It takes `ADMIN_PUBKEY` from
`wrangler.jsonc` rather than from `.dev.vars`, because the Cloudflare Vite
plugin carries only the required secrets from `.dev.vars` into the build
output. Use `npm run dev` to work with the Admin UI locally.

## Administration

### Sign in

Open `/admin/` and select **Sign in with Nostr**. Your NIP-07 signer is asked
to sign a one-time NIP-98 login event (kind 27235) for
`POST /admin/api/login`. Signflare accepts it only from `ADMIN_PUBKEY` and
starts an administrative session: an `HttpOnly`, `Secure`, `SameSite=Strict`
cookie that expires 12 hours after sign-in, however active the session is.
**Sign out** ends it earlier.

### Register an identity

An identity is a Nostr user keypair whose private key you entrust to
Signflare, so that it can sign for clients. Under **Register an identity**,
enter its private key, as an `nsec` or 64 hexadecimal characters, and select
**Register identity**. The key is sent to Signflare once, encrypted before it
is stored, and never shown again. Signflare v1 cannot export it.

**Delete identity** removes the identity together with its sessions and
pairings.

### Pair a client

1. On an identity, select **Create pairing**, choose the permissions to grant,
   and select **Create pairing** again.
2. Copy the connection token. It has this form:

   ```text
   bunker://<remote-signer-pubkey>?relay=wss://<your-host>/&secret=<one-time-secret>
   ```

3. Paste it into a NIP-46 client within 10 minutes. The token establishes one
   session only.

The session gets the permissions that the client requests, limited to those of
the pairing, or all of the pairing's permissions if the client requests none.
The available permissions are `sign_event`, `sign_event:<kind>`,
`nip04_encrypt`, `nip04_decrypt`, `nip44_encrypt`, and `nip44_decrypt`.

The client keeps its own keypair and reconnects with it, without a new
pairing. Its session lasts until the client logs out, you revoke it under
**Show sessions** with **Revoke session**, or you delete the identity. Pairing
again requires a new token.

Client-initiated `nostrconnect://` connections are not supported.

## Deployment

### Deploy to Cloudflare

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/SnowCait/signflare)

The button copies this repository into your GitHub or GitLab account, creates
the Worker with its Durable Object and static assets, and builds and deploys
it with Workers Builds. On the setup page:

- Set `ADMIN_PUBKEY` to your hex public key.
- Set `MASTER_ENCRYPTION_KEY` and `REMOTE_SIGNER_PRIVATE_KEY` to values
  generated as in [Generate the secrets](#generate-the-secrets). The
  `replace-me` placeholders that `.dev.vars.example` suggests are rejected at
  runtime.

Each later build deploys the `wrangler.jsonc` of your new repository, and its
`vars.ADMIN_PUBKEY` replaces the deployed value. Make sure that it holds your
public key, and change the administrator there.

### Deploy with Wrangler

In a fork or clone of this repository:

1. Sign in to Cloudflare:

   ```sh
   npx wrangler login
   ```

2. Set `vars.ADMIN_PUBKEY` in `wrangler.jsonc` to your hex public key. To keep
   `wrangler.jsonc` unchanged instead, pass
   `--var ADMIN_PUBKEY:<hex public key>` to every `wrangler deploy`.

3. Write the two secrets to a file outside the repository, for example
   `../signflare-secrets.env`, in the same form as `.dev.vars`. Do not put
   `ADMIN_PUBKEY` in it: every name in that file is uploaded as a secret.

   ```dotenv
   MASTER_ENCRYPTION_KEY=<generated value>
   REMOTE_SIGNER_PRIVATE_KEY=<generated value>
   ```

4. Build, and deploy with the secrets. A new Worker has no secrets yet, so the
   first deployment uploads them along with the code:

   ```sh
   npm run build
   npx wrangler deploy --secrets-file ../signflare-secrets.env
   ```

   Delete the file afterwards.

5. Later deployments keep the secrets:

   ```sh
   npm run build
   npx wrangler deploy
   ```

`npm run build` writes the Worker and its generated Wrangler configuration to
`dist/`, and `wrangler deploy` uses that configuration. Without local values,
the build warns `Missing required secrets`: the warning is about the local
values for `npm run preview`, while `wrangler deploy` checks the secrets of the
deployed Worker.

`wrangler.jsonc` stays the source of truth for `ADMIN_PUBKEY`: Signflare does
not set `keep_vars`, so a value changed only in the Cloudflare dashboard is
replaced on the next deployment. Secrets set in the dashboard or with
`npx wrangler secret put <NAME>` are kept.

## Validation

```sh
npm run check
```

runs, in order:

```sh
npm run format:check  # Prettier
npm run lint          # ESLint
npm run typecheck     # wrangler types --strict-vars=false, tsc, svelte-check
npm test              # Vitest in the Workers runtime
npm run build         # Vite build of the Worker and the Admin UI
```

`npm run types` generates `worker-configuration.d.ts`, which git ignores, from
`wrangler.jsonc` alone: the generated `Env` types every binding of the Worker
and the `SignerHub` without reading `.dev.vars`.

After `npm run build`, `npx wrangler deploy --dry-run` checks the deployment
bundle and lists its bindings without deploying.

## Security notes

- The administrator's private key never reaches Signflare. The Admin UI signs
  in through a NIP-07 signer, which signs a NIP-98 login event with the key it
  keeps.
- Registered identity private keys are entrusted to Signflare, which needs them
  to sign. They are encrypted at rest under `MASTER_ENCRYPTION_KEY` and never
  returned by the Admin API. Deleting an identity removes it from Signflare,
  but is not a guaranteed erasure: Durable Object Point-in-Time Recovery can
  keep earlier states of the database for Cloudflare's recovery window.
- Losing `MASTER_ENCRYPTION_KEY`, or replacing it, makes the stored identities
  impossible to decrypt.
- `REMOTE_SIGNER_PRIVATE_KEY` is the NIP-46 transport security boundary of the
  whole deployment. Whoever holds it can read and forge the NIP-46 traffic of
  every identity, including recorded traffic, since NIP-44 has no forward
  secrecy. It does not decrypt the stored identity keys, which depend on
  `MASTER_ENCRYPTION_KEY`.
- A `bunker://` connection token is sensitive connection material. Its
  one-time secret lets the first client that uses it within 10 minutes
  establish a session with the pairing's permissions. Give it only to the
  client you are pairing.
- The landing page and the NIP-11 document show only the administrator public
  key and the relay URL. The remote-signer public key is given to clients only
  in connection tokens.
- Signflare never logs `MASTER_ENCRYPTION_KEY`, `REMOTE_SIGNER_PRIVATE_KEY`,
  identity private keys, or pairing secrets, and never returns the first three.
  A pairing secret is returned once, in the connection token it belongs to.
