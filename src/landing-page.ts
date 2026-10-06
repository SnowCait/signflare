import { html } from 'hono/html';
import { npubEncode } from 'nostr-tools/nip19';
import { SOFTWARE_URL } from './relay-information';

export const DEPLOY_TO_CLOUDFLARE_URL = `https://deploy.workers.cloudflare.com/?url=${SOFTWARE_URL}`;

// The page runs no script and loads nothing: its inline stylesheet is all it
// may use.
export const LANDING_PAGE_CONTENT_SECURITY_POLICY =
  "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// The informational page at the root (docs/design.md §37.3). It shows public
// deployment information only: the parsed ADMIN_PUBKEY and the relay URL of
// the deployment. `html` escapes every interpolated value.
export function landingPage(adminPubkey: string, relay: string) {
  return html`<!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Signflare</title>
        <style>
          :root {
            color-scheme: light dark;
            font-family: system-ui, sans-serif;
            line-height: 1.5;
          }
          body {
            max-width: 42rem;
            margin: 3rem auto;
            padding: 0 1rem;
          }
          code {
            font-family: ui-monospace, monospace;
            font-size: 0.9em;
            overflow-wrap: anywhere;
          }
          dt {
            margin-top: 1rem;
            font-weight: bold;
          }
          dd {
            margin: 0;
          }
        </style>
      </head>
      <body>
        <main>
          <h1>Signflare</h1>
          <p>Self-hosted Nostr remote signer running on Cloudflare Workers.</p>
          <p>
            This endpoint is a restricted NIP-46 relay for the remote signing
            traffic of this signer. It is not a general-purpose Nostr relay: it
            accepts NIP-46 requests and responses only, and stores no events.
          </p>
          <dl>
            <dt>Relay URL</dt>
            <dd><code>${relay}</code></dd>
            <dt>Administrator public key</dt>
            <dd>
              <code>${npubEncode(adminPubkey)}</code><br />
              <code>${adminPubkey}</code>
            </dd>
            <dt>Compatibility</dt>
            <dd>
              NIP-46 remote signing through <code>bunker://</code> connection
              tokens issued by the administrator. Client-initiated
              <code>nostrconnect://</code> connections are not supported.
            </dd>
          </dl>
          <p>
            <a href="${SOFTWARE_URL}">Source code</a> ·
            <a href="${DEPLOY_TO_CLOUDFLARE_URL}">Deploy to Cloudflare</a>
          </p>
        </main>
      </body>
    </html>`;
}
