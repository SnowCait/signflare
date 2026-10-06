<script lang="ts">
  import type { SessionsState } from '../lib/admin-controller';
  import { sessionRevocation } from '../lib/confirmations';
  import { formatTime, isoTime, metadataText } from '../lib/format';
  import ConfirmDialog from './ConfirmDialog.svelte';

  interface Props {
    id: string;
    sessions: SessionsState | null;
    // Client pubkeys being revoked.
    revoking: readonly string[];
    onreload: () => void;
    onrevoke: (clientPubkey: string) => void;
  }

  let { id, sessions, revoking, onreload, onrevoke }: Props = $props();

  // The client pubkey of the session to revoke, kept while the dialog closes.
  let target = $state('');
  let confirming = $state(false);

  function askToRevoke(clientPubkey: string) {
    target = clientPubkey;
    confirming = true;
  }

  function confirmRevocation() {
    confirming = false;
    onrevoke(target);
  }
</script>

<section {id} class="subpanel" aria-labelledby="{id}-heading">
  <div class="section-header">
    <h4 id="{id}-heading">Sessions</h4>
    <button
      type="button"
      onclick={onreload}
      disabled={sessions?.loading ?? false}
    >
      {sessions?.loading ? 'Loading…' : 'Reload'}
    </button>
  </div>

  {#if sessions?.error}
    <p class="error-text" role="alert">{sessions.error}</p>
  {/if}

  {#if sessions === null || sessions.sessions === null}
    {#if sessions === null || sessions.loading}
      <p role="status">Loading sessions…</p>
    {/if}
  {:else if sessions.sessions.length === 0}
    <p>No clients are connected to this identity.</p>
  {:else}
    <ul class="session-list">
      {#each sessions.sessions as session (session.clientPubkey)}
        {@const metadata = session.clientMetadata}
        <li class="session">
          <dl class="details">
            <div>
              <dt>Client public key</dt>
              <dd class="mono">{session.clientPubkey}</dd>
            </div>
            <div>
              <dt>Permissions</dt>
              <dd>
                {#if session.permissions.length === 0}
                  None: no signing, encryption, or decryption permissions.
                  Control methods remain available.
                {:else}
                  <ul class="permissions">
                    {#each session.permissions as permission (permission)}
                      <li><code>{permission}</code></li>
                    {/each}
                  </ul>
                {/if}
              </dd>
            </div>
            <div>
              <dt>Connected</dt>
              <dd>
                <time datetime={isoTime(session.createdAt)}
                  >{formatTime(session.createdAt)}</time
                >
              </dd>
            </div>
            <div>
              <dt>Last used</dt>
              <dd>
                <time datetime={isoTime(session.lastUsedAt)}
                  >{formatTime(session.lastUsedAt)}</time
                >
              </dd>
            </div>
          </dl>

          <!-- Client metadata is unverified input from the client: shown as
               plain text only, never as a link or a loaded image. -->
          <div class="client-metadata">
            <p class="hint">
              Reported by the client and not verified. Any client can claim any
              name.
            </p>
            <dl class="details">
              <div>
                <dt>Name</dt>
                <dd>
                  {#if metadata.name === null}
                    <span class="muted">Not provided</span>
                  {:else}
                    <bdi>{metadataText(metadata.name)}</bdi>
                  {/if}
                </dd>
              </div>
              <div>
                <dt>URL</dt>
                <dd class="mono">
                  {#if metadata.url === null}
                    <span class="muted">Not provided</span>
                  {:else}
                    <bdi>{metadataText(metadata.url)}</bdi>
                  {/if}
                </dd>
              </div>
              <div>
                <dt>Image URL</dt>
                <dd class="mono">
                  {#if metadata.image === null}
                    <span class="muted">Not provided</span>
                  {:else}
                    <bdi>{metadataText(metadata.image)}</bdi>
                  {/if}
                </dd>
              </div>
            </dl>
          </div>

          <div class="actions">
            <button
              type="button"
              class="danger"
              onclick={() => askToRevoke(session.clientPubkey)}
              disabled={revoking.includes(session.clientPubkey)}
            >
              {revoking.includes(session.clientPubkey)
                ? 'Revoking…'
                : 'Revoke session'}
            </button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}

  <ConfirmDialog
    open={confirming}
    confirmation={sessionRevocation(target)}
    onconfirm={confirmRevocation}
    oncancel={() => (confirming = false)}
  />
</section>
