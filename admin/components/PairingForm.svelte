<script lang="ts">
  import type { ActionResult } from '../lib/admin-controller';
  import {
    MAX_EVENT_KIND,
    pairingPermissions,
    PERMISSION_METHODS,
    type PermissionMethod,
  } from '../lib/permissions';
  import type { PairingPermissions } from '../lib/types';

  interface Props {
    id: string;
    busy: boolean;
    oncreate: (permissions: PairingPermissions) => Promise<ActionResult>;
  }

  let { id, busy, oncreate }: Props = $props();

  const LABELS: Record<PermissionMethod, string> = {
    sign_event: 'Sign events of any kind',
    nip04_encrypt: 'Encrypt messages with NIP-04',
    nip04_decrypt: 'Decrypt messages with NIP-04',
    nip44_encrypt: 'Encrypt messages with NIP-44',
    nip44_decrypt: 'Decrypt messages with NIP-44',
  };

  let mode: 'all' | 'explicit' = $state('all');
  let methods: PermissionMethod[] = $state([]);
  let kinds = $state('');
  let error: string | null = $state(null);

  const anyKind = $derived(methods.includes('sign_event'));
  const nothingSelected = $derived(methods.length === 0 && kinds.trim() === '');

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    error = null;
    const selection = pairingPermissions({ mode, methods, kinds });
    if (!selection.ok) {
      error = selection.error;
      return;
    }
    const result = await oncreate(selection.permissions);
    if (!result.ok) {
      error = result.message;
    }
  }
</script>

<form
  {id}
  class="subpanel"
  onsubmit={submit}
  autocomplete="off"
  aria-labelledby="{id}-heading"
>
  <h4 id="{id}-heading">New pairing</h4>
  <p class="hint">
    A pairing is a one-time <code>bunker://</code> connection token that lets one
    client connect within 10 minutes. The client gets at most the permissions selected
    here.
  </p>
  <fieldset>
    <legend>Permissions</legend>
    <label class="choice">
      <input type="radio" name="{id}-mode" value="all" bind:group={mode} />
      <span>
        All permissions: sign events of any kind, and encrypt and decrypt with
        NIP-04 and NIP-44
      </span>
    </label>
    <label class="choice">
      <input type="radio" name="{id}-mode" value="explicit" bind:group={mode} />
      <span>Only the permissions selected below</span>
    </label>

    {#if mode === 'explicit'}
      <fieldset class="nested">
        <legend>Selected permissions</legend>
        {#each PERMISSION_METHODS as method (method)}
          <label class="choice">
            <input type="checkbox" value={method} bind:group={methods} />
            <span>{LABELS[method]} <code>{method}</code></span>
          </label>
        {/each}
        <label for="{id}-kinds">
          Sign only events of these kinds <code>sign_event:&lt;kind&gt;</code>
        </label>
        <input
          id="{id}-kinds"
          type="text"
          bind:value={kinds}
          disabled={anyKind}
          placeholder="1, 7"
          autocomplete="off"
          spellcheck="false"
          aria-describedby="{id}-kinds-hint"
        />
        <p class="hint" id="{id}-kinds-hint">
          {anyKind
            ? 'Not needed: events of any kind may be signed.'
            : `Whole numbers from 0 to ${MAX_EVENT_KIND}, separated by commas or spaces.`}
        </p>
        {#if nothingSelected}
          <p class="hint">
            No signing, encryption, or decryption permissions are granted.
            NIP-46 control methods (<code>ping</code>,
            <code>get_public_key</code>,
            <code>switch_relays</code>, and <code>logout</code>) remain
            available once the client is connected.
          </p>
        {/if}
      </fieldset>
    {/if}
  </fieldset>

  {#if error !== null}
    <p class="error-text" role="alert">{error}</p>
  {/if}
  <button type="submit" class="primary" disabled={busy}>
    {busy ? 'Creating pairing…' : 'Create pairing'}
  </button>
</form>
