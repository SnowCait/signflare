<script lang="ts">
  import type { ActionResult } from '../lib/admin-controller';
  import {
    hasPrivateKeyInput,
    submitPrivateKey,
  } from '../lib/private-key-entry';

  interface Props {
    pending: boolean;
    onregister: (privateKey: string) => Promise<ActionResult>;
  }

  let { pending, onregister }: Props = $props();

  const id = $props.id();
  // The entered key. It is cleared when the form is submitted and again when
  // the request completes, and goes away with the component on sign-out.
  let privateKey = $state('');
  let error: string | null = $state(null);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    error = null;
    if (!hasPrivateKeyInput(privateKey)) {
      error = 'Enter a private key.';
      return;
    }
    const result = await submitPrivateKey(
      {
        read: () => privateKey,
        clear: () => {
          privateKey = '';
        },
      },
      onregister,
    );
    if (!result.ok) {
      error = result.message;
    }
  }
</script>

<form
  class="subpanel"
  onsubmit={submit}
  autocomplete="off"
  aria-labelledby="{id}-heading"
>
  <h3 id="{id}-heading">Register an identity</h3>
  <label for="{id}-key">Private key</label>
  <input
    id="{id}-key"
    type="password"
    bind:value={privateKey}
    autocomplete="off"
    autocapitalize="off"
    spellcheck="false"
    disabled={pending}
    oninput={() => (error = null)}
    aria-describedby="{id}-hint{error === null ? '' : ` ${id}-error`}"
    aria-invalid={error !== null}
  />
  <p class="hint" id="{id}-hint">
    An <code>nsec1…</code> value or a 64-character hex private key. It is sent once
    to the server, which stores it encrypted, and is not kept in this browser. If
    your browser offers to save it as a password, decline.
  </p>
  {#if error !== null}
    <p class="error-text" id="{id}-error" role="alert">{error}</p>
  {/if}
  <button type="submit" class="primary" disabled={pending}>
    {pending ? 'Registering…' : 'Register identity'}
  </button>
</form>
