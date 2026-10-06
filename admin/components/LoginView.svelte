<script lang="ts">
  interface Props {
    pending: boolean;
    error: string | null;
    onlogin: () => void;
  }

  let { pending, error, onlogin }: Props = $props();

  function signerAvailable(): boolean {
    return typeof window.nostr?.signEvent === 'function';
  }

  let signerDetected = $state(signerAvailable());

  // Extensions may only add window.nostr once the page has loaded.
  $effect(() => {
    const timer = setTimeout(() => {
      signerDetected = signerAvailable();
    }, 1000);
    return () => clearTimeout(timer);
  });
</script>

<section class="panel login" aria-labelledby="login-heading">
  <h2 id="login-heading">Sign in</h2>
  <p>
    Sign in with the Nostr key configured as this deployment’s administrator (<code
      >ADMIN_PUBKEY</code
    >). Your NIP-07 browser signer is asked to sign a one-time NIP-98 login
    event; the key itself never leaves the signer.
  </p>
  {#if !signerDetected}
    <p class="hint" id="login-signer-hint">
      No NIP-07 signer has been detected on this page. Administration requires a
      NIP-07 browser signer extension that provides <code>window.nostr</code>.
    </p>
  {/if}
  {#if error !== null}
    <p class="error-text" role="alert">{error}</p>
  {/if}
  <button
    type="button"
    class="primary"
    onclick={onlogin}
    disabled={pending}
    aria-describedby={signerDetected ? undefined : 'login-signer-hint'}
  >
    {pending ? 'Waiting for the signer…' : 'Sign in with Nostr'}
  </button>
</section>
