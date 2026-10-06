<script lang="ts">
  import type { PairingState } from '../lib/admin-controller';
  import { copyText } from '../lib/clipboard';
  import { formatCountdown, formatTime, isoTime } from '../lib/format';
  import { unixNow } from '../lib/nip98';

  interface Props {
    pairing: PairingState;
    ondismiss: () => void;
    onexpire: () => void;
  }

  let { pairing, ondismiss, onexpire }: Props = $props();

  const id = $props.id();
  let now = $state(unixNow());
  let copyResult: 'copied' | 'failed' | null = $state(null);

  const remaining = $derived(pairing.expiresAt - now);

  $effect(() => {
    const timer = setInterval(() => {
      now = unixNow();
    }, 1000);
    return () => clearInterval(timer);
  });

  $effect(() => {
    if (remaining <= 0 && pairing.bunkerUrl !== null) {
      onexpire();
    }
  });

  async function copy() {
    if (pairing.bunkerUrl !== null) {
      copyResult = (await copyText(navigator.clipboard, pairing.bunkerUrl))
        ? 'copied'
        : 'failed';
    }
  }
</script>

<section class="pairing-result" aria-labelledby="{id}-heading">
  <h4 id="{id}-heading">Connection token</h4>
  {#if pairing.bunkerUrl !== null}
    <p class="warning">
      <strong>Sensitive:</strong> this <code>bunker://</code> URL contains a one-time
      secret. Give it only to the client you are pairing. It is shown only here and
      is gone once dismissed or when you leave this page.
    </p>
    <code class="secret">{pairing.bunkerUrl}</code>
    <p>
      Valid until
      <time datetime={isoTime(pairing.expiresAt)}
        >{formatTime(pairing.expiresAt)}</time
      >
      ({formatCountdown(remaining)} left).
    </p>
    <div class="actions">
      <button type="button" onclick={copy}>Copy URL</button>
      <button type="button" onclick={ondismiss}>Dismiss</button>
    </div>
    <p class="copy-result" role="status">
      {#if copyResult === 'copied'}
        Copied to the clipboard.
      {:else if copyResult === 'failed'}
        Copying failed. Select the URL above and copy it manually.
      {/if}
    </p>
  {:else}
    <p>
      This pairing expired at
      <time datetime={isoTime(pairing.expiresAt)}
        >{formatTime(pairing.expiresAt)}</time
      >. Create a new pairing if the client still needs to connect.
    </p>
    <div class="actions">
      <button type="button" onclick={ondismiss}>Dismiss</button>
    </div>
  {/if}
</section>
