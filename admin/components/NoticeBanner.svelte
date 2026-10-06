<script lang="ts">
  import type { Notice } from '../lib/admin-controller';

  interface Props {
    notice: Notice | null;
    ondismiss: () => void;
  }

  let { notice, ondismiss }: Props = $props();
</script>

<!-- Always present, so that assistive technology announces each new notice. -->
<div class="notice-region" aria-live="polite">
  {#if notice !== null}
    <div
      class="notice notice-{notice.kind}"
      role={notice.kind === 'error' ? 'alert' : 'status'}
    >
      <p>
        <strong>{notice.kind === 'error' ? 'Error:' : 'Done:'}</strong>
        {notice.message}
      </p>
      <button type="button" class="link-button" onclick={ondismiss}>
        Dismiss
      </button>
    </div>
  {/if}
</div>
