<script lang="ts">
  import type { Confirmation } from '../lib/confirmations';

  interface Props {
    open: boolean;
    confirmation: Confirmation;
    onconfirm: () => void;
    oncancel: () => void;
  }

  let { open, confirmation, onconfirm, oncancel }: Props = $props();

  const id = $props.id();
  let dialog: HTMLDialogElement | undefined = $state();
  let cancelButton: HTMLButtonElement | undefined = $state();

  $effect(() => {
    if (dialog === undefined) {
      return;
    }
    if (open && !dialog.open) {
      dialog.showModal();
      // The safe choice has the focus.
      cancelButton?.focus();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  });
</script>

<!-- Escape closes the dialog, which counts as cancelling. -->
<dialog
  bind:this={dialog}
  class="confirm-dialog"
  aria-labelledby="{id}-title"
  aria-describedby="{id}-details"
  onclose={() => {
    if (open) {
      oncancel();
    }
  }}
>
  <h2 id="{id}-title">{confirmation.title}</h2>
  <ul id="{id}-details">
    {#each confirmation.details as detail (detail)}
      <li>{detail}</li>
    {/each}
  </ul>
  <div class="actions">
    <button type="button" bind:this={cancelButton} onclick={oncancel}>
      Cancel
    </button>
    <button type="button" class="danger" onclick={onconfirm}>
      {confirmation.confirmLabel}
    </button>
  </div>
</dialog>
