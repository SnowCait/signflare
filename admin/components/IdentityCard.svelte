<script lang="ts">
  import type {
    ActionResult,
    AdminController,
    PairingState,
    PendingState,
    SessionsState,
  } from '../lib/admin-controller';
  import { identityDeletion } from '../lib/confirmations';
  import { formatTime, isoTime } from '../lib/format';
  import type { Identity, PairingPermissions } from '../lib/types';
  import ConfirmDialog from './ConfirmDialog.svelte';
  import PairingForm from './PairingForm.svelte';
  import PairingResult from './PairingResult.svelte';
  import SessionList from './SessionList.svelte';

  interface Props {
    admin: AdminController;
    identity: Identity;
    sessions: SessionsState | null;
    pairing: PairingState | null;
    pending: PendingState;
  }

  let { admin, identity, sessions, pairing, pending }: Props = $props();

  const id = $props.id();
  let pairingFormOpen = $state(false);
  let sessionsOpen = $state(false);
  let confirmingDeletion = $state(false);

  const deleting = $derived(pending.deleting.includes(identity.pubkey));
  const creatingPairing = $derived(pending.pairing.includes(identity.pubkey));

  function toggleSessions() {
    sessionsOpen = !sessionsOpen;
    if (sessionsOpen) {
      void admin.loadSessions(identity.pubkey);
    }
  }

  function confirmDeletion() {
    confirmingDeletion = false;
    void admin.deleteIdentity(identity.pubkey);
  }

  // The form closes once its token is shown.
  async function createPairing(
    permissions: PairingPermissions,
  ): Promise<ActionResult> {
    const result = await admin.createPairing(identity.pubkey, permissions);
    if (result.ok) {
      pairingFormOpen = false;
    }
    return result;
  }
</script>

<article class="identity" aria-labelledby="{id}-npub">
  <h3 class="identity-npub mono" id="{id}-npub">{identity.npub}</h3>
  <dl class="details">
    <div>
      <dt>Public key (hex)</dt>
      <dd class="mono">{identity.pubkey}</dd>
    </div>
    <div>
      <dt>Created</dt>
      <dd>
        <time datetime={isoTime(identity.createdAt)}
          >{formatTime(identity.createdAt)}</time
        >
      </dd>
    </div>
    <div>
      <dt>Updated</dt>
      <dd>
        <time datetime={isoTime(identity.updatedAt)}
          >{formatTime(identity.updatedAt)}</time
        >
      </dd>
    </div>
  </dl>

  <div class="actions">
    <button
      type="button"
      aria-expanded={pairingFormOpen}
      aria-controls="{id}-pairing"
      aria-describedby="{id}-npub"
      onclick={() => (pairingFormOpen = !pairingFormOpen)}
    >
      {pairingFormOpen ? 'Close pairing form' : 'Create pairing'}
    </button>
    <button
      type="button"
      aria-expanded={sessionsOpen}
      aria-controls="{id}-sessions"
      aria-describedby="{id}-npub"
      onclick={toggleSessions}
    >
      {sessionsOpen ? 'Hide sessions' : 'Show sessions'}
    </button>
    <button
      type="button"
      class="danger"
      aria-describedby="{id}-npub"
      onclick={() => (confirmingDeletion = true)}
      disabled={deleting || creatingPairing}
    >
      {deleting ? 'Deleting…' : 'Delete identity'}
    </button>
  </div>

  {#if pairing !== null}
    <!-- A new token starts over, without the copy result of the last one. -->
    {#key pairing.bunkerUrl}
      <PairingResult
        {pairing}
        ondismiss={() => admin.dismissPairing(identity.pubkey)}
        onexpire={() => admin.expirePairing(identity.pubkey)}
      />
    {/key}
  {/if}

  {#if pairingFormOpen}
    <PairingForm
      id="{id}-pairing"
      busy={creatingPairing || deleting}
      oncreate={createPairing}
    />
  {/if}

  {#if sessionsOpen}
    <SessionList
      id="{id}-sessions"
      {sessions}
      revoking={pending.revoking}
      onreload={() => admin.loadSessions(identity.pubkey)}
      onrevoke={(clientPubkey) =>
        admin.revokeSession(identity.pubkey, clientPubkey)}
    />
  {/if}

  <ConfirmDialog
    open={confirmingDeletion}
    confirmation={identityDeletion(identity.npub)}
    onconfirm={confirmDeletion}
    oncancel={() => (confirmingDeletion = false)}
  />
</article>
