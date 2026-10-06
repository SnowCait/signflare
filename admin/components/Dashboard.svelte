<script lang="ts">
  import type { AdminController, AdminState } from '../lib/admin-controller';
  import IdentityCard from './IdentityCard.svelte';
  import IdentityForm from './IdentityForm.svelte';
  import StatusSummary from './StatusSummary.svelte';

  interface Props {
    admin: AdminController;
    state: AdminState;
  }

  let { admin, state }: Props = $props();
</script>

<StatusSummary
  status={state.status}
  error={state.dashboardError}
  refreshing={state.pending.refresh}
  onrefresh={() => admin.refresh()}
/>

<section class="panel" aria-labelledby="identities-heading">
  <h2 id="identities-heading">Identities</h2>
  <IdentityForm
    pending={state.pending.register}
    onregister={(privateKey) => admin.registerIdentity(privateKey)}
  />

  {#if state.identities === null}
    <p role="status">
      {state.pending.refresh
        ? 'Loading identities…'
        : 'The identity list could not be loaded. Use Refresh to try again.'}
    </p>
  {:else if state.identities.length === 0}
    <p>No identities are registered yet.</p>
  {:else}
    <ul class="identity-list">
      {#each state.identities as identity (identity.pubkey)}
        <li>
          <IdentityCard
            {admin}
            {identity}
            sessions={state.sessions[identity.pubkey] ?? null}
            pairing={state.pairings[identity.pubkey] ?? null}
            pending={state.pending}
          />
        </li>
      {/each}
    </ul>
  {/if}
</section>
