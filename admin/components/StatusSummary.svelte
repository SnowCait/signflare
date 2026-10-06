<script lang="ts">
  import { formatBytes, formatExactBytes } from '../lib/format';
  import type { AdminStatus } from '../lib/types';

  interface Props {
    status: AdminStatus | null;
    error: string | null;
    refreshing: boolean;
    onrefresh: () => void;
  }

  let { status, error, refreshing, onrefresh }: Props = $props();
</script>

<section class="panel" aria-labelledby="status-heading">
  <div class="section-header">
    <h2 id="status-heading">Status</h2>
    <button type="button" onclick={onrefresh} disabled={refreshing}>
      {refreshing ? 'Refreshing…' : 'Refresh'}
    </button>
  </div>
  {#if error !== null}
    <p class="error-text" role="alert">{error}</p>
  {/if}
  {#if status === null}
    <p role="status">
      {refreshing ? 'Loading status…' : 'The status could not be loaded.'}
    </p>
  {:else}
    <dl class="stats">
      <div class="stat">
        <dt>Identities</dt>
        <dd>{status.identities}</dd>
      </div>
      <div class="stat">
        <dt>Sessions</dt>
        <dd>{status.sessions}</dd>
      </div>
      <div class="stat">
        <dt>Pending pairings</dt>
        <dd>{status.pairings}</dd>
      </div>
      <div class="stat">
        <dt>Database size</dt>
        <dd>
          {formatBytes(status.databaseSize)}
          {#if status.databaseSize >= 1024}
            <span class="stat-detail"
              >{formatExactBytes(status.databaseSize)}</span
            >
          {/if}
        </dd>
      </div>
    </dl>
  {/if}
</section>
