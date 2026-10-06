<script lang="ts">
  import Dashboard from './components/Dashboard.svelte';
  import LoginView from './components/LoginView.svelte';
  import NoticeBanner from './components/NoticeBanner.svelte';
  import { AdminController } from './lib/admin-controller';
  import { formatTime, isoTime, shortKey } from './lib/format';

  const admin = new AdminController({
    fetch: (url, init) => fetch(url, init),
    signer: () => window.nostr,
    pageUrl: () => window.location.href,
  });
  void admin.start();
</script>

<header class="app-header">
  <p class="brand">
    <span class="brand-name">Signflare</span>
    <span class="brand-tag">Admin</span>
  </p>
  {#if $admin.auth.status === 'authenticated'}
    {@const session = $admin.auth.session}
    <div class="account">
      <p class="account-detail">
        Signed in as <code title={session.pubkey}
          >{shortKey(session.pubkey)}</code
        >
      </p>
      <p class="account-detail">
        Session ends
        <time datetime={isoTime(session.expiresAt)}
          >{formatTime(session.expiresAt)}</time
        >
      </p>
      <button
        type="button"
        onclick={() => admin.logout()}
        disabled={$admin.pending.logout}
      >
        {$admin.pending.logout ? 'Signing out…' : 'Sign out'}
      </button>
    </div>
  {/if}
</header>

<main class="app-main">
  <h1 class="visually-hidden">Signflare administration</h1>
  <NoticeBanner
    notice={$admin.notice}
    ondismiss={() => admin.dismissNotice()}
  />

  {#if $admin.auth.status === 'loading'}
    <p class="panel" role="status">Checking the admin session…</p>
  {:else if $admin.auth.status === 'unauthenticated'}
    <LoginView
      pending={$admin.pending.login}
      error={$admin.loginError}
      onlogin={() => admin.login()}
    />
  {:else if $admin.auth.status === 'configuration_error'}
    <section class="panel" role="alert" aria-labelledby="configuration-heading">
      <h2 id="configuration-heading">Server configuration error</h2>
      <p>{$admin.auth.message}</p>
      <button type="button" onclick={() => admin.start()}>Retry</button>
    </section>
  {:else if $admin.auth.status === 'error'}
    <section class="panel" role="alert" aria-labelledby="session-error-heading">
      <h2 id="session-error-heading">Could not check the admin session</h2>
      <p>{$admin.auth.message}</p>
      <button type="button" onclick={() => admin.start()}>Retry</button>
    </section>
  {:else}
    <Dashboard {admin} state={$admin} />
  {/if}
</main>
