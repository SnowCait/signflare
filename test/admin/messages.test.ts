import { describe, expect, it } from 'vitest';
import { ApiError } from '../../admin/lib/api';
import {
  identityDeletion,
  sessionRevocation,
} from '../../admin/lib/confirmations';
import { errorMessage, NO_SIGNER_MESSAGE } from '../../admin/lib/messages';
import {
  InvalidSignedEventError,
  NoSignerError,
  SignerRejectedError,
} from '../../admin/lib/nip98';

describe('errorMessage', () => {
  it('explains that a NIP-07 signer is required', () => {
    expect(errorMessage(new NoSignerError(), 'login')).toBe(NO_SIGNER_MESSAGE);
    expect(NO_SIGNER_MESSAGE).toMatch(/NIP-07/);
  });

  it('describes signer failures', () => {
    expect(errorMessage(new SignerRejectedError(), 'login')).toMatch(
      /did not sign/,
    );
    expect(errorMessage(new InvalidSignedEventError(), 'login')).toMatch(
      /invalid/,
    );
  });

  it.each<[string, RegExp]>([
    ['session', /ADMIN_PUBKEY/],
    ['login', /ADMIN_PUBKEY/],
    ['register', /MASTER_ENCRYPTION_KEY/],
    ['pairing', /REMOTE_SIGNER_PRIVATE_KEY/],
    ['revoke', /ADMIN_PUBKEY and the Worker secrets/],
  ])('points to the configuration to check for %s', (operation, hint) => {
    const message = errorMessage(
      new ApiError(500, 'server configuration error'),
      operation as Parameters<typeof errorMessage>[1],
    );
    expect(message).toMatch(/^Server configuration error\. /);
    expect(message).toMatch(hint);
  });

  it.each<[ApiError, Parameters<typeof errorMessage>[1], RegExp]>([
    [new ApiError(null), 'refresh', /could not be reached/],
    [new ApiError(401, 'unauthorized'), 'login', /login was rejected/],
    [new ApiError(401, 'unauthorized'), 'refresh', /session has ended/],
    [new ApiError(403, 'forbidden'), 'register', /did not come from this page/],
    [
      new ApiError(400, 'invalid private key'),
      'register',
      /not a valid private key/,
    ],
    [new ApiError(400, 'invalid permissions'), 'pairing', /permissions/],
    [new ApiError(404, 'not found'), 'delete', /identity no longer exists/],
    [new ApiError(404, 'not found'), 'revoke', /session no longer exists/],
    [
      new ApiError(409, 'identity already exists'),
      'register',
      /already registered/,
    ],
    [new ApiError(413, 'payload too large'), 'register', /too long/],
    [new ApiError(507, 'insufficient storage'), 'pairing', /storage is full/],
    [new ApiError(500, 'internal error'), 'refresh', /HTTP 500/],
    [new ApiError(200), 'refresh', /unexpected response \(HTTP 200\)/],
  ])('describes %s for %s', (error, operation, message) => {
    expect(errorMessage(error, operation)).toMatch(message);
  });

  it('falls back to a fixed text for anything else', () => {
    expect(errorMessage(new Error('nsec1secret'), 'register')).not.toContain(
      'nsec1secret',
    );
    expect(errorMessage('nsec1secret', 'register')).not.toContain(
      'nsec1secret',
    );
  });
});

describe('confirmations', () => {
  it('explain what deleting an identity removes', () => {
    const confirmation = identityDeletion('npub1example');
    const text = confirmation.details.join('\n');
    expect(confirmation.title).toBe('Delete this identity?');
    expect(text).toMatch(/npub1example .* deleted/);
    expect(text).toMatch(/active sessions are revoked/);
    expect(text).toMatch(/outstanding pairings are deleted/);
    // docs/design.md §12
    expect(text).toMatch(/not a secure erasure/);
    expect(confirmation.confirmLabel).toBe('Delete identity');
  });

  it('say that revocation is immediate', () => {
    const confirmation = sessionRevocation('c'.repeat(64));
    const text = confirmation.details.join('\n');
    expect(text).toContain('c'.repeat(64));
    expect(text).toMatch(/loses access immediately/);
    expect(text).toMatch(/new pairing/);
    expect(confirmation.confirmLabel).toBe('Revoke session');
  });
});
