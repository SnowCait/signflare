import { ApiError } from './api';
import {
  InvalidSignedEventError,
  NoSignerError,
  SignerRejectedError,
} from './nip98';

// User-facing messages for failed operations. They are fixed texts chosen by
// error class and status, so nothing from a request, a response body, or a
// thrown value is ever shown.

export type Operation =
  | 'session'
  | 'login'
  | 'logout'
  | 'refresh'
  | 'register'
  | 'delete'
  | 'pairing'
  | 'sessions'
  | 'revoke';

export const NO_SIGNER_MESSAGE =
  'No NIP-07 signer was found. Signflare administration requires a NIP-07 browser signer extension: install or enable one, then reload this page.';

// What to check for a server configuration error. The server does not say
// which setting is wrong, so these are hints by operation.
const CONFIGURATION_HINTS: Partial<Record<Operation, string>> = {
  session:
    'Check that ADMIN_PUBKEY is set to the administrator public key as 64 lowercase hex characters, then reload this page.',
  login:
    'Check that ADMIN_PUBKEY is set to the administrator public key as 64 lowercase hex characters.',
  register:
    'Check that the MASTER_ENCRYPTION_KEY secret is set to at least 32 bytes.',
  pairing:
    'Check that the REMOTE_SIGNER_PRIVATE_KEY secret is set to an nsec or a 64-character hex private key.',
};

const NOT_FOUND_MESSAGES: Partial<Record<Operation, string>> = {
  delete: 'This identity no longer exists.',
  pairing: 'This identity no longer exists.',
  sessions: 'This identity no longer exists.',
  revoke: 'This session no longer exists.',
};

export function isUnauthorized(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401;
}

export function isNotFound(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404;
}

export function isConfigurationError(error: unknown): boolean {
  return (
    error instanceof ApiError && error.code === 'server configuration error'
  );
}

export function errorMessage(error: unknown, operation: Operation): string {
  if (error instanceof NoSignerError) {
    return NO_SIGNER_MESSAGE;
  }
  if (error instanceof SignerRejectedError) {
    return 'The NIP-07 signer did not sign the login request.';
  }
  if (error instanceof InvalidSignedEventError) {
    return 'The NIP-07 signer returned an invalid login event.';
  }
  if (!(error instanceof ApiError)) {
    return 'Something went wrong. Reload the page and try again.';
  }
  if (error.status === null) {
    return 'The Signflare server could not be reached. Check your connection and try again.';
  }
  if (isConfigurationError(error)) {
    return `Server configuration error. ${
      CONFIGURATION_HINTS[operation] ??
      'Check ADMIN_PUBKEY and the Worker secrets in the deployment settings.'
    }`;
  }
  switch (error.status) {
    case 400:
      return badRequestMessage(error, operation);
    case 401:
      return operation === 'login'
        ? 'The login was rejected. Sign with the key configured as ADMIN_PUBKEY, and make sure that this device’s clock is correct.'
        : 'Your admin session has ended. Sign in again.';
    case 403:
      return 'The server refused the request because it did not come from this page. Reload the page and try again.';
    case 404:
      return (
        NOT_FOUND_MESSAGES[operation] ?? 'The requested item was not found.'
      );
    case 409:
      return operation === 'register'
        ? 'This identity is already registered.'
        : 'The request conflicts with the current state. Refresh and try again.';
    case 413:
      return operation === 'register'
        ? 'The private key input is too long.'
        : 'The request is too large.';
    case 507:
      return 'Signflare’s storage is full. Delete identities you no longer need to free space, then try again.';
  }
  return error.status >= 500
    ? `The server could not complete the request (HTTP ${error.status}). Try again later.`
    : `The server returned an unexpected response (HTTP ${error.status}).`;
}

function badRequestMessage(error: ApiError, operation: Operation): string {
  switch (error.code) {
    case 'invalid private key':
      return 'This is not a valid private key. Enter an nsec1… value or a 64-character hex private key.';
    case 'invalid permissions':
      return 'The server did not accept the selected permissions.';
    case 'invalid pubkey':
      return 'The public key is not valid.';
  }
  return operation === 'register'
    ? 'The registration request was not accepted. Enter an nsec1… value or a 64-character hex private key.'
    : 'The request was not accepted.';
}
