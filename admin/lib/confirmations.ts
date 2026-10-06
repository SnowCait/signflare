// Texts of the confirmations shown before destructive actions.

export interface Confirmation {
  readonly title: string;
  readonly details: readonly string[];
  readonly confirmLabel: string;
}

// docs/design.md §12: deletion removes the identity with its sessions and
// pairings, and is not described as secure erasure.
export function identityDeletion(npub: string): Confirmation {
  return {
    title: 'Delete this identity?',
    details: [
      `The identity ${npub} and its encrypted private key are deleted from Signflare.`,
      'All of its active sessions are revoked: connected clients can no longer sign or decrypt with it.',
      'All of its outstanding pairings are deleted: bunker:// URLs that have not been used yet stop working.',
      'This cannot be undone. Signflare can only use this key again if you register it again.',
      'Deletion is not a secure erasure: earlier database states can remain in Cloudflare’s point-in-time recovery for a limited period.',
    ],
    confirmLabel: 'Delete identity',
  };
}

// docs/design.md §30.10: revocation applies to the very next request.
export function sessionRevocation(clientPubkey: string): Confirmation {
  return {
    title: 'Revoke this session?',
    details: [
      `The client ${clientPubkey} loses access immediately: Signflare rejects its next request.`,
      'To connect again, the client needs a new pairing.',
      'Events it has already signed and messages it has already decrypted are not affected.',
    ],
    confirmLabel: 'Revoke session',
  };
}
