import { type NostrEvent, validateEvent } from 'nostr-tools/pure';

const HEX_ID = /^[0-9a-f]{64}$/;
const HEX_SIG = /^[0-9a-f]{128}$/;

// The shape of a signed NIP-01 event: what nostr-tools validateEvent() checks,
// plus an integer kind and created_at and a well-formed id and sig. Neither the
// id nor the signature is verified; verifyEvent() does that.
export function isSignedEvent(value: unknown): value is NostrEvent {
  if (!validateEvent(value)) {
    return false;
  }
  const { id, sig } = value as Partial<NostrEvent>;
  return (
    Number.isSafeInteger(value.kind) &&
    Number.isSafeInteger(value.created_at) &&
    typeof id === 'string' &&
    HEX_ID.test(id) &&
    typeof sig === 'string' &&
    HEX_SIG.test(sig)
  );
}
