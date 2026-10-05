// The WebSocket protocol for each protocol the Worker serves. Each pair shares
// its default port.
const RELAY_PROTOCOLS = new Map([
  ['http:', 'ws:'],
  ['https:', 'wss:'],
]);

// The NIP-46 relay endpoint of the deployment that received `requestUrl`,
// which is its root WebSocket URL (docs/design.md §37.1). The host and any
// explicit port are kept; credentials, path, query, and fragment are not.
//
// Throws TypeError unless `requestUrl` is an absolute http: or https: URL.
export function relayUrl(requestUrl: string): string {
  const url = new URL(requestUrl);
  const protocol = RELAY_PROTOCOLS.get(url.protocol);
  if (protocol === undefined) {
    throw new TypeError('Request URL is neither http: nor https:');
  }
  const relay = new URL(url.origin);
  relay.protocol = protocol;
  return relay.href;
}
