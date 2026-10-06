// Operational status for administrators (docs/design.md §30.4). Counts only:
// no key material, secrets, or pubkeys.
export interface AdminStatus {
  readonly identities: number;
  readonly sessions: number;
  // Pairings that can still establish a session.
  readonly pairings: number;
  // Bytes, as reported by the SQLite-backed Durable Object.
  readonly databaseSize: number;
}

type CountsRow = {
  identities: number;
  sessions: number;
  pairings: number;
};

// A pure read, so it keeps working when storage is full (docs/design.md §32).
// Expired pairings (expires_at <= now) are left out of the count but are not
// removed here.
export function getAdminStatus(sql: SqlStorage, now: number): AdminStatus {
  const counts = sql
    .exec<CountsRow>(
      `SELECT
        (SELECT COUNT(*) FROM identities) AS identities,
        (SELECT COUNT(*) FROM sessions) AS sessions,
        (SELECT COUNT(*) FROM pairings WHERE expires_at > ?) AS pairings`,
      now,
    )
    .one();
  return {
    identities: counts.identities,
    sessions: counts.sessions,
    pairings: counts.pairings,
    databaseSize: sql.databaseSize,
  };
}
