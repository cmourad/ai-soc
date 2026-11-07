import { chmodSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import type { InsightStatus, NetworkFlow, TrafficClass } from "@aisoc/shared";
import type { DomainHistory, InsightFeedback } from "./compass.js";

const TRAFFIC_CLASSES: readonly TrafficClass[] = ["web", "infrastructure", "local", "other"];

/**
 * Rows written by an older schema lack the fields the UI now reads. Filling
 * them in beats discarding a day of the operator's history on upgrade.
 */
function toNetworkFlow(value: unknown): NetworkFlow | null {
  if (!value || typeof value !== "object") return null;
  const flow = value as Partial<NetworkFlow>;
  if (
    typeof flow.id !== "string" ||
    typeof flow.flowId !== "string" ||
    typeof flow.startedAt !== "string" ||
    typeof flow.endedAt !== "string" ||
    typeof flow.localIp !== "string" ||
    typeof flow.remoteIp !== "string" ||
    typeof flow.bytesUp !== "number" ||
    typeof flow.bytesDown !== "number"
  ) {
    return null;
  }
  return {
    ...(flow as NetworkFlow),
    hostname: typeof flow.hostname === "string" ? flow.hostname : (flow.domain ?? null),
    trafficClass: TRAFFIC_CLASSES.includes(flow.trafficClass as TrafficClass)
      ? (flow.trafficClass as TrafficClass)
      : "other",
    domainConfidence:
      flow.domainConfidence === "asserted" || flow.domainConfidence === "inferred"
        ? flow.domainConfidence
        : "unknown",
    country: typeof flow.country === "string" ? flow.country : null,
    asn: typeof flow.asn === "string" ? flow.asn : null,
    organization: typeof flow.organization === "string" ? flow.organization : null,
    processName: typeof flow.processName === "string" ? flow.processName : null,
  };
}

/** Dedicated durable store so private flow history never bloats state.json. */
export class CompassRepository {
  readonly #db: DatabaseSync;
  readonly #path: string;
  readonly #upsertFlow;
  readonly #deleteExpired;
  readonly #trimFlows;
  readonly #selectFlows;
  readonly #upsertDay;
  readonly #selectHistory;
  readonly #pruneHistory;
  readonly #upsertFeedback;
  readonly #selectFeedback;

  constructor(path: string) {
    this.#path = path;
    this.#db = new DatabaseSync(path, { allowExtension: false });
    this.#db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      PRAGMA foreign_keys = ON;
      PRAGMA trusted_schema = OFF;
      -- Retention pruning runs every minute. Without this, freed pages keep a
      -- readable copy of expired browsing metadata in the file indefinitely,
      -- which would make the retention setting a display preference.
      PRAGMA secure_delete = ON;
      CREATE TABLE IF NOT EXISTS network_flows (
        id TEXT PRIMARY KEY,
        ended_at INTEGER NOT NULL,
        payload TEXT NOT NULL CHECK (json_valid(payload))
      ) STRICT;
      CREATE INDEX IF NOT EXISTS network_flows_ended_at ON network_flows(ended_at);
      -- Coarse daily totals outlive the raw flows so "you have never contacted
      -- this site before" is answerable without keeping every connection.
      CREATE TABLE IF NOT EXISTS destination_days (
        destination TEXT NOT NULL,
        day TEXT NOT NULL,
        flows INTEGER NOT NULL DEFAULT 0,
        bytes_up INTEGER NOT NULL DEFAULT 0,
        bytes_down INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (destination, day)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS insight_feedback (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL CHECK (status IN ('dismissed', 'snoozed')),
        snoozed_until TEXT
      ) STRICT;
      DROP TABLE IF EXISTS curiosity_feedback;
      DROP TABLE IF EXISTS schema_version;
    `);
    if (path !== ":memory:") chmodSync(path, 0o600);

    this.#upsertFlow = this.#db.prepare(
      "INSERT INTO network_flows(id, ended_at, payload) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET ended_at=excluded.ended_at, payload=excluded.payload",
    );
    this.#deleteExpired = this.#db.prepare("DELETE FROM network_flows WHERE ended_at < ?");
    this.#trimFlows = this.#db.prepare(
      "DELETE FROM network_flows WHERE id NOT IN (SELECT id FROM network_flows ORDER BY ended_at DESC LIMIT ?)",
    );
    this.#selectFlows = this.#db.prepare(
      "SELECT payload FROM network_flows WHERE ended_at >= ? ORDER BY ended_at ASC LIMIT ?",
    );
    this.#upsertDay = this.#db.prepare(
      `INSERT INTO destination_days(destination, day, flows, bytes_up, bytes_down)
       VALUES (?, ?, 1, ?, ?)
       ON CONFLICT(destination, day) DO UPDATE SET
         flows = flows + 1,
         bytes_up = bytes_up + excluded.bytes_up,
         bytes_down = bytes_down + excluded.bytes_down`,
    );
    this.#selectHistory = this.#db.prepare(
      "SELECT destination, COUNT(*) AS days, MIN(day) AS first_day FROM destination_days GROUP BY destination",
    );
    this.#pruneHistory = this.#db.prepare("DELETE FROM destination_days WHERE day < ?");
    this.#upsertFeedback = this.#db.prepare(
      "INSERT INTO insight_feedback(id, status, snoozed_until) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, snoozed_until=excluded.snoozed_until",
    );
    this.#selectFeedback = this.#db.prepare(
      "SELECT id, status, snoozed_until FROM insight_feedback",
    );
  }

  upsertFlow(flow: NetworkFlow): void {
    const endedAt = Date.parse(flow.endedAt);
    if (!Number.isFinite(endedAt)) return;
    this.#upsertFlow.run(flow.id, endedAt, JSON.stringify(flow));
  }

  /** Only called for flows a person plausibly caused; chatter would swamp it. */
  recordDay(destination: string, day: string, bytesUp: number, bytesDown: number): void {
    this.#upsertDay.run(destination, day, bytesUp, bytesDown);
  }

  prune(retentionHours: number, limit: number, historyDays: number, now = Date.now()): void {
    this.#deleteExpired.run(now - retentionHours * 3_600_000);
    this.#trimFlows.run(limit);
    this.#pruneHistory.run(new Date(now - historyDays * 86_400_000).toISOString().slice(0, 10));
  }

  loadFlows(retentionHours: number, limit: number, now = Date.now()): NetworkFlow[] {
    const rows = this.#selectFlows.all(now - retentionHours * 3_600_000, limit) as {
      payload: string;
    }[];
    const flows: NetworkFlow[] = [];
    for (const row of rows) {
      try {
        const flow = toNetworkFlow(JSON.parse(row.payload));
        if (flow) flows.push(flow);
      } catch {
        // One corrupt row does not make the privacy ledger unavailable.
      }
    }
    return flows;
  }

  loadHistory(): DomainHistory {
    const rows = this.#selectHistory.all() as {
      destination: string;
      days: number;
      first_day: string;
    }[];
    const history: DomainHistory = {};
    for (const row of rows) history[row.destination] = { days: row.days, firstDay: row.first_day };
    return history;
  }

  loadFeedback(): InsightFeedback {
    const result: InsightFeedback = {};
    const rows = this.#selectFeedback.all() as {
      id: string;
      status: InsightStatus;
      snoozed_until: string | null;
    }[];
    for (const row of rows) {
      result[row.id] = { status: row.status, snoozedUntil: row.snoozed_until };
    }
    return result;
  }

  setFeedback(id: string, status: InsightStatus, snoozedUntil: string | null): void {
    this.#upsertFeedback.run(id, status, snoozedUntil);
  }

  /**
   * "Forget" has to mean the bytes are gone, not unlinked. DELETE alone leaves
   * them in freelist pages and in the write-ahead log, both readable with a hex
   * editor, so the checkpoint and VACUUM are part of the guarantee.
   */
  clear(): void {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      this.#db.exec(
        "DELETE FROM network_flows; DELETE FROM destination_days; DELETE FROM insight_feedback",
      );
      this.#db.exec("COMMIT");
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
    if (this.#path === ":memory:") return;
    this.#db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    this.#db.exec("VACUUM");
  }
}
