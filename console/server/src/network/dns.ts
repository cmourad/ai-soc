import type { DnsCount, DnsQuery, DnsQueryStatus, DnsSummary } from "@aisoc/shared";
import { getSecret } from "../crypto.js";

/**
 * Read over FTL's own API rather than its SQLite file. The database is WAL, and
 * a read-only connection needs to write the -shm index to see anything the
 * writer has not checkpointed yet — which ProtectSystem=strict denies the
 * console. Reading the file directly therefore returns a silently stale
 * snapshot, which is worse than an error.
 */
const BASE = process.env.AISOC_PIHOLE_URL ?? "http://127.0.0.1:8089";
const SECRET_NAME = "pihole.password";
const WINDOW_HOURS = 24;
const RECENT_LIMIT = 100;
const TOP_LIMIT = 10;
const TIMEOUT_MS = 4_000;

const BLOCKED_STATUS = new Set([
  "GRAVITY",
  "REGEX",
  "DENYLIST",
  "EXTERNAL_BLOCKED_IP",
  "EXTERNAL_BLOCKED_NULL",
  "EXTERNAL_BLOCKED_NXRA",
  "GRAVITY_CNAME",
  "REGEX_CNAME",
  "DENYLIST_CNAME",
  "SPECIAL_DOMAIN",
  "EXTERNAL_BLOCKED_EDE15",
]);
const CACHED_STATUS = new Set(["CACHE", "CACHE_STALE"]);
const FORWARDED_STATUS = new Set(["FORWARDED", "RETRIED", "RETRIED_DNSSEC"]);

function statusOf(code: string): DnsQueryStatus {
  if (BLOCKED_STATUS.has(code)) return "blocked";
  if (CACHED_STATUS.has(code)) return "cached";
  if (FORWARDED_STATUS.has(code)) return "forwarded";
  return "other";
}

/** FTL hands out a session per login and complains loudly about churn. */
let session: { sid: string; expiresAt: number } | null = null;
let authentication: Promise<string> | null = null;

async function fetchJson(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(`${BASE}${path}`, {
    ...init,
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`${path} responded ${response.status}`);
  return response.json();
}

async function login(): Promise<string> {
  const password = getSecret(SECRET_NAME) ?? process.env.AISOC_PIHOLE_PASSWORD;
  if (!password) throw new Error(`no resolver password stored as "${SECRET_NAME}"`);
  const body = (await fetchJson("/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password }),
  })) as { session?: { sid?: string; validity?: number } };
  const sid = body.session?.sid;
  if (!sid) throw new Error("resolver rejected the stored password");
  // Renew early; a sid that expires mid-render costs a whole refresh cycle.
  const validity = body.session?.validity ?? 300;
  session = { sid, expiresAt: Date.now() + Math.max(30, validity - 30) * 1_000 };
  return sid;
}

async function authenticate(): Promise<string> {
  if (session && Date.now() < session.expiresAt) return session.sid;

  // dnsSummary fetches several resources in parallel. Share a single login so
  // an empty/expired session does not hammer FTL's rate-limited auth endpoint.
  authentication ??= login().finally(() => {
    authentication = null;
  });
  return authentication;
}

async function call(path: string, init?: RequestInit): Promise<unknown> {
  const sid = await authenticate();
  try {
    return await fetchJson(path, { ...init, headers: { ...init?.headers, sid } });
  } catch (error) {
    if (!(error instanceof Error) || !error.message.includes("401")) throw error;
    // Another parallel request may already have replaced this sid. Do not
    // discard its fresh session when a late response arrives for the old one.
    if (session?.sid === sid) session = null;
    // The retry has to carry the original method and body: replaying a PATCH
    // as a bare GET would report success for a write that never happened.
    return fetchJson(path, { ...init, headers: { ...init?.headers, sid: await authenticate() } });
  }
}

type TopRow = { domain?: string; ip?: string; count?: number };

const keyOf = (row: TopRow) => row.domain ?? row.ip ?? "";

/**
 * FTL's permitted and blocked top lists are disjoint: a domain that is blocked
 * never appears in the permitted one. Only clients show up in both, so this
 * annotates a permitted row with its blocked share; blocked domains are
 * reported separately rather than folded in.
 */
function mergeTop(total: readonly TopRow[], blocked: readonly TopRow[]): DnsCount[] {
  const blockedByKey = new Map(blocked.map((row) => [keyOf(row), row.count ?? 0]));
  return total
    .filter((row) => keyOf(row))
    .slice(0, TOP_LIMIT)
    .map((row) => ({
      key: keyOf(row),
      queries: row.count ?? 0,
      blocked: blockedByKey.get(keyOf(row)) ?? 0,
    }));
}

function blockedTop(blocked: readonly TopRow[]): DnsCount[] {
  return blocked
    .filter((row) => keyOf(row))
    .slice(0, TOP_LIMIT)
    .map((row) => ({ key: keyOf(row), queries: row.count ?? 0, blocked: row.count ?? 0 }));
}

function empty(error: string | null): DnsSummary {
  return {
    available: false,
    error,
    windowHours: WINDOW_HOURS,
    blockingEnabled: null,
    totals: { queries: 0, blocked: 0, cached: 0, forwarded: 0, clients: 0 },
    recent: [],
    topDomains: [],
    blockedDomains: [],
    topClients: [],
  };
}

/**
 * Null rather than a throw: an FTL build that does not expose the blocking
 * switch should cost the operator the toggle, not the whole ledger view.
 */
async function readBlockingEnabled(): Promise<boolean | null> {
  try {
    const body = (await call("/api/config/dns/blocking/active")) as {
      config?: { dns?: { blocking?: { active?: boolean } } };
    };
    const active = body.config?.dns?.blocking?.active;
    return typeof active === "boolean" ? active : null;
  } catch {
    return null;
  }
}

export async function dnsSummary(): Promise<DnsSummary> {
  try {
    const [summary, queries, domains, clients, blocking] = await Promise.all([
      call("/api/stats/summary") as Promise<{
        queries?: { total?: number; blocked?: number; cached?: number; forwarded?: number };
        clients?: { active?: number; total?: number };
      }>,
      call(`/api/queries?length=${RECENT_LIMIT}`) as Promise<{
        queries?: {
          id?: number;
          time?: number;
          type?: string;
          status?: string;
          domain?: string;
          upstream?: string | null;
          client?: { ip?: string; name?: string | null };
        }[];
      }>,
      call(`/api/stats/top_domains?count=${TOP_LIMIT}`) as Promise<{ domains?: TopRow[] }>,
      call(`/api/stats/top_clients?count=${TOP_LIMIT}`) as Promise<{ clients?: TopRow[] }>,
      readBlockingEnabled(),
    ]);

    // Only worth two more round trips when something was actually suppressed.
    const anyBlocked = (summary.queries?.blocked ?? 0) > 0;
    const [blockedDomains, blockedClients] = anyBlocked
      ? await Promise.all([
          call(`/api/stats/top_domains?count=${TOP_LIMIT}&blocked=true`) as Promise<{
            domains?: TopRow[];
          }>,
          call(`/api/stats/top_clients?count=${TOP_LIMIT}&blocked=true`) as Promise<{
            clients?: TopRow[];
          }>,
        ])
      : [{ domains: [] }, { clients: [] }];

    const recent: DnsQuery[] = (queries.queries ?? []).map((row, index) => ({
      id: row.id ?? index,
      at: new Date((row.time ?? 0) * 1_000).toISOString(),
      client: row.client?.ip ?? "unknown",
      domain: row.domain ?? "unknown",
      type: row.type ?? "OTHER",
      status: statusOf(row.status ?? ""),
      upstream: row.upstream ?? null,
    }));

    return {
      available: true,
      error: null,
      windowHours: WINDOW_HOURS,
      blockingEnabled: blocking,
      totals: {
        queries: summary.queries?.total ?? 0,
        blocked: summary.queries?.blocked ?? 0,
        cached: summary.queries?.cached ?? 0,
        forwarded: summary.queries?.forwarded ?? 0,
        clients: summary.clients?.active ?? (clients.clients ?? []).length,
      },
      recent,
      topDomains: mergeTop(domains.domains ?? [], blockedDomains.domains ?? []),
      blockedDomains: blockedTop(blockedDomains.domains ?? []),
      topClients: mergeTop(clients.clients ?? [], blockedClients.clients ?? []),
    };
  } catch (error) {
    return empty(`${BASE}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Flip FTL's global blocking switch — the same state `pihole -d` and
 * `pihole -e` change. This pauses or resumes blocking for every client on the
 * network, not a single device; FTL has no per-client blocking toggle.
 *
 * The v6 webserver only accepts config writes as a PATCH on /api/config
 * wrapped in a `config` object; the flat /api/config/blocking_enabled
 * endpoint of older FTL releases 404s here.
 */
export async function setBlockingEnabled(enabled: boolean): Promise<void> {
  const result = (await call("/api/config", {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ config: { dns: { blocking: { active: enabled } } } }),
  })) as { config?: { dns?: { blocking?: { active?: boolean } } } };
  // FTL echoes the merged config back, so the echo is the cheap confirmation.
  // A build that answers 200 with a body we do not recognise gets one read of
  // the switch before we call the write failed.
  const applied = result.config?.dns?.blocking?.active;
  if (applied === enabled) return;
  if (applied === undefined && (await readBlockingEnabled()) === enabled) return;
  throw new Error("resolver did not apply the blocking change");
}
