import type { CompassReview, CompassSummary, InsightStatus, NetworkFlow } from "@aisoc/shared";
import { broadcast } from "../bus.js";
import { COMPASS_DB_FILE } from "../paths.js";
import { getSettings } from "../settings.js";
import {
  buildCompassSummary,
  type CompassConfig,
  type DomainHistory,
  type InsightFeedback,
} from "./compass.js";
import { CompassRepository } from "./repository.js";

/**
 * Network Compass state: the retained flow window, its durable mirror, and the
 * cached aggregate the console reads.
 *
 * It is kept apart from the security store because it is the one body of state
 * with a different privacy contract — ordinary browsing rather than security
 * events — and its own retention, pruning and exclusion rules. Nothing here
 * knows about alerts, incidents or responses.
 */

const MAX_NETWORK_FLOWS = 25_000;

const compassRepository = new CompassRepository(COMPASS_DB_FILE);

/**
 * Keyed by flow id and iterated in insertion order, which is also oldest-first
 * for expiry. The previous array cost a 25k-element linear scan per arriving
 * flow just to decide whether it was an update.
 */
const networkFlows = new Map<string, NetworkFlow>(
  compassRepository
    .loadFlows(getSettings().networkCompass.rawRetentionHours, MAX_NETWORK_FLOWS)
    .map((flow) => [flow.id, flow]),
);

const insightFeedback: InsightFeedback = compassRepository.loadFeedback();

let summaryCache: { at: number; summary: CompassSummary } | null = null;
let history: DomainHistory | null = null;
let lastRepositoryPrune = 0;
let broadcastTimer: NodeJS.Timeout | null = null;

/**
 * The latest model read of the aggregate table. Memory only: it names sites, so
 * it must not outlive a restart or survive "erase everything".
 */
let review: CompassReview | null = null;

function config(): CompassConfig {
  const { networkCompass } = getSettings();
  return {
    enabled: networkCompass.enabled,
    paused: networkCompass.paused,
    insightsEnabled: networkCompass.insightsEnabled,
    windowHours: networkCompass.rawRetentionHours,
  };
}

/**
 * Matches the full hostname as well as the registrable domain, so muting
 * `detectportal.firefox.com` no longer requires giving up every Mozilla flow.
 */
function isExcluded(flow: NetworkFlow): boolean {
  if (!flow.domain && !flow.hostname) return false;
  return getSettings().networkCompass.excludedDomains.some((entry) => {
    const excluded = entry
      .trim()
      .toLowerCase()
      .replace(/^\.+|\.+$/g, "");
    if (!excluded) return false;
    return [flow.hostname, flow.domain].some(
      (name) => name === excluded || (name?.endsWith(`.${excluded}`) ?? false),
    );
  });
}

function prune(now = Date.now()): void {
  const { rawRetentionHours, historyDays } = getSettings().networkCompass;
  const cutoff = now - rawRetentionHours * 3_600_000;
  for (const [id, flow] of networkFlows) {
    if (Date.parse(flow.endedAt) >= cutoff) break;
    networkFlows.delete(id);
  }
  let overflow = networkFlows.size - MAX_NETWORK_FLOWS;
  if (overflow > 0) {
    for (const id of networkFlows.keys()) {
      networkFlows.delete(id);
      if (--overflow === 0) break;
    }
  }
  if (now - lastRepositoryPrune >= 60_000) {
    compassRepository.prune(rawRetentionHours, MAX_NETWORK_FLOWS, historyDays, now);
    lastRepositoryPrune = now;
  }
}

function broadcastSummarySoon(): void {
  if (broadcastTimer) return;
  broadcastTimer = setTimeout(() => {
    broadcastTimer = null;
    broadcast({ type: "compass", summary: compassSummary() });
  }, 500);
}

export function addNetworkFlow(flow: NetworkFlow): void {
  const settings = getSettings().networkCompass;
  if (!settings.enabled || settings.paused || isExcluded(flow)) return;
  networkFlows.set(flow.id, flow);
  compassRepository.upsertFlow(flow);
  // Chatter would drown the daily history that answers "have I seen this
  // before", so only destinations a person plausibly chose are counted.
  if (flow.trafficClass !== "infrastructure" && settings.historyDays > 0) {
    const destinationKey = flow.domain ?? `ip:${flow.remoteIp}`;
    compassRepository.recordDay(
      destinationKey,
      flow.startedAt.slice(0, 10),
      flow.bytesUp,
      flow.bytesDown,
    );
    history = null;
  }
  summaryCache = null;
  prune();
  broadcast({ type: "network-flow", flow });
  broadcastSummarySoon();
}

export function listNetworkFlows(): NetworkFlow[] {
  prune();
  return [...networkFlows.values()];
}

export function compassDomainHistory(): DomainHistory {
  history ??= compassRepository.loadHistory();
  return { ...history };
}

export function compassSummary(): CompassSummary {
  prune();
  // Recomputed at most once a second: the grouping walks every retained flow
  // and every settings save used to trigger a full pass.
  const now = Date.now();
  if (summaryCache && now - summaryCache.at < 1_000) return summaryCache.summary;
  history ??= compassRepository.loadHistory();
  const summary = buildCompassSummary(networkFlows.values(), config(), history, insightFeedback);
  summaryCache = { at: now, summary };
  return summary;
}

/** The shape the snapshot sends when Compass data is withheld from a remote client. */
export function emptyCompassSummary(): CompassSummary {
  return buildCompassSummary([], {
    enabled: false,
    paused: true,
    insightsEnabled: false,
    windowHours: 0,
  });
}

export function getCompassReview(): CompassReview | null {
  return review;
}

export function setCompassReview(next: CompassReview | null): void {
  review = next;
  broadcast({ type: "compass-review", review: next });
}

export function invalidateCompassSummary(): void {
  summaryCache = null;
  history = null;
}

export function clearCompassData(): void {
  networkFlows.clear();
  review = null;
  for (const key of Object.keys(insightFeedback)) delete insightFeedback[key];
  compassRepository.clear();
  invalidateCompassSummary();
  broadcast({ type: "compass-review", review: null });
  broadcast({ type: "compass", summary: compassSummary() });
}

export function setInsightFeedback(
  id: string,
  status: InsightStatus,
  snoozedUntil: string | null,
): void {
  insightFeedback[id] = { status, snoozedUntil };
  compassRepository.setFeedback(id, status, snoozedUntil);
  summaryCache = null;
  broadcast({ type: "compass", summary: compassSummary() });
}
