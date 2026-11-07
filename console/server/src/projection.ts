import type { ServerMessage, Snapshot, Stats, TriageStage } from "@aisoc/shared";
import { secretPresence } from "./crypto.js";
import { ENGINE_VERSION } from "./detect/feeds.js";
import { counters, eventsPerSecond, uptimeSeconds } from "./metrics.js";
import {
  compassSummary,
  emptyCompassSummary,
  getCompassReview,
  listNetworkFlows,
} from "./network/state.js";
import { getSettings } from "./settings.js";
import { sensorHealth } from "./sources/sensor.js";
import {
  getRemoteAccess,
  getVpn,
  listActions,
  listAlerts,
  listAssets,
  listAudit,
  listDetections,
  listEvents,
  listIncidents,
  listListEntries,
  listLlmCalls,
  listNotifications,
  listPages,
  listPlaybooks,
  listQuarantine,
  listRulePacks,
  listVpnProfiles,
} from "./store.js";
import { queueBacklog } from "./triage/pipeline.js";
import { listServers } from "./vpn/servers.js";

/**
 * Read models: the two payloads the console publishes, assembled from the state
 * modules rather than owned by any of them.
 *
 * This sits above the features deliberately. Statistics and the opening
 * snapshot need detection versions, sensor liveness, triage backlog and the VPN
 * catalogue all at once — asking the state layer to reach up for those is what
 * previously forced a set of registration hooks in the store. A composition
 * layer can simply import them.
 */

function vpnServers() {
  return listServers(getSettings().site);
}

export function computeStats(): Stats {
  const events = listEvents();
  const alerts = listAlerts();
  const actions = listActions();
  const assets = listAssets();
  const settings = getSettings();
  const backlog = queueBacklog();
  const vpn = getVpn();
  const totals = counters();

  const bySeverity: Record<string, number> = { "1": 0, "2": 0, "3": 0, "4": 0 };
  for (const event of events) {
    bySeverity[String(event.severity)] = (bySeverity[String(event.severity)] ?? 0) + 1;
  }

  const byStage: Record<TriageStage, number> = {
    pending: 0,
    first_triage: 0,
    second_triage: 0,
    resolved: 0,
    needs_human: 0,
  };
  let malicious = 0;
  let suspicious = 0;
  for (const alert of alerts) {
    byStage[alert.stage] += 1;
    if (alert.detection?.band === "malicious") malicious += 1;
    else if (alert.detection?.band === "suspicious") suspicious += 1;
  }

  return {
    eventsPerSecond: eventsPerSecond(),
    queueDepth: backlog.depth,
    queueCapacity: backlog.capacity,
    totalEvents: totals.totalEvents,
    openAlerts:
      byStage.pending + byStage.first_triage + byStage.second_triage + byStage.needs_human,
    needsHuman: byStage.needs_human,
    llmInFlight: listLlmCalls().filter((call) => call.status === "running").length,
    llmTotal: totals.llmTotal,
    llmErrors: totals.llmErrors,
    tokensUsed: totals.tokensUsed,
    openIncidents: listPages().filter((page) => !page.acked && !page.closedAt).length,
    uptimeSeconds: uptimeSeconds(),
    bySeverity,
    byStage,
    ingestSource: settings.ingest.source,
    paused: settings.ingest.paused,
    sensors: sensorHealth(),

    detectionRuns: totals.detectionRuns,
    detectionHits: totals.detectionHits,
    malicious,
    suspicious,
    pendingActions: actions.filter((action) => action.status === "pending_approval").length,
    appliedActions: actions.filter((action) => action.status === "applied").length,
    quarantined: listQuarantine().filter((item) => item.status === "held").length,
    assetsOnline: assets.filter((asset) => asset.online).length,
    assetsTotal: assets.length,
    assetsIsolated: assets.filter((asset) => asset.isolated).length,
    atRiskAssets: assets.filter((asset) => asset.riskScore >= 60).length,
    openSecurityIncidents: listIncidents().filter((entry) => entry.status !== "closed").length,
    unreadNotifications: listNotifications().filter((entry) => !entry.read).length,
    autonomy: settings.response.autonomy,
    engineVersion: ENGINE_VERSION,
    vpnStatus: settings.vpn.enabled ? vpn.status : "disconnected",
    vpnCountry:
      vpn.serverId === null
        ? null
        : (vpnServers().find((server) => server.id === vpn.serverId)?.country ?? null),
    vpnKillSwitch: settings.vpn.killSwitch && vpn.killSwitchEngaged,
  };
}

/**
 * `includeCompass` is the remote-client guard. Ordinary browsing metadata is
 * more sensitive than a security alert, so a tailnet session receives the
 * security console with every Compass-derived field withheld — including the
 * model records and audit entries that would otherwise leak the same list back.
 */
export function snapshot(includeCompass = true): ServerMessage {
  const settings = getSettings();
  const body: Snapshot = {
    events: listEvents().slice(-500),
    networkFlows: includeCompass ? listNetworkFlows().slice(-1_000) : [],
    compass: includeCompass ? compassSummary() : emptyCompassSummary(),
    compassReview: includeCompass ? getCompassReview() : null,
    alerts: listAlerts(),
    llmCalls: includeCompass
      ? listLlmCalls()
      : listLlmCalls().filter(
          (call) => call.stage !== "compass_review" && call.stage !== "compass_chat",
        ),
    detections: listDetections().slice(-300),
    pages: listPages(),
    incidents: listIncidents(),
    actions: listActions(),
    assets: listAssets(),
    quarantine: listQuarantine(),
    lists: listListEntries(),
    audit: (includeCompass
      ? listAudit()
      : listAudit().filter((entry) => !entry.action.startsWith("compass."))
    ).slice(-500),
    notifications: listNotifications().slice(-150),
    rulePacks: listRulePacks(),
    playbooks: listPlaybooks(),
    vpn: getVpn(),
    vpnServers: vpnServers(),
    vpnProfiles: listVpnProfiles(),
    remoteAccess: getRemoteAccess(),
    stats: computeStats(),
    settings: includeCompass
      ? settings
      : {
          ...settings,
          networkCompass: {
            ...settings.networkCompass,
            excludedDomains: [],
            beaconSuppressions: [],
          },
        },
    secrets: secretPresence(),
  };
  return { type: "snapshot", ...body };
}
