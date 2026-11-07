import type { Alert, Asset, SecurityEvent } from "@aisoc/shared";
import { isLocal, localIp } from "./detect/engine.js";
import { getSettings } from "./settings.js";
import {
  addAudit,
  addNotification,
  getAsset,
  listAlerts,
  listAssets,
  upsertAsset,
} from "./store.js";

/**
 * Host inventory and risk. Risk is a decayed accumulator rather than a count:
 * a host that was attacked an hour ago and has been quiet since should drift
 * back down on its own, or the estate view turns into a list of everything that
 * has ever been noisy.
 */

const HALF_LIFE_MINUTES = 45;

const SEED: Omit<Asset, "riskScore" | "openAlerts" | "criticalAlerts" | "lastSeen">[] = [
  {
    id: "host-9",
    hostname: "soc-host",
    ip: "192.0.2.9",
    mac: "02:00:00:00:00:01",
    os: "Ubuntu 25.10 · kernel 7.0.0-28",
    kind: "workstation",
    owner: "aisoc",
    tags: ["primary", "sensor-host", "console"],
    online: true,
    isolated: false,
    protection: {
      realtime: true,
      firewall: true,
      rulesVersion: "2026.08.4",
      lastScan: "2026-08-05T04:12:00.000Z",
      agentVersion: "aisoc-agent 1.4.0",
    },
    lat: null,
    lon: null,
  },
  {
    id: "host-14",
    hostname: "build-srv",
    ip: "192.0.2.14",
    mac: "02:00:00:00:00:02",
    os: "Debian 13 · kernel 6.12",
    kind: "server",
    owner: "aisoc",
    tags: ["build", "docker"],
    online: true,
    isolated: false,
    protection: {
      realtime: true,
      firewall: true,
      rulesVersion: "2026.08.4",
      lastScan: "2026-08-05T02:40:00.000Z",
      agentVersion: "aisoc-agent 1.4.0",
    },
    lat: null,
    lon: null,
  },
  {
    id: "host-32",
    hostname: "work-laptop",
    ip: "192.0.2.32",
    mac: "02:00:00:00:00:03",
    os: "Fedora 43 Workstation",
    kind: "laptop",
    owner: "analyst",
    tags: ["roaming", "byod"],
    online: true,
    isolated: false,
    protection: {
      realtime: true,
      firewall: false,
      rulesVersion: "2026.07.29",
      lastScan: "2026-08-01T19:05:00.000Z",
      agentVersion: "aisoc-agent 1.3.2",
    },
    lat: null,
    lon: null,
  },
  {
    id: "host-51",
    hostname: "backup-nas",
    ip: "192.0.2.51",
    mac: "02:00:00:00:00:04",
    os: "TrueNAS SCALE 25.04",
    kind: "server",
    owner: "aisoc",
    tags: ["storage", "backup", "crown-jewel"],
    online: true,
    isolated: false,
    protection: {
      realtime: false,
      firewall: true,
      rulesVersion: "2026.06.11",
      lastScan: null,
      agentVersion: "aisoc-agent 1.2.0",
    },
    lat: null,
    lon: null,
  },
];

export function seedAssets(): void {
  if (listAssets().length > 0) return;
  const { site } = getSettings();
  for (const asset of SEED) {
    upsertAsset({
      ...asset,
      lat: site.lat,
      lon: site.lon,
      riskScore: 0,
      openAlerts: 0,
      criticalAlerts: 0,
      lastSeen: new Date().toISOString(),
    });
  }
}

function byIp(ip: string): Asset | undefined {
  return listAssets().find((asset) => asset.ip === ip);
}

/** The managed host an event concerns, if either endpoint is one of ours. */
export function assetForEvent(event: SecurityEvent): Asset | undefined {
  if (event.assetId) return getAsset(event.assetId);
  const local = localIp(event);
  if (isLocal(local)) return byIp(local);
  return byIp(event.srcIp) ?? byIp(event.destIp);
}

/**
 * Risk decays on its own clock rather than off `lastSeen`, which means "the host
 * checked in" and would otherwise be rewritten by every decay tick.
 */
const riskClock = new Map<string, number>();

function decay(asset: Asset, now: number): number {
  const since = riskClock.get(asset.id) ?? now;
  riskClock.set(asset.id, now);
  const elapsedMinutes = (now - since) / 60_000;
  if (elapsedMinutes <= 0) return asset.riskScore;
  return asset.riskScore * 0.5 ** (elapsedMinutes / HALF_LIFE_MINUTES);
}

/** Marks the host as seen and folds the alert's detection score into its risk. */
export function recordAlertOnAsset(alert: Alert): Asset | undefined {
  const asset = assetForEvent(alert.event);
  if (!asset) return undefined;
  const now = Date.now();
  const contribution = Math.max(
    alert.detection?.score ?? 0,
    alert.event.severity === 1 ? 30 : alert.event.severity === 2 ? 18 : 6,
  );

  const before = asset.riskScore;
  const decayed = decay(asset, now);
  // Saturating add: risk approaches 100 but a single event never pins it there.
  asset.riskScore = Math.round(Math.min(100, decayed + contribution * (1 - decayed / 100)));
  asset.lastSeen = new Date(now).toISOString();
  asset.online = true;
  recountAlerts(asset);
  upsertAsset(asset);

  if (before < 60 && asset.riskScore >= 60) {
    addNotification({
      kind: "asset",
      level: "warning",
      title: `${asset.hostname} crossed the at-risk threshold`,
      body: `Risk ${asset.riskScore}/100 across ${asset.openAlerts} open alerts. Latest: ${alert.event.signature}.`,
      linkView: "assets",
      linkId: asset.id,
    });
  }
  return asset;
}

/**
 * Counted from the queue rather than accumulated. An incrementing counter drifts
 * the moment an alert is overridden, re-queued, or aged out, and a host card
 * claiming ten open alerts when the queue holds two is worse than no count.
 */
function recountAlerts(asset: Asset): void {
  const mine = listAlerts().filter((alert) => alert.assetId === asset.id);
  asset.openAlerts = mine.filter((alert) => alert.stage !== "resolved").length;
  asset.criticalAlerts = mine.filter(
    (alert) => alert.stage !== "resolved" && alert.event.severity === 1,
  ).length;
}

/** Keeps host cards honest as alerts leave the queue without new ones arriving. */
export function refreshAlertCounts(): void {
  for (const asset of listAssets()) {
    const before = `${asset.openAlerts}:${asset.criticalAlerts}`;
    recountAlerts(asset);
    if (before !== `${asset.openAlerts}:${asset.criticalAlerts}`) upsertAsset(asset);
  }
}

export function setIsolation(assetId: string, isolated: boolean, by: string): Asset | null {
  const asset = getAsset(assetId);
  if (!asset) return null;
  asset.isolated = isolated;
  asset.lastSeen = new Date().toISOString();
  upsertAsset(asset);
  addAudit(
    by,
    isolated ? "asset.isolate" : "asset.release",
    asset.hostname,
    isolated
      ? "Host isolated from the network; management traffic to the console is preserved."
      : "Host returned to the network.",
  );
  addNotification({
    kind: "asset",
    level: isolated ? "critical" : "info",
    title: `${asset.hostname} ${isolated ? "isolated" : "released from isolation"}`,
    body: `${by} ${isolated ? "cut" : "restored"} network access for ${asset.ip}.`,
    linkView: "assets",
    linkId: asset.id,
  });
  return asset;
}

/** Ages risk down on hosts that have gone quiet, so the estate view stays honest. */
export function decayAllAssets(): void {
  const now = Date.now();
  for (const asset of listAssets()) {
    if (asset.riskScore === 0) continue;
    const next = Math.round(decay(asset, now));
    if (next === asset.riskScore) continue;
    asset.riskScore = next;
    upsertAsset(asset);
  }
}
