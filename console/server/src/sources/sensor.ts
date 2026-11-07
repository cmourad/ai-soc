import { statSync } from "node:fs";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import type { SensorHealth } from "@aisoc/shared";
import { REPO_ROOT } from "../paths.js";
import { getSettings } from "../settings.js";

/**
 * Suricata writes stats and flow records on its own timer, so a live sensor
 * touches eve.json even when the network is silent. A log that stops growing is
 * therefore a dead sensor rather than a quiet one — the failure the console
 * could not otherwise see, because ingest keeps reporting "live" while the
 * event table empties out.
 */
export const SENSOR_SILENCE_MS = 120_000;

/** Enough of the path to tell the tap and the VPN sensor apart. */
function label(path: string): string {
  return `${basename(dirname(path))}/${basename(path)}`;
}

export function readSensorHealth(
  paths: string[],
  now = Date.now(),
  silenceMs = SENSOR_SILENCE_MS,
): SensorHealth[] {
  return paths.map((path) => {
    let modifiedAt: number;
    try {
      modifiedAt = statSync(path).mtimeMs;
    } catch {
      return { path, label: label(path), ok: false, lastWriteAt: null, detail: "log is missing" };
    }

    const silentMs = now - modifiedAt;
    if (silentMs < silenceMs) {
      return {
        path,
        label: label(path),
        ok: true,
        lastWriteAt: new Date(modifiedAt).toISOString(),
        detail: "writing",
      };
    }
    return {
      path,
      label: label(path),
      ok: false,
      lastWriteAt: new Date(modifiedAt).toISOString(),
      detail: `no output for ${humanGap(silentMs)}`,
    };
  });
}

function humanGap(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  return hours < 24 ? `${hours}h ${minutes % 60}m` : `${Math.floor(hours / 24)}d ${hours % 24}h`;
}

/** Configured eve.json taps, resolved against the repo root when relative. */
export function evePaths(): string[] {
  return getSettings()
    .ingest.evePath.split(",")
    .map((configured) => configured.trim())
    .filter(Boolean)
    .map((configured) => (isAbsolute(configured) ? configured : resolve(REPO_ROOT, configured)));
}

/** The cluster spool, when the collector is enabled. */
export function clusterPaths(): string[] {
  const cluster = getSettings().clusterTelemetry;
  if (!cluster.enabled || !cluster.spoolPath.trim()) return [];
  const configured = cluster.spoolPath.trim();
  return [isAbsolute(configured) ? configured : resolve(REPO_ROOT, configured)];
}

/**
 * Seeded ingest has no sensor behind it, so it reports none rather than a dead
 * tap. The cluster spool is reported independently of the ingest source: it is
 * a second vantage point, and a dead collector must be visible even while the
 * network sensors are healthy. This is the host-side deadman — the one that
 * still works when the cluster it watches is the thing that failed.
 */
export function sensorHealth(): SensorHealth[] {
  const eve = getSettings().ingest.source === "eve" ? readSensorHealth(evePaths()) : [];
  const cluster = readSensorHealth(
    clusterPaths(),
    Date.now(),
    getSettings().clusterTelemetry.silenceMinutes * 60_000,
  );
  return [...eve, ...cluster];
}
