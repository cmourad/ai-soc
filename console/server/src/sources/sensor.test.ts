import assert from "node:assert/strict";
import { mkdtempSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { readSensorHealth, SENSOR_SILENCE_MS } from "./sensor.js";

function eveLog(dir: string, ageMs: number): string {
  const root = mkdtempSync(join(tmpdir(), "aisoc-sensor-"));
  const path = join(root, dir);
  writeFileSync(path, "");
  const seconds = (Date.now() - ageMs) / 1_000;
  utimesSync(path, seconds, seconds);
  return path;
}

test("a log written just now is healthy", () => {
  const [sensor] = readSensorHealth([eveLog("eve.json", 0)]);

  assert.equal(sensor?.ok, true);
  assert.equal(sensor?.detail, "writing");
});

// Suricata writes stats records on its own timer, so silence is a dead sensor
// rather than a quiet network — the case that emptied the console for 11 hours.
test("a log that stopped growing is unhealthy", () => {
  const [sensor] = readSensorHealth([eveLog("eve.json", SENSOR_SILENCE_MS + 60_000)]);

  assert.equal(sensor?.ok, false);
  assert.equal(sensor?.detail, "no output for 3 min");
});

test("a long outage reads in hours", () => {
  const [sensor] = readSensorHealth([eveLog("eve.json", 11 * 3_600_000)]);

  assert.equal(sensor?.ok, false);
  assert.equal(sensor?.detail, "no output for 11h 0m");
});

test("a missing log is unhealthy rather than an exception", () => {
  const [sensor] = readSensorHealth(["/nonexistent/logs/eve.json"]);

  assert.equal(sensor?.ok, false);
  assert.equal(sensor?.lastWriteAt, null);
  assert.equal(sensor?.detail, "log is missing");
});

// Both sensors write a file called eve.json; the parent directory is what
// distinguishes the tap from the VPN sensor in a notification.
test("labels keep the two sensors apart", () => {
  const health = readSensorHealth([
    "/srv/aisoc/suricata/logs/eve.json",
    "/srv/aisoc/suricata/logs-vpn/eve.json",
  ]);

  assert.deepEqual(
    health.map((sensor) => sensor.label),
    ["logs/eve.json", "logs-vpn/eve.json"],
  );
});
