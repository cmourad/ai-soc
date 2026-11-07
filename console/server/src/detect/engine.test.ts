import assert from "node:assert/strict";
import test from "node:test";
import type { SecurityEvent } from "@aisoc/shared";
import { runDetection } from "./engine.js";

function uploadEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: "evt",
    ts: "2026-08-13T18:24:38.000Z",
    srcIp: "10.2.0.2",
    srcPort: 45_164,
    destIp: "198.51.100.77",
    destPort: 443,
    proto: "TCP",
    appProto: "tls",
    signature: "SURICATA STREAM ESTABLISHED packet out of window",
    signatureId: 2_210_020,
    category: "Generic Protocol Command Decode",
    severity: 3,
    tags: [],
    direction: "to_server",
    bytesToServer: 30_000_000,
    bytesToClient: 400_000,
    pktsToServer: 21_000,
    pktsToClient: 9_000,
    source: "eve",
    ...overrides,
  };
}

const exfilVolume = (event: SecurityEvent) =>
  runDetection(event).hits.find((hit) => hit.ruleId === "AISOC-BEH-EXFIL");

// INC-0125: flow.bytes_* are cumulative for the life of the flow, so three
// alerts on one connection re-added its whole total twice and reported 429 GB
// of egress from a single transfer.
test("repeated alerts on one flow do not re-add the flow's total", () => {
  const flow = { destIp: "198.51.100.77" };

  assert.equal(exfilVolume(uploadEvent(flow)), undefined);
  assert.equal(exfilVolume(uploadEvent(flow)), undefined);
  assert.equal(exfilVolume(uploadEvent(flow)), undefined);
});

// Two separate connections to the same destination are genuinely additive.
test("distinct flows to one destination accumulate", () => {
  const dest = "198.51.100.88";

  assert.equal(exfilVolume(uploadEvent({ destIp: dest, srcPort: 40_001 })), undefined);
  const hit = exfilVolume(uploadEvent({ destIp: dest, srcPort: 40_002 }));

  assert.ok(hit);
  assert.equal(hit.value, `60 MB → ${dest}`);
});

// The same guard the rule pack uses: acknowledging a download is not volume.
test("an ack stream never accumulates as outbound volume", () => {
  const download = {
    destIp: "198.51.100.99",
    bytesToServer: 813_458,
    bytesToClient: 33_100_317,
    pktsToServer: 13_468,
    pktsToClient: 21_658,
  };

  for (let i = 0; i < 200; i++) {
    assert.equal(exfilVolume(uploadEvent({ ...download, srcPort: 40_000 + i })), undefined);
  }
});
