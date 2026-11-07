import assert from "node:assert/strict";
import test from "node:test";
import type { NetworkFlow } from "@aisoc/shared";
import { scoreCompassBeacons } from "./beacon.js";

const BASE = Date.parse("2026-08-08T12:00:00Z");
const IP = "203.0.113.77";
const KEY = `ip:${IP}`;

function series(
  input: {
    processName?: string | null;
    destinationDays?: number;
    named?: boolean;
    bytes?: readonly number[];
    gaps?: readonly number[];
  } = {},
): { flows: NetworkFlow[]; knownDays: Record<string, number> } {
  const gaps = input.gaps ?? [90, 78, 105, 84, 96, 75, 108, 88, 101, 82, 94, 79];
  const bytes = input.bytes ?? gaps.map((_, index) => 760 + (index % 3) * 35);
  let at = BASE;
  const starts = [at];
  for (const gap of gaps) {
    at += gap * 1_000;
    starts.push(at);
  }
  return {
    flows: starts.map((startedAt, index) => ({
      id: `flow-${index}`,
      flowId: String(index),
      sensor: "aisoc0",
      startedAt: new Date(startedAt).toISOString(),
      endedAt: new Date(startedAt + 1_000).toISOString(),
      updatedAt: new Date(startedAt + 1_000).toISOString(),
      localIp: "192.0.2.10",
      localPort: 50_000 + index,
      remoteIp: IP,
      remotePort: 443,
      direction: "outbound",
      trafficClass: "web",
      proto: "TCP",
      appProto: "tls",
      hostname: input.named ? "edge.example.net" : null,
      domain: input.named ? "example.net" : null,
      domainSource: input.named ? "tls" : null,
      domainConfidence: input.named ? "asserted" : "unknown",
      country: "US",
      asn: "AS64500 TEST-NET",
      organization: "Test Network",
      bytesUp: Math.floor((bytes[index % bytes.length] ?? 800) / 2),
      bytesDown: Math.ceil((bytes[index % bytes.length] ?? 800) / 2),
      packetsUp: 2,
      packetsDown: 2,
      state: "closed",
      category: null,
      processName: input.processName ?? null,
    })),
    knownDays: { [input.named ? "example.net" : KEY]: input.destinationDays ?? 1 },
  };
}

test("jittered, novel, unresolved callbacks from an unexpected process score as a beacon", () => {
  const candidate = series({ processName: "odd-helper" });
  const findings = scoreCompassBeacons(candidate.flows, {
    hasPastDays: true,
    knownDays: candidate.knownDays,
  });

  assert.equal(findings.length, 1);
  assert.ok(findings[0]!.detection.score >= 40);
  assert.ok(findings[0]!.intervalConcentration >= 0.8);
  assert.deepEqual(findings[0]!.detection.mitre.map((reference) => reference.techniqueId).sort(), [
    "T1071",
    "T1573",
  ]);
});

test("regular benign pollers and established or named destinations stay quiet", () => {
  const firefox = series({ processName: "firefox" });
  const established = series({ processName: "odd-helper", destinationDays: 2 });
  const named = series({ processName: "odd-helper", named: true });

  assert.equal(
    scoreCompassBeacons(firefox.flows, { hasPastDays: true, knownDays: firefox.knownDays }).length,
    0,
  );
  assert.equal(
    scoreCompassBeacons(established.flows, {
      hasPastDays: true,
      knownDays: established.knownDays,
    }).length,
    0,
  );
  assert.equal(
    scoreCompassBeacons(named.flows, { hasPastDays: true, knownDays: named.knownDays }).length,
    0,
  );
});

test("short bursts, nonuniform exchanges and suppressions do not alert", () => {
  const short = series({ gaps: [20, 22, 18, 21, 19, 20, 23, 18, 22] });
  const noisyPayload = series({ bytes: [100, 5_000, 200, 7_000, 300, 9_000] });
  const suppressed = series({ processName: "odd-helper" });

  assert.equal(
    scoreCompassBeacons(short.flows, { hasPastDays: true, knownDays: short.knownDays }).length,
    0,
  );
  assert.equal(
    scoreCompassBeacons(noisyPayload.flows, {
      hasPastDays: true,
      knownDays: noisyPayload.knownDays,
    }).length,
    0,
  );
  assert.equal(
    scoreCompassBeacons(suppressed.flows, { hasPastDays: true, knownDays: suppressed.knownDays }, [
      KEY,
    ]).length,
    0,
  );
});

test("novelty is disabled until the ledger contains an earlier day", () => {
  const candidate = series({ processName: "odd-helper" });
  assert.equal(
    scoreCompassBeacons(candidate.flows, {
      hasPastDays: false,
      knownDays: candidate.knownDays,
    }).length,
    0,
  );
});

/** A UDP flow to the same address, alongside the scored TCP series. */
function sidecar(input: { remotePort: number; localPort: number; count: number }): NetworkFlow[] {
  return Array.from({ length: input.count }, (_, index) => ({
    id: `udp-${index}`,
    flowId: `udp-${index}`,
    sensor: "aisoc0",
    startedAt: new Date(BASE + index * 30_000).toISOString(),
    endedAt: new Date(BASE + index * 30_000 + 500).toISOString(),
    updatedAt: new Date(BASE + index * 30_000 + 500).toISOString(),
    localIp: "192.0.2.10",
    localPort: input.localPort,
    remoteIp: IP,
    remotePort: input.remotePort,
    direction: "outbound",
    trafficClass: "web",
    proto: "UDP",
    appProto: null,
    hostname: null,
    domain: null,
    domainSource: null,
    domainConfidence: "unknown",
    country: "US",
    asn: "AS64500 TEST-NET",
    organization: "Test Network",
    bytesUp: 82,
    bytesDown: 96,
    packetsUp: 1,
    packetsDown: 1,
    state: "closed",
    category: null,
    processName: null,
  }));
}

test("a destination this host runs NAT traversal against is a relay, not a beacon", () => {
  const candidate = series({ processName: "odd-helper" });
  const withStun = [
    ...candidate.flows,
    ...sidecar({ remotePort: 3478, localPort: 41641, count: 2 }),
  ];

  assert.equal(
    scoreCompassBeacons(candidate.flows, {
      hasPastDays: true,
      knownDays: candidate.knownDays,
    }).length,
    1,
  );
  assert.equal(
    scoreCompassBeacons(withStun, {
      hasPastDays: true,
      knownDays: candidate.knownDays,
    }).length,
    0,
  );
});

test("repeated datagrams from one pinned local port read as a tunnel endpoint", () => {
  const candidate = series({ processName: "odd-helper" });
  const pinned = [
    ...candidate.flows,
    ...sidecar({ remotePort: 41641, localPort: 41641, count: 5 }),
  ];
  const ephemeral = [
    ...candidate.flows,
    ...sidecar({ remotePort: 41641, localPort: 41641, count: 4 }),
  ];

  assert.equal(
    scoreCompassBeacons(pinned, {
      hasPastDays: true,
      knownDays: candidate.knownDays,
    }).length,
    0,
  );
  assert.equal(
    scoreCompassBeacons(ephemeral, {
      hasPastDays: true,
      knownDays: candidate.knownDays,
    }).length,
    1,
  );
});
