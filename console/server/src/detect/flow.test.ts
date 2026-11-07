import assert from "node:assert/strict";
import test from "node:test";
import {
  inboundBytes,
  isLocal,
  orientationKnown,
  outboundBytes,
  outboundPayloadBytes,
  remoteIp,
  type SecurityEvent,
  setLocalNetworks,
} from "@aisoc/shared";
import { RULES } from "./rules.js";

const EXFIL_RULE = RULES.find((rule) => rule.id === "AISOC-EXFIL-0001")!;

function event(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: "evt",
    ts: "2026-08-09T18:10:42.000Z",
    srcIp: "10.2.0.2",
    srcPort: 37_564,
    destIp: "151.101.130.132",
    destPort: 80,
    proto: "TCP",
    appProto: "http",
    signature: "ET INFO GNU/Linux APT User-Agent Outbound likely related to package management",
    signatureId: 2_013_504,
    category: "Not Suspicious Traffic",
    severity: 3,
    tags: [],
    direction: "to_server",
    bytesToServer: 0,
    bytesToClient: 0,
    source: "eve",
    ...overrides,
  };
}

// INC-0007: an apt download scored 49/100 as exfiltration because the rule read
// the total flow size and trusted `direction`, which is only the direction of
// the packet that matched the signature.
test("a large download is not outbound volume", () => {
  const download = event({ bytesToServer: 41_204, bytesToClient: 699_000_000 });

  assert.equal(outboundBytes(download), 41_204);
  assert.equal(inboundBytes(download), 699_000_000);
  assert.equal(EXFIL_RULE.match(download), null);
});

test("a large upload is outbound volume", () => {
  const upload = event({ bytesToServer: 699_000_000, bytesToClient: 41_204 });

  assert.equal(outboundBytes(upload), 699_000_000);
  assert.deepEqual(EXFIL_RULE.match(upload), {
    field: "bytesToServer",
    value: "699.0 MB sent",
  });
});

// When the remote end opened the connection, what we sent is bytes_toclient.
test("outbound is measured from our end, not the flow initiator", () => {
  const inbound = event({
    srcIp: "203.0.113.9",
    destIp: "10.2.0.2",
    direction: "to_server",
    bytesToServer: 6_100,
    bytesToClient: 40_000_000,
  });

  assert.equal(remoteIp(inbound), "203.0.113.9");
  assert.equal(outboundBytes(inbound), 40_000_000);
  assert.equal(inboundBytes(inbound), 6_100);
  assert.deepEqual(EXFIL_RULE.match(inbound), {
    field: "bytesToServer",
    value: "40.0 MB sent",
  });
});

// INC-0125: a TLS download from Fastly alerted on a to_client STREAM packet, so
// the remote end was src_ip while the byte counters stayed anchored to us as
// the flow client — 25 MB pulled down read as 25 MB pushed out.
test("a download that alerts on a to_client packet is not outbound volume", () => {
  const download = event({
    srcIp: "151.101.193.91",
    srcPort: 443,
    destIp: "10.2.0.2",
    destPort: 45_164,
    direction: "to_client",
    appProto: "tls",
    signature: "SURICATA STREAM ESTABLISHED invalid ack",
    bytesToServer: 733_000,
    bytesToClient: 29_400_000,
  });

  assert.equal(remoteIp(download), "151.101.193.91");
  assert.equal(outboundBytes(download), 733_000);
  assert.equal(inboundBytes(download), 29_400_000);
  assert.equal(EXFIL_RULE.match(download), null);
});

// The ack stream acknowledging a 33 MB download is 813 kB of bare headers, and
// bytes alone cannot tell that apart from having uploaded 813 kB.
test("an ack stream is not payload", () => {
  const acks = event({
    bytesToServer: 813_458,
    bytesToClient: 33_100_317,
    pktsToServer: 13_468,
    pktsToClient: 21_658,
  });

  assert.equal(outboundBytes(acks), 813_458);
  assert.equal(outboundPayloadBytes(acks), 0);
});

test("a real upload keeps its payload once packet counts are known", () => {
  const upload = event({
    bytesToServer: 699_000_000,
    bytesToClient: 41_204,
    pktsToServer: 480_000,
    pktsToClient: 12_000,
  });

  assert.equal(outboundPayloadBytes(upload), 699_000_000);
  assert.deepEqual(EXFIL_RULE.match(upload), {
    field: "bytesToServer",
    value: "699.0 MB sent",
  });
});

// A sensor that reports no packet counts must not have its detections suppressed.
test("missing packet counts fall through to the byte total", () => {
  const upload = event({ bytesToServer: 699_000_000, bytesToClient: 41_204 });

  assert.equal(outboundPayloadBytes(upload), 699_000_000);
});

// INC-0126: a 963 MB model download over a VPN whose IPv6 prefix was globally
// routable. Both ends looked external, so the site's own tunnel address was
// named as the hostile remote and the download was scored as 943 MB sent.
const VPN_DOWNLOAD: Partial<SecurityEvent> = {
  srcIp: "2001:0db8:0000:0000:0000:0000:0002:0002",
  srcPort: 58_506,
  destIp: "2606:4700:0020:0000:0000:0000:ac43:455c",
  destPort: 443,
  appProto: "tls",
  direction: "to_server",
  flowInitiatorIp: "2001:0db8:0000:0000:0000:0000:0002:0002",
  signature: "SURICATA STREAM ESTABLISHED invalid ack",
  bytesToServer: 15_215_766,
  bytesToClient: 709_844_544,
  pktsToServer: 201_840,
  pktsToClient: 437_205,
};

test("an undeclared tunnel prefix leaves the flow unoriented rather than inverted", () => {
  setLocalNetworks([], []);
  const download = event(VPN_DOWNLOAD);

  assert.equal(orientationKnown(download), false);
  assert.equal(outboundPayloadBytes(download), 0);
  assert.equal(EXFIL_RULE.match(download), null);
  // Whatever we cannot orient, we must never name our own end as the remote.
  assert.equal(remoteIp(download), "2606:4700:0020:0000:0000:0000:ac43:455c");
});

test("a declared tunnel prefix orients the flow and reads the download as inbound", () => {
  setLocalNetworks(["2001:db8::/48"], []);
  const download = event(VPN_DOWNLOAD);

  assert.equal(isLocal("2001:0db8:0000:0000:0000:0000:0002:0002"), true);
  assert.equal(remoteIp(download), "2606:4700:0020:0000:0000:0000:ac43:455c");
  assert.equal(outboundBytes(download), 15_215_766);
  assert.equal(inboundBytes(download), 709_844_544);
  // 15.2 MB over 201,840 packets is 75 B each — the ack stream, not a transfer.
  assert.equal(outboundPayloadBytes(download), 0);
  assert.equal(EXFIL_RULE.match(download), null);
  setLocalNetworks([], []);
});

test("bulk transfer between two private hosts is not exfiltration", () => {
  const internal = event({
    destIp: "10.2.0.40",
    bytesToServer: 900_000_000,
    bytesToClient: 2_400,
  });

  assert.equal(EXFIL_RULE.match(internal), null);
});
