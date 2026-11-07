import assert from "node:assert/strict";
import test from "node:test";
import type { NetworkFlow } from "@aisoc/shared";
import { inNetwork } from "@aisoc/shared";
import {
  buildCompassSummary,
  type CompassConfig,
  categoryForDomain,
  EveFlowCorrelator,
  registrableDomain,
} from "./compass.js";
import { CompassRepository } from "./repository.js";

const home = ["192.0.2.0/24", "10.0.0.0/8"];
const config: CompassConfig = {
  enabled: true,
  paused: false,
  insightsEnabled: true,
  windowHours: 24,
};

test("IPv4 CIDRs are matched without confusing adjacent networks", () => {
  assert.equal(inNetwork("192.0.2.42", "192.0.2.0/24"), true);
  assert.equal(inNetwork("198.51.100.42", "192.0.2.0/24"), false);
  assert.equal(inNetwork("10.99.1.4", "10.0.0.0/8"), true);
});

test("IPv6 CIDRs normalize compressed and expanded addresses", () => {
  assert.equal(inNetwork("2001:0db8:0000:0000:0000:0000:0002:0002", "2001:db8::/32"), true);
  assert.equal(inNetwork("2001:db9::1", "2001:db8::/32"), false);
});

test("registrable domains discard subdomains and malformed values", () => {
  assert.equal(registrableDomain("API.GitHub.com."), "github.com");
  assert.equal(registrableDomain("news.bbc.co.uk"), "bbc.co.uk");
  assert.equal(registrableDomain("bad domain.example"), null);
  assert.equal(registrableDomain("1.2.3.4"), null);
});

test("protocol machinery is never treated as a destination", () => {
  assert.equal(registrableDomain("ipv4only.arpa"), null);
  assert.equal(registrableDomain("1.0.0.10.in-addr.arpa"), null);
  assert.equal(registrableDomain("use-application-dns.net"), null);
  assert.equal(registrableDomain("printer.local"), null);
});

test("TLS metadata is correlated into an outbound terminal flow", () => {
  const correlator = new EveFlowCorrelator();
  assert.equal(
    correlator.consume(
      { event_type: "tls", flow_id: 42, tls: { sni: "api.github.com" } },
      "aisoc0",
      home,
    ),
    null,
  );
  const flow = correlator.consume(
    {
      event_type: "flow",
      flow_id: 42,
      timestamp: "2026-08-08T12:01:00Z",
      src_ip: "192.0.2.9",
      src_port: 50123,
      dest_ip: "140.82.112.3",
      dest_port: 443,
      proto: "TCP",
      app_proto: "tls",
      flow: {
        start: "2026-08-08T12:00:00Z",
        end: "2026-08-08T12:01:00Z",
        bytes_toserver: 1_000,
        bytes_toclient: 5_000,
        pkts_toserver: 10,
        pkts_toclient: 20,
        state: "closed",
      },
    },
    "aisoc0",
    home,
  );
  assert.ok(flow);
  assert.equal(flow.direction, "outbound");
  assert.equal(flow.localIp, "192.0.2.9");
  assert.equal(flow.remoteIp, "140.82.112.3");
  assert.equal(flow.bytesUp, 1_000);
  assert.equal(flow.bytesDown, 5_000);
  assert.equal(flow.hostname, "api.github.com");
  assert.equal(flow.domain, "github.com");
  assert.equal(flow.domainSource, "tls");
  assert.equal(flow.domainConfidence, "asserted");
  assert.equal(flow.trafficClass, "web");
  assert.equal(flow.category, "software-development");
});

test("a name observed on one sensor does not leak into the other's flow ids", () => {
  const correlator = new EveFlowCorrelator();
  correlator.consume(
    { event_type: "tls", flow_id: 99, tls: { sni: "api.github.com" } },
    "aisoc0",
    home,
  );
  const other = correlator.consume(
    {
      event_type: "flow",
      flow_id: 99,
      src_ip: "192.0.2.9",
      dest_ip: "203.0.113.9",
      dest_port: 443,
      flow: { bytes_toserver: 10, bytes_toclient: 10 },
    },
    "wlp7s0",
    home,
  );
  assert.ok(other);
  assert.equal(other.domain, null);
  assert.equal(other.domainConfidence, "unknown");
});

test("a DNS query is attributed to the resolver, not to the name asked about", () => {
  const flow = new EveFlowCorrelator().consume(
    {
      event_type: "flow",
      flow_id: 5,
      src_ip: "10.2.0.2",
      src_port: 49681,
      dest_ip: "10.2.0.1",
      dest_port: 53,
      proto: "UDP",
      app_proto: "dns",
      dns: { type: "query", rrname: "chatgpt.com" },
      flow: { bytes_toserver: 68, bytes_toclient: 124 },
    },
    "aisoc0",
    home,
  );
  assert.ok(flow);
  assert.equal(flow.domain, null, "the destination is the resolver");
  assert.equal(flow.trafficClass, "infrastructure");
});

test("a DNS answer names the later connection to the address it returned", () => {
  const correlator = new EveFlowCorrelator();
  correlator.consume(
    {
      event_type: "dns",
      flow_id: 6,
      timestamp: "2026-08-08T12:00:00Z",
      src_ip: "10.2.0.1",
      dest_ip: "10.2.0.2",
      dns: {
        type: "answer",
        rrname: "api.telegram.org",
        answers: [{ rrname: "api.telegram.org", rdata: "2001:067c:04e8:f004:0000:0000:0000:0009" }],
      },
    },
    "aisoc0",
    home,
  );
  const flow = correlator.consume(
    {
      event_type: "flow",
      flow_id: 7,
      timestamp: "2026-08-08T12:00:30Z",
      src_ip: "10.2.0.2",
      src_port: 40888,
      // Compressed here, expanded in the DNS answer: both must resolve alike.
      dest_ip: "2001:67c:4e8:f004::9",
      dest_port: 443,
      app_proto: "tls",
      flow: { bytes_toserver: 3_000, bytes_toclient: 7_500 },
    },
    "aisoc0",
    home,
  );
  assert.ok(flow);
  assert.equal(flow.hostname, "api.telegram.org");
  assert.equal(flow.domain, "telegram.org");
  assert.equal(flow.domainConfidence, "inferred");
});

test("the tunnel endpoint is transport, not a site that moved 18 GB", () => {
  const encrypted = {
    event_type: "flow",
    flow_id: 20,
    src_ip: "192.0.2.9",
    src_port: 51820,
    dest_ip: "195.181.163.1",
    dest_port: 51820,
    proto: "UDP",
    flow: { bytes_toserver: 5_000_000, bytes_toclient: 90_000_000 },
  };
  const asDestination = new EveFlowCorrelator().consume(encrypted, "wlp7s0", home);
  assert.equal(asDestination?.trafficClass, "other");

  const asTransport = new EveFlowCorrelator().consume(
    encrypted,
    "wlp7s0",
    home,
    [],
    ["195.181.163.1"],
  );
  assert.equal(asTransport?.trafficClass, "infrastructure");

  const summary = buildCompassSummary([asTransport!], config);
  assert.equal(summary.bytesDown, 0, "transport must not inflate the headline total");
  assert.equal(summary.backgroundBytes, 95_000_000);
});

test("encrypted DNS is chatter whether dialled by name or by address", () => {
  const byAddress = new EveFlowCorrelator().consume(
    {
      event_type: "flow",
      flow_id: 21,
      src_ip: "192.0.2.9",
      dest_ip: "1.1.1.1",
      dest_port: 443,
      app_proto: "tls",
      flow: { bytes_toserver: 900, bytes_toclient: 2_400 },
    },
    "wlp7s0",
    home,
  );
  assert.equal(byAddress?.trafficClass, "infrastructure");

  const byName = new EveFlowCorrelator().consume(
    {
      event_type: "flow",
      flow_id: 22,
      src_ip: "192.0.2.9",
      dest_ip: "104.16.249.249",
      dest_port: 443,
      app_proto: "tls",
      tls: { sni: "cloudflare-dns.com" },
      flow: { bytes_toserver: 900, bytes_toclient: 2_400 },
    },
    "wlp7s0",
    home,
  );
  assert.equal(byName?.trafficClass, "infrastructure");
});

test("incoming flow byte direction is reversed around the local endpoint", () => {
  const flow = new EveFlowCorrelator().consume(
    {
      event_type: "flow",
      flow_id: 7,
      src_ip: "203.0.113.20",
      src_port: 443,
      dest_ip: "192.0.2.9",
      dest_port: 51000,
      flow: { bytes_toserver: 400, bytes_toclient: 100, pkts_toserver: 4, pkts_toclient: 2 },
    },
    "wlp7s0",
    home,
  );
  assert.ok(flow);
  assert.equal(flow.direction, "inbound");
  assert.equal(flow.bytesUp, 100);
  assert.equal(flow.bytesDown, 400);
});

test("an expanded IPv6 flow matches the host's compressed local address", () => {
  const flow = new EveFlowCorrelator().consume(
    {
      event_type: "flow",
      flow_id: 8,
      src_ip: "2001:0db8:0000:0000:0000:0000:0002:0002",
      src_port: 51000,
      dest_ip: "2606:4700:3037:0000:0000:0000:6815:268f",
      dest_port: 443,
      flow: { bytes_toserver: 400, bytes_toclient: 900 },
    },
    "aisoc0",
    home,
    ["2001:db8::2:2"],
  );
  assert.ok(flow);
  assert.equal(flow.direction, "outbound");
  assert.equal(flow.bytesUp, 400);
  assert.equal(flow.bytesDown, 900);
});

test("a hostname with an illegal character is rejected, not silently repaired", () => {
  const flow = new EveFlowCorrelator().consume(
    {
      event_type: "flow",
      flow_id: 9,
      src_ip: "192.0.2.9",
      dest_ip: "203.0.113.9",
      dest_port: 443,
      app_proto: "tls",
      tls: { sni: "foo bar.com" },
      flow: { bytes_toserver: 10, bytes_toclient: 10 },
    },
    "aisoc0",
    home,
  );
  assert.ok(flow);
  assert.equal(flow.domain, null, "must not become the unrelated real domain foobar.com");
});

function flowAt(day: number, over: Partial<NetworkFlow> = {}): NetworkFlow {
  const at = `2026-08-0${day}T12:00:00.000Z`;
  return {
    id: `${day}:${over.domain ?? "github.com"}:${over.remotePort ?? 443}`,
    flowId: String(day),
    sensor: "aisoc0",
    startedAt: at,
    endedAt: at,
    updatedAt: at,
    localIp: "192.0.2.9",
    localPort: 50000 + day,
    remoteIp: "140.82.112.3",
    remotePort: 443,
    direction: "outbound",
    trafficClass: "web",
    proto: "TCP",
    appProto: "tls",
    hostname: "api.github.com",
    domain: "github.com",
    domainSource: "tls",
    domainConfidence: "asserted",
    country: "US",
    asn: "AS36459 GITHUB",
    organization: "GITHUB",
    bytesUp: 100,
    bytesDown: 500,
    packetsUp: 2,
    packetsDown: 4,
    state: "closed",
    category: categoryForDomain("github.com"),
    processName: null,
    ...over,
  };
}

test("connections fold into one row per site, biggest first", () => {
  const summary = buildCompassSummary(
    [
      flowAt(1),
      flowAt(2),
      flowAt(3, {
        domain: "googlevideo.com",
        hostname: "r1.googlevideo.com",
        bytesDown: 90_000_000,
      }),
    ],
    config,
  );
  assert.deepEqual(
    summary.destinations.map((entry) => entry.key),
    ["googlevideo.com", "github.com"],
  );
  assert.equal(summary.destinations[1]?.flows, 2);
  assert.equal(summary.destinations[1]?.bytesDown, 1_000);
  assert.equal(summary.retainedFlows, 3);
});

test("an unnamed address is labelled by its offline network owner", () => {
  const summary = buildCompassSummary(
    [flowAt(1, { domain: null, hostname: null, domainConfidence: "unknown" })],
    config,
  );
  assert.equal(summary.destinations[0]?.key, "ip:140.82.112.3");
  assert.equal(summary.destinations[0]?.label, "GITHUB");
});

test("process ownership folds per site without filling unknowns", () => {
  const summary = buildCompassSummary(
    [flowAt(1, { processName: "firefox" }), flowAt(2), flowAt(3, { processName: "firefox" })],
    config,
  );
  assert.equal(summary.attributedFlows, 2);
  assert.equal(summary.unattributedFlows, 1);
  assert.equal(summary.attributionCoverage, 2 / 3);
  assert.deepEqual(
    summary.destinations[0]?.processes.map((process) => [process.name, process.flows]),
    [
      ["firefox", 2],
      [null, 1],
    ],
  );
});

test("machine chatter is counted separately from sites a person chose", () => {
  const summary = buildCompassSummary(
    [flowAt(1), flowAt(2, { trafficClass: "infrastructure", domain: null, hostname: null })],
    config,
  );
  assert.equal(summary.backgroundFlows, 1);
  assert.equal(summary.categories[0]?.flows, 1, "chatter must not inflate a category");
});

test("a site is only called new once the daily history has a past to compare against", () => {
  const flows = [flowAt(1, { bytesDown: 50_000 }), flowAt(2), flowAt(3)];
  const past = {
    "github.com": { days: 1, firstDay: "2026-08-01" },
    "example.com": { days: 12, firstDay: "2026-07-20" },
  };

  const noHistory = buildCompassSummary(flows, config, {});
  assert.equal(
    noHistory.insights.some((insight) => insight.kind === "new-destination"),
    false,
    "everything looks new on day one",
  );

  const withHistory = buildCompassSummary(flows, config, past);
  const insight = withHistory.insights.find((entry) => entry.kind === "new-destination");
  assert.ok(insight);
  assert.match(insight.title, /github\.com/);

  const trivial = buildCompassSummary([flowAt(1)], config, past);
  assert.equal(
    trivial.insights.some((entry) => entry.kind === "new-destination"),
    false,
    "a few hundred bytes to a new host is background noise, not a finding",
  );
});

test("plain HTTP is surfaced and dismissals are honoured", () => {
  const flows = [flowAt(1, { appProto: "http", remotePort: 80, domain: "firefox.com" })];
  const summary = buildCompassSummary(flows, config);
  const unencrypted = summary.insights.find((entry) => entry.kind === "unencrypted");
  assert.ok(unencrypted);

  const dismissed = buildCompassSummary(
    flows,
    config,
    {},
    {
      [unencrypted.id]: { status: "dismissed", snoozedUntil: null },
    },
  );
  assert.equal(
    dismissed.insights.some((entry) => entry.kind === "unencrypted"),
    false,
  );
});

test("insights stay off when the operator turns them off", () => {
  const summary = buildCompassSummary([flowAt(1)], { ...config, insightsEnabled: false });
  assert.deepEqual(summary.insights, []);
});

test("CompassRepository durably bounds flows, history and feedback", () => {
  const repository = new CompassRepository(":memory:");
  const first = flowAt(1);
  const second = flowAt(2);
  repository.upsertFlow(first);
  repository.upsertFlow(second);
  repository.recordDay("github.com", "2026-08-01", 100, 500);
  repository.recordDay("github.com", "2026-08-02", 100, 500);
  repository.setFeedback("unencrypted:firefox.com", "dismissed", null);

  assert.equal(repository.loadFlows(168, 10, Date.parse(second.endedAt)).length, 2);
  assert.deepEqual(repository.loadHistory()["github.com"], { days: 2, firstDay: "2026-08-01" });
  assert.equal(repository.loadFeedback()["unencrypted:firefox.com"]?.status, "dismissed");

  repository.prune(168, 1, 3_650, Date.parse(second.endedAt));
  assert.deepEqual(
    repository.loadFlows(168, 10, Date.parse(second.endedAt)).map((flow) => flow.id),
    [second.id],
  );

  repository.clear();
  assert.equal(repository.loadFlows(168, 10, Date.parse(second.endedAt)).length, 0);
  assert.deepEqual(repository.loadHistory(), {});
  assert.deepEqual(repository.loadFeedback(), {});
});

test("a row written before hostname and class existed still loads", () => {
  const repository = new CompassRepository(":memory:");
  const legacy = { ...flowAt(1) } as Record<string, unknown>;
  legacy.hostname = undefined;
  legacy.trafficClass = undefined;
  legacy.domainConfidence = "confirmed";
  legacy.asn = undefined;
  legacy.organization = undefined;
  repository.upsertFlow(legacy as unknown as NetworkFlow);
  const [loaded] = repository.loadFlows(168, 10, Date.parse(flowAt(1).endedAt));
  assert.ok(loaded);
  assert.equal(loaded.hostname, "github.com", "falls back to the registrable domain");
  assert.equal(loaded.trafficClass, "other");
  assert.equal(loaded.domainConfidence, "unknown", "the retired label is not carried forward");
  assert.equal(loaded.asn, null);
  assert.equal(loaded.organization, null);
});
