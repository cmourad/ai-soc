import assert from "node:assert/strict";
import test from "node:test";
import type { CompassSummary } from "@aisoc/shared";
import { buildReviewContext, reconcileFindings } from "./review.js";

function summaryWith(overrides: Partial<CompassSummary> = {}): CompassSummary {
  return {
    enabled: true,
    paused: false,
    insightsEnabled: true,
    windowHours: 24,
    retainedFlows: 3,
    earliestFlowAt: "2026-08-08T00:00:00.000Z",
    bytesUp: 2_048,
    bytesDown: 10_240,
    directionCounts: { outbound: 3, inbound: 0, internal: 0, unknown: 0 },
    destinations: [
      {
        key: "github.com",
        label: "github.com",
        hostnames: ["api.github.com", "gist.github.com"],
        category: "software-development",
        categoryLabel: "Software development",
        country: "US",
        asn: "AS36459 GITHUB",
        organization: "GITHUB",
        trafficClass: "web",
        confidence: "asserted",
        flows: 12,
        plaintextFlows: 0,
        bytesUp: 1_024,
        bytesDown: 8_192,
        firstSeen: "2026-08-08T09:00:00.000Z",
        lastSeen: "2026-08-08T11:00:00.000Z",
        knownDays: 9,
        firstSeenDay: "2026-07-30",
        processes: [{ name: "firefox-bin", flows: 12, bytesUp: 1_024, bytesDown: 8_192 }],
      },
      {
        key: "cloudflare-dns.com",
        label: "cloudflare-dns.com",
        hostnames: [],
        category: null,
        categoryLabel: null,
        country: "US",
        asn: "AS13335 CLOUDFLARENET",
        organization: "CLOUDFLARENET",
        trafficClass: "infrastructure",
        confidence: "asserted",
        flows: 800,
        plaintextFlows: 0,
        bytesUp: 512,
        bytesDown: 1_024,
        firstSeen: "2026-08-08T09:00:00.000Z",
        lastSeen: "2026-08-08T11:00:00.000Z",
        knownDays: 9,
        firstSeenDay: "2026-07-30",
        processes: [{ name: null, flows: 800, bytesUp: 512, bytesDown: 1_024 }],
      },
      {
        key: "ip:203.0.113.9",
        label: "203.0.113.9",
        hostnames: [],
        category: null,
        categoryLabel: null,
        country: "NL",
        asn: "AS64496 PRIVATE EXAMPLE",
        organization: "PRIVATE EXAMPLE",
        trafficClass: "web",
        confidence: "unknown",
        flows: 2,
        plaintextFlows: 0,
        bytesUp: 512,
        bytesDown: 1_024,
        firstSeen: "2026-08-08T09:00:00.000Z",
        lastSeen: "2026-08-08T11:00:00.000Z",
        knownDays: 1,
        firstSeenDay: "2026-08-08",
        processes: [{ name: null, flows: 2, bytesUp: 512, bytesDown: 1_024 }],
      },
    ],
    categories: [],
    insights: [],
    namedFlows: 12,
    unnamedFlows: 2,
    backgroundFlows: 800,
    backgroundBytes: 1_536,
    attributedFlows: 12,
    unattributedFlows: 802,
    attributionCoverage: 12 / 814,
    ...overrides,
  };
}

test("the model is sent aggregates only, never anything page-identifying", () => {
  const { context } = buildReviewContext(summaryWith());
  const serialized = JSON.stringify(context);

  for (const leak of [
    "api.github.com",
    "gist.github.com",
    "firstSeen",
    "lastSeen",
    "2026-08-08T09:00:00",
    "443",
    "192.168",
    "firefox-bin",
    "AS36459",
    "GITHUB",
  ]) {
    assert.equal(serialized.includes(leak), false, `${leak} must not reach the model`);
  }
  assert.match(serialized, /github\.com/, "the registrable domain is the point of the exercise");
});

test("chatter and bare addresses are not offered for review", () => {
  const { sites } = buildReviewContext(summaryWith());
  assert.deepEqual(sites, ["github.com"]);
});

test("a site the model invented is dropped and reported, never shown as a finding", () => {
  const { findings, invented } = reconcileFindings(
    [
      { site: "github.com", assessment: "expected", reason: "ordinary developer traffic" },
      { site: "evil-exfil.example", assessment: "unexpected", reason: "made up entirely" },
    ],
    ["github.com"],
  );
  assert.deepEqual(
    findings.map((finding) => finding.site),
    ["github.com"],
  );
  assert.deepEqual(invented, ["evil-exfil.example"]);
});

test("duplicate findings for one site collapse and the list stays bounded", () => {
  const sites = Array.from({ length: 20 }, (_, index) => `site${index}.com`);
  const raw = [
    ...sites.map((site) => ({ site, assessment: "expected" as const, reason: "fine" })),
    { site: "site0.com", assessment: "unexpected" as const, reason: "contradicts itself" },
  ];
  const { findings } = reconcileFindings(raw, sites);
  assert.equal(findings.length, 6);
  assert.equal(findings.filter((finding) => finding.site === "site0.com").length, 1);
  assert.equal(findings[0]?.assessment, "expected", "the first answer for a site wins");
});
