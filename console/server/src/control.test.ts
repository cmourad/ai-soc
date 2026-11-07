import assert from "node:assert/strict";
import { test } from "node:test";
import type { AuditEntry, Incident } from "@aisoc/shared";
import { executeControlCommand, matchesIncidentFilter } from "./control.js";
import { addAudit, getIncident, upsertIncident } from "./store.js";

function incident(overrides: Partial<Incident> = {}): Incident {
  return {
    id: "control-test-id",
    ref: "INC-9999",
    title: "Control test incident",
    status: "open",
    severity: 3,
    correlationKey: "sig:test",
    correlationBasis: "test signature",
    alertIds: [],
    assetIds: [],
    indicators: [],
    mitre: [],
    score: 42,
    assignee: null,
    narrative: null,
    narrativeModel: null,
    suggestedResponse: null,
    timeline: [],
    createdAt: "2026-08-01T00:00:00.000Z",
    updatedAt: "2026-08-01T00:00:00.000Z",
    closedAt: null,
    ...overrides,
  };
}

test("incident filters combine status, severity, age, and reference", () => {
  const candidate = incident();
  const now = Date.parse("2026-08-12T00:00:00.000Z");
  assert.equal(
    matchesIncidentFilter(
      candidate,
      { status: "active", severities: [3, 4], olderThanMs: 24 * 60 * 60_000, refs: ["INC-9999"] },
      now,
    ),
    true,
  );
  assert.equal(matchesIncidentFilter(candidate, { status: "closed" }, now), false);
  assert.equal(matchesIncidentFilter(candidate, { severities: [1, 2] }, now), false);
});

test("bulk close previews by default and mutates only with confirmation", async () => {
  upsertIncident(incident());
  const filter = { refs: ["INC-9999"] };

  const preview = await executeControlCommand({ command: "incidents.close", filter });
  assert.equal(preview.ok, true);
  assert.equal(preview.dryRun, true);
  assert.equal(preview.matched, 1);
  assert.equal(getIncident("control-test-id")?.status, "open");

  const forged = await executeControlCommand({
    command: "incidents.close",
    filter,
    confirm: "true",
  });
  assert.equal(forged.dryRun, true);
  assert.equal(getIncident("control-test-id")?.status, "open");

  const applied = await executeControlCommand({
    command: "incidents.close",
    filter,
    confirm: true,
  });
  assert.equal(applied.ok, true);
  assert.equal(applied.changed, 1);
  assert.equal(getIncident("control-test-id")?.status, "closed");
});

test("audit tail returns newest first and clamps the requested limit", async () => {
  addAudit("terminal:test", "audit.test", "one", "first");
  addAudit("terminal:test", "audit.test", "two", "second");

  const response = await executeControlCommand({ command: "audit.list", limit: 1 });
  assert.equal(response.ok, true);
  assert.deepEqual(
    (response.audit as AuditEntry[]).map((entry) => entry.target),
    ["two"],
  );

  const clamped = await executeControlCommand({ command: "audit.list", limit: 10_000 });
  assert.ok((clamped.audit as AuditEntry[]).length <= 500);
});

test("resolver apply previews unless confirm is exactly true", async () => {
  const preview = await executeControlCommand({ command: "dns.resolver", apply: true });
  assert.equal(preview.ok, true);
  assert.equal(preview.dryRun, true);

  const forged = await executeControlCommand({
    command: "dns.resolver",
    apply: true,
    confirm: "true",
  });
  assert.equal(forged.dryRun, true);
});

test("Pi-hole restart previews unless confirm is exactly true", async () => {
  const preview = await executeControlCommand({ command: "pihole.restart" });
  assert.equal(preview.ok, true);
  assert.equal(preview.dryRun, true);

  const forged = await executeControlCommand({ command: "pihole.restart", confirm: "true" });
  assert.equal(forged.ok, true);
  assert.equal(forged.dryRun, true);
});
