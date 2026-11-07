import assert from "node:assert/strict";
import test from "node:test";
import type { Alert, LlmCall, SecurityEvent, Snapshot, Stats } from "@aisoc/shared";
import { applyServerMessage, type StreamState, upsert } from "./apply.js";

function state(patch: Partial<StreamState> = {}): StreamState {
  return {
    events: [],
    networkFlows: [],
    compass: null,
    compassReview: null,
    alerts: [],
    llmCalls: [],
    detections: [],
    pages: [],
    incidents: [],
    actions: [],
    assets: [],
    quarantine: [],
    lists: [],
    audit: [],
    notifications: [],
    rulePacks: [],
    playbooks: [],
    vpn: null,
    vpnServers: [],
    vpnProfiles: [],
    remoteAccess: null,
    stats: null,
    settings: {} as StreamState["settings"],
    secrets: {},
    paused: false,
    selectedCallId: null,
    ...patch,
  };
}

function event(id: string): SecurityEvent {
  return { id } as SecurityEvent;
}

function llmCall(id: string, stage: string): LlmCall {
  return { id, stage } as LlmCall;
}

test("a frozen view holds its event reading and keeps everything else live", () => {
  const frozen = state({ paused: true, events: [event("a")] });
  assert.deepEqual(applyServerMessage(frozen, { type: "event", event: event("b") }), {});

  const stats = { totalEvents: 7 } as Stats;
  assert.deepEqual(applyServerMessage(frozen, { type: "stats", stats }), { stats });
});

test("events are capped at the client retention window, oldest first", () => {
  let current = state();
  for (let index = 0; index < 850; index += 1) {
    current = {
      ...current,
      ...applyServerMessage(current, { type: "event", event: event(`e${index}`) }),
    };
  }
  assert.equal(current.events.length, 800);
  assert.equal(current.events[0]?.id, "e50");
  assert.equal(current.events.at(-1)?.id, "e849");
});

test("a re-sent record replaces its predecessor instead of duplicating", () => {
  const first = { id: "alert-1", stage: "pending" } as Alert;
  const settled = { id: "alert-1", stage: "resolved" } as Alert;
  const after = applyServerMessage(state({ alerts: [first] }), { type: "alert", alert: settled });
  assert.equal(after.alerts?.length, 1);
  assert.equal(after.alerts?.[0]?.stage, "resolved");
});

test("upsert keeps array identity stable for an unchanged list", () => {
  const list = [{ id: "a" }];
  assert.notEqual(upsert(list, { id: "b" }), list);
  assert.equal(upsert(list, { id: "a" })[0]?.id, "a");
});

test("clearing Compass model records also drops a selection pointing into them", () => {
  const current = state({
    llmCalls: [llmCall("call-1", "compass_review"), llmCall("call-2", "first_triage")],
    selectedCallId: "call-1",
  });
  const after = applyServerMessage(current, {
    type: "llm-clear",
    stages: ["compass_review", "compass_chat"],
  });
  assert.deepEqual(
    after.llmCalls?.map((call) => call.id),
    ["call-2"],
  );
  assert.equal(after.selectedCallId, null);
});

test("clearing Compass model records leaves an unrelated selection alone", () => {
  const current = state({
    llmCalls: [llmCall("call-1", "compass_review"), llmCall("call-2", "first_triage")],
    selectedCallId: "call-2",
  });
  const after = applyServerMessage(current, {
    type: "llm-clear",
    stages: ["compass_review", "compass_chat"],
  });
  assert.equal(after.selectedCallId, "call-2");
});

test("marking notifications read only touches the ids named", () => {
  const current = state({
    notifications: [
      { id: "n1", read: false },
      { id: "n2", read: false },
    ] as StreamState["notifications"],
  });
  const after = applyServerMessage(current, { type: "notifications-read", ids: ["n1"] });
  assert.deepEqual(
    after.notifications?.map((entry) => entry.read),
    [true, false],
  );
});

test("a snapshot fills the server-owned fields and leaves local view state alone", () => {
  const {
    paused: _paused,
    selectedCallId: _selected,
    ...local
  } = state({ alerts: [{ id: "alert-1" } as Alert] });
  // The wire type has no nulls: the server always sends all four.
  const remote: Snapshot = {
    ...local,
    compass: {} as Snapshot["compass"],
    vpn: {} as Snapshot["vpn"],
    remoteAccess: {} as Snapshot["remoteAccess"],
    stats: {} as Snapshot["stats"],
  };
  const current = state({ paused: true, selectedCallId: "call-9" });
  const after = applyServerMessage(current, { type: "snapshot", ...remote });

  assert.equal("type" in after, false, "the discriminant must not land in state");
  assert.equal("paused" in after, false, "a snapshot never overwrites the frozen view");
  assert.equal("selectedCallId" in after, false);
  assert.equal(after.alerts?.[0]?.id, "alert-1");
});
