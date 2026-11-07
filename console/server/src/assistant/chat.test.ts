import assert from "node:assert/strict";
import test from "node:test";
import type { Incident } from "@aisoc/shared";
import { llmStage, useTemporaryDataDir } from "../testing/settings-fixture.js";

useTemporaryDataDir("aisoc-assistant-chat-test-", {
  firstTriage: llmStage("test-model-1"),
  secondTriage: llmStage("test-model-2"),
});

const { listAssistanceChats, sendAssistanceMessage } = await import("./chat.js");
const { listLlmCalls, upsertIncident } = await import("../store.js");

function incident(id = "11111111-1111-4111-8111-111111111111"): Incident {
  return {
    id,
    ref: "INC-0001",
    title: "Suspicious outbound connection",
    status: "investigating",
    severity: 2,
    correlationKey: "remote:203.0.113.4",
    correlationBasis: "shared remote address",
    alertIds: [],
    assetIds: [],
    indicators: ["203.0.113.4"],
    mitre: [],
    score: 72,
    assignee: null,
    narrative: "A workstation contacted an unusual remote address.",
    narrativeModel: "test-model-2",
    suggestedResponse: "Inspect the initiating process.",
    timeline: [
      {
        id: "timeline-1",
        at: "2026-08-17T12:00:00.000Z",
        kind: "alert",
        title: "Outbound alert",
        detail: "Connection observed to 203.0.113.4.",
        refId: null,
      },
    ],
    createdAt: "2026-08-17T12:00:00.000Z",
    updatedAt: "2026-08-17T12:00:00.000Z",
    closedAt: null,
  };
}

test("an assistance conversation is subject-scoped and freezes its initial evidence", async () => {
  const subject = incident();
  upsertIncident(subject);
  const first = await sendAssistanceMessage({
    chatId: null,
    subjectKind: "incident",
    subjectId: subject.id,
    question: "Why is this suspicious?",
    model: "secondTriage",
  });
  assert.equal(first.subjectKind, "incident");
  assert.equal(first.subjectId, subject.id);
  assert.equal(first.messages.length, 2);
  assert.equal(listAssistanceChats("incident", subject.id).length, 1);

  const firstCall = listLlmCalls().find((call) => call.stage === "assistant_chat");
  assert.ok(firstCall?.systemPrompt.includes("Suspicious outbound connection"));
  subject.title = "CHANGED AFTER CHAT STARTED";
  upsertIncident(subject);

  await sendAssistanceMessage({
    chatId: first.id,
    subjectKind: "incident",
    subjectId: subject.id,
    question: "What should I check next?",
    model: "secondTriage",
  });
  const calls = listLlmCalls().filter((call) => call.stage === "assistant_chat");
  assert.equal(calls.length, 2);
  assert.equal(calls[0]?.systemPrompt, calls[1]?.systemPrompt);
  assert.ok(!calls[1]?.systemPrompt.includes("CHANGED AFTER CHAT STARTED"));
});

test("a conversation cannot be continued under another subject", async () => {
  const subject = incident("33333333-3333-4333-8333-333333333333");
  upsertIncident(subject);
  const existing = await sendAssistanceMessage({
    chatId: null,
    subjectKind: "incident",
    subjectId: subject.id,
    question: "Explain this incident",
    model: "secondTriage",
  });
  await assert.rejects(
    sendAssistanceMessage({
      chatId: existing.id,
      subjectKind: "incident",
      subjectId: "22222222-2222-4222-8222-222222222222",
      question: "Cross the streams",
      model: "secondTriage",
    }),
    /another subject/,
  );
});

test("a compass conversation is refused while Compass is not recording", async () => {
  await assert.rejects(
    sendAssistanceMessage({
      chatId: null,
      subjectKind: "compass",
      subjectId: "current",
      question: "Anything odd in my traffic?",
      model: "secondTriage",
    }),
    /not recording/,
  );
});
