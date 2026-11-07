import assert from "node:assert/strict";
import test from "node:test";
import { llmStage, useTemporaryDataDir } from "../testing/settings-fixture.js";

useTemporaryDataDir("aisoc-analyst-models-test-", {
  firstTriage: llmStage("test-model"),
  secondTriage: llmStage("test-model-2"),
});

const { resolveAnalystModel } = await import("./models.js");
const { foldChatTranscript } = await import("../triage/llm.js");

test("stage ids resolve to their configured endpoint and model", () => {
  const first = resolveAnalystModel("firstTriage");
  assert.equal(first?.model, "test-model");
  assert.equal(first?.config.endpoint, "http://127.0.0.1:9/v1/chat/completions");
  const second = resolveAnalystModel("secondTriage");
  assert.equal(second?.model, "test-model-2");
});

test("anything else is a model name riding the first-tier endpoint", () => {
  const custom = resolveAnalystModel("org/Some-Model:Q4_K_XL");
  assert.equal(custom?.model, "org/Some-Model:Q4_K_XL");
  assert.equal(custom?.config.model, "org/Some-Model:Q4_K_XL");
  assert.equal(custom?.config.endpoint, "http://127.0.0.1:9/v1/chat/completions");
});

test("live picker ids resolve to the model advertised by the endpoint", () => {
  const live = resolveAnalystModel("live:org/Loaded-Model:Q8");
  assert.equal(live?.model, "org/Loaded-Model:Q8");
  assert.equal(live?.config.model, "org/Loaded-Model:Q8");
});

test("names that are not model names are rejected", () => {
  assert.equal(resolveAnalystModel("hello world"), null);
  assert.equal(resolveAnalystModel("$(rm -rf /)"), null);
  assert.equal(resolveAnalystModel("a; drop table"), null);
  assert.equal(resolveAnalystModel(""), null);
  assert.equal(resolveAnalystModel("x".repeat(201)), null);
});

test("the transcript folds into one message, in order, with the reply contract", () => {
  const folded = foldChatTranscript("SYSTEM", [
    { role: "user", content: "why github?" },
    { role: "assistant", content: "It is normal." },
    { role: "user", content: "and the upload?" },
  ]);
  assert.ok(folded.startsWith("SYSTEM"));
  assert.ok(folded.indexOf("Operator: why github?") < folded.indexOf("Analyst: It is normal."));
  assert.ok(folded.indexOf("Analyst: It is normal.") < folded.indexOf("Operator: and the upload?"));
  assert.ok(folded.includes('{"reply":'));
});
