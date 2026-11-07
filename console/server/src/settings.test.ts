import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { getSettings, reloadSettings } from "./settings.js";

let originalDemoEnv: string | undefined;

beforeEach(() => {
  originalDemoEnv = process.env.AISOC_DEMO;
});

afterEach(() => {
  if (originalDemoEnv === undefined) {
    delete process.env.AISOC_DEMO;
  } else {
    process.env.AISOC_DEMO = originalDemoEnv;
  }
  reloadSettings();
});

test("AISOC_DEMO=1 forces seed source and unpaused ingest", () => {
  process.env.AISOC_DEMO = "1";
  const settings = reloadSettings();
  assert.equal(settings.ingest.source, "seed");
  assert.equal(settings.ingest.paused, false);
  assert.equal(getSettings().ingest.source, "seed");
  assert.equal(getSettings().ingest.paused, false);
});

test("AISOC_DEMO=true forces seed source and unpaused ingest", () => {
  process.env.AISOC_DEMO = "true";
  const settings = reloadSettings();
  assert.equal(settings.ingest.source, "seed");
  assert.equal(settings.ingest.paused, false);
});
