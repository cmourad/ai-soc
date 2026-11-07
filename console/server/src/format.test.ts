import assert from "node:assert/strict";
import test from "node:test";
import { formatBytes, windowLabel } from "@aisoc/shared";

// Lives here rather than in `shared` because that package is deliberately
// toolchain-free. These two are the reason the module exists: the server writes them into
// insight prose and the UI prints them beside the same totals, so a divergence
// shows up as one figure rendered two ways on one screen.

test("bytes are SI throughout, never binary", () => {
  assert.equal(formatBytes(999), "999 B");
  assert.equal(formatBytes(1_000), "1.0 kB");
  assert.equal(formatBytes(1_024), "1.0 kB");
  assert.equal(formatBytes(1_500_000), "1.5 MB");
  assert.equal(formatBytes(2_400_000_000), "2.4 GB");
});

test("window prose collapses to days only past two", () => {
  assert.equal(windowLabel(1), "the last hour");
  assert.equal(windowLabel(0), "the last hour");
  assert.equal(windowLabel(24), "the last 24 hours");
  assert.equal(windowLabel(47), "the last 47 hours");
  assert.equal(windowLabel(48), "the last 2 days");
  assert.equal(windowLabel(168), "the last 7 days");
});
