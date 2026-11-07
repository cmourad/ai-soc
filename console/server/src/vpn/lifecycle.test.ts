import assert from "node:assert/strict";
import test from "node:test";
import { VpnOperationGate } from "./lifecycle.js";

test("VPN operations cannot overlap", async () => {
  const gate = new VpnOperationGate();
  const calls: string[] = [];
  let releaseFirst!: () => void;
  const firstCanFinish = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });

  const first = gate.run(async () => {
    calls.push("first:start");
    await firstCanFinish;
    calls.push("first:end");
  });
  const second = gate.run(async () => {
    calls.push("second:start");
  });

  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(gate.busy, true);
  assert.deepEqual(calls, ["first:start"]);
  releaseFirst();
  await Promise.all([first, second]);
  assert.deepEqual(calls, ["first:start", "first:end", "second:start"]);
  assert.equal(gate.busy, false);
});
