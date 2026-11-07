import assert from "node:assert/strict";
import { test } from "node:test";
import { parseTerminalFrame } from "./terminal.js";

test("terminal input is carried in an explicit frame", () => {
  assert.deepEqual(parseTerminalFrame(JSON.stringify({ type: "input", data: "echo hello\r" })), {
    type: "input",
    data: "echo hello\r",
  });
  assert.deepEqual(
    parseTerminalFrame(
      JSON.stringify({ type: "input", data: '{"type":"resize","cols":90,"rows":30}' }),
    ),
    { type: "input", data: '{"type":"resize","cols":90,"rows":30}' },
  );
});

test("terminal resize frames require bounded integer dimensions", () => {
  assert.deepEqual(parseTerminalFrame(JSON.stringify({ type: "resize", cols: 90, rows: 30 })), {
    type: "resize",
    cols: 90,
    rows: 30,
  });
  assert.equal(parseTerminalFrame(JSON.stringify({ type: "resize", cols: "90", rows: 30 })), null);
  assert.equal(
    parseTerminalFrame(JSON.stringify({ type: "resize", cols: 10_000, rows: 30 })),
    null,
  );
  assert.equal(parseTerminalFrame(JSON.stringify({ type: "resize", cols: 90, rows: 1.5 })), null);
  assert.equal(parseTerminalFrame("not json"), null);
});
