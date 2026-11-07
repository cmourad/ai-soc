import assert from "node:assert/strict";
import test from "node:test";
import { automaticResponseOriginHold } from "./policy.js";

test("Compass-derived alerts can never enter automatic response", () => {
  assert.match(automaticResponseOriginHold({ origin: "compass_beacon" }) ?? "", /human/i);
  assert.equal(automaticResponseOriginHold({ origin: "event" }), null);
  assert.equal(automaticResponseOriginHold(null), null);
});
