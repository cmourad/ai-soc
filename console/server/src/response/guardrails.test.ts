import assert from "node:assert/strict";
import test from "node:test";
import { setLocalNetworks } from "@aisoc/shared";
import { updateSettings } from "../settings.js";
import { guardrailViolation } from "./actions.js";

/**
 * INC-0126 proposed firewalling the site's own tunnel address. These cover the
 * rails that are supposed to make that impossible.
 */

test("an address inside a declared home network is never a block target", () => {
  updateSettings({ site: { homeNetworks: ["192.0.2.0/24", "10.0.0.0/8"] } });

  // The home-network rail compared string prefixes: "10.0.0.0/8" became
  // "10.0.0", which no address in the rest of the range starts with.
  assert.equal(
    guardrailViolation("block_ip", "10.99.1.4", null),
    "target is one of our own addresses",
  );
});

// block_ip only accepts IPv4 shapes today, which is the only reason INC-0126's
// suggested response could not have executed. Pinned so that adding v6 response
// support has to confront the address rails rather than inherit this accident.
test("block_ip does not accept an IPv6 target at all", () => {
  assert.equal(
    guardrailViolation("block_ip", "2001:0db8:0000:0000:0000:0000:0002:0002", null),
    'target "2001:0db8:0000:0000:0000:0000:0002:0002" is not a valid block ip target',
  );
});

test("a declared tunnel prefix makes its addresses ours", () => {
  setLocalNetworks(["2001:db8::/48"], []);

  assert.equal(
    guardrailViolation("block_domain", "2001:0db8:0000:0000:0000:0000:0002:0002", null),
    'target "2001:0db8:0000:0000:0000:0000:0002:0002" is not a valid block domain target',
  );

  setLocalNetworks([], []);
});

test("an external address is a legitimate block target", () => {
  updateSettings({ site: { homeNetworks: ["192.0.2.0/24", "10.0.0.0/8"] } });

  assert.equal(guardrailViolation("block_ip", "45.155.205.233", null), null);
});
