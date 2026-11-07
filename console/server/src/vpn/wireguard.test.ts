import assert from "node:assert/strict";
import test from "node:test";
import { allowedIpsFor, complementOf, NEVER_TUNNELED, parseCidr } from "./wireguard.js";

/** Does the emitted AllowedIPs list route `ip` into the tunnel? */
function covers(allowedIps: string[], ip: string): boolean {
  const target = parseCidr(`${ip}/32`);
  assert.ok(target);
  return allowedIps.some((cidr) => {
    const range = parseCidr(cidr);
    return range !== null && range.start <= target.start && range.end >= target.start;
  });
}

// INC: a full-tunnel profile took the route to every ClusterIP with it. The
// Tetragon sensor then crash-looped for an hour on "10.43.0.1:443: i/o timeout"
// while the NAT path was intact — the packets were leaving through aisoc0.
test("a full tunnel never carries the cluster networks", () => {
  const allowed = allowedIpsFor({ mode: "off", networks: [] });
  assert.ok(!covers(allowed, "10.43.0.1"), "the API server must stay on the host");
  assert.ok(!covers(allowed, "10.42.0.33"), "pod addresses must stay on the host");
  // Everything else still goes through, which is what a full tunnel is for.
  assert.ok(covers(allowed, "1.1.1.1"));
  assert.ok(covers(allowed, "10.41.255.255"));
  assert.ok(covers(allowed, "10.44.0.1"));
});

test("exclusions the operator asked for are honoured alongside the mandatory ones", () => {
  const allowed = allowedIpsFor({ mode: "exclude", networks: ["192.0.2.0/24"] });
  assert.ok(!covers(allowed, "192.0.2.50"));
  assert.ok(!covers(allowed, "10.43.0.1"));
  assert.ok(covers(allowed, "8.8.8.8"));
});

test("an include list is trimmed rather than refused when it overlaps the cluster", () => {
  const allowed = allowedIpsFor({ mode: "include", networks: ["10.0.0.0/8"] });
  assert.ok(!covers(allowed, "10.43.0.1"));
  assert.ok(!covers(allowed, "10.42.0.1"));
  // The rest of the requested range still routes through the tunnel.
  assert.ok(covers(allowed, "10.1.2.3"));
  assert.ok(covers(allowed, "10.255.255.255"));
});

test("the complement of the mandatory set stays small enough to install as routes", () => {
  assert.ok(complementOf(NEVER_TUNNELED).length < 40);
});
