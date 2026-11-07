import assert from "node:assert/strict";
import { test } from "node:test";
import Fastify from "fastify";
import { hostAllowed, installTrustBoundary, isForgeableCrossOrigin, issueSession } from "./auth.js";
import { complementOf, parseCidr } from "./vpn/wireguard.js";

// ---------------------------------------------------------------------------
// CSRF gate. These are the cases that decide whether a page the operator
// happens to visit can approve an nftables block or pause the whole SOC.
// ---------------------------------------------------------------------------

test("cross-site fetch metadata is refused", () => {
  assert.equal(isForgeableCrossOrigin({ "sec-fetch-site": "cross-site" }, { remote: false }), true);
  assert.equal(isForgeableCrossOrigin({ "sec-fetch-site": "same-site" }, { remote: false }), true);
});

test("our own surfaces are allowed", () => {
  assert.equal(
    isForgeableCrossOrigin({ "sec-fetch-site": "same-origin" }, { remote: false }),
    false,
  );
  // typed URL / non-browser client
  assert.equal(isForgeableCrossOrigin({ "sec-fetch-site": "none" }, { remote: false }), false);
});

test("fetch metadata wins over a spoofable Origin", () => {
  // script cannot set sec-fetch-site, so trust it even when Origin disagrees
  assert.equal(
    isForgeableCrossOrigin(
      { "sec-fetch-site": "same-origin", origin: "http://evil.example" },
      { remote: false },
    ),
    false,
  );
});

test("without fetch metadata, the Origin allowlist decides", () => {
  assert.equal(isForgeableCrossOrigin({ origin: "http://evil.example" }, { remote: false }), true);
  assert.equal(
    isForgeableCrossOrigin({ origin: "http://127.0.0.1:4319" }, { remote: false }),
    false,
  );
  assert.equal(
    isForgeableCrossOrigin({ origin: "http://127.0.0.1:5319" }, { remote: false }),
    false,
  );
});

test("a client sending no browser headers at all is the local operator", () => {
  assert.equal(isForgeableCrossOrigin({}, { remote: false }), false);
});

test("remote listener requires the page origin to match the served host", () => {
  const headers = { origin: "https://box.mesh.internal:8443", host: "box.mesh.internal:8443" };
  assert.equal(isForgeableCrossOrigin(headers, { remote: true }), false);
  assert.equal(
    isForgeableCrossOrigin({ ...headers, origin: "https://evil.example" }, { remote: true }),
    true,
  );
  // a mesh-authenticated browser with no Host to compare against
  assert.equal(
    isForgeableCrossOrigin({ origin: "https://box.mesh.internal:8443" }, { remote: true }),
    true,
  );
});

test("Host validation is exact and rejects rebinding syntax", () => {
  const allowed = new Set(["127.0.0.1:4319", "box.mesh.internal:8443"]);
  assert.equal(hostAllowed("127.0.0.1:4319", allowed), true);
  assert.equal(hostAllowed("BOX.MESH.INTERNAL:8443", allowed), true);
  assert.equal(hostAllowed("evil.example", allowed), false);
  assert.equal(hostAllowed("127.0.0.1:4319, evil.example", allowed), false);
  assert.equal(hostAllowed("user@127.0.0.1:4319", allowed), false);
  assert.equal(hostAllowed(undefined, allowed), false);
});

test("mutations require both an authenticated cookie and its CSRF token", async () => {
  const app = Fastify();
  const hosts = new Set(["127.0.0.1:4319"]);
  installTrustBoundary(app, { allowedHosts: () => hosts });
  app.get("/api/session", async (request, reply) => issueSession(request, reply, false));
  app.post("/api/change", async () => ({ ok: true }));

  const headers = { host: "127.0.0.1:4319", "sec-fetch-site": "same-origin" };
  const missing = await app.inject({ method: "POST", url: "/api/change", headers });
  assert.equal(missing.statusCode, 401);

  const bootstrap = await app.inject({ method: "GET", url: "/api/session", headers });
  assert.equal(bootstrap.statusCode, 200);
  const setCookie = bootstrap.headers["set-cookie"];
  const cookie = (Array.isArray(setCookie) ? setCookie[0] : setCookie)?.split(";")[0];
  const { csrf } = bootstrap.json<{ csrf: string }>();
  assert.ok(cookie);

  const noCsrf = await app.inject({
    method: "POST",
    url: "/api/change",
    headers: { ...headers, cookie },
  });
  assert.equal(noCsrf.statusCode, 403);

  const accepted = await app.inject({
    method: "POST",
    url: "/api/change",
    headers: { ...headers, cookie, "x-csrf-token": csrf },
  });
  assert.equal(accepted.statusCode, 200);
  assert.equal(accepted.headers["x-content-type-options"], "nosniff");
  assert.equal(accepted.headers["cache-control"], "no-store");
  await app.close();
});

test("terminal websocket path requires an authenticated session", async () => {
  const app = Fastify();
  const hosts = new Set(["127.0.0.1:4319"]);
  installTrustBoundary(app, { allowedHosts: () => hosts });
  app.get("/api/session", async (request, reply) => issueSession(request, reply, false));
  app.get("/ws/terminal", async () => ({ ok: true }));

  const headers = { host: "127.0.0.1:4319", origin: "http://127.0.0.1:5319" };
  const missing = await app.inject({ method: "GET", url: "/ws/terminal", headers });
  assert.equal(missing.statusCode, 401);

  const bootstrap = await app.inject({ method: "GET", url: "/api/session", headers });
  const setCookie = bootstrap.headers["set-cookie"];
  const cookie = (Array.isArray(setCookie) ? setCookie[0] : setCookie)?.split(";")[0];
  assert.ok(cookie);

  const accepted = await app.inject({
    method: "GET",
    url: "/ws/terminal",
    headers: { ...headers, cookie },
  });
  assert.equal(accepted.statusCode, 200);
  await app.close();
});

// ---------------------------------------------------------------------------
// Split-tunnel CIDR arithmetic. A wrong complement here silently routes traffic
// outside the tunnel, and the code carries a comment about a signed-32-bit bug
// that was already hit once.
// ---------------------------------------------------------------------------

const ip = (a: number, b: number, c: number, d: number) => a * 2 ** 24 + b * 2 ** 16 + c * 256 + d;

test("parseCidr snaps to the network address", () => {
  assert.deepEqual(parseCidr("10.2.0.7/24"), { start: ip(10, 2, 0, 0), end: ip(10, 2, 0, 255) });
  assert.deepEqual(parseCidr("0.0.0.0/0"), { start: 0, end: 4_294_967_295 });
  assert.equal(parseCidr("999.1.1.1/24"), null);
  assert.equal(parseCidr("10.0.0.0/33"), null);
});

test("complement of nothing is everything", () => {
  assert.deepEqual(complementOf([]), ["0.0.0.0/0"]);
});

test("complement covers the whole space exactly once", () => {
  for (const excluded of [["192.0.2.0/24"], ["10.0.0.0/8", "172.16.0.0/12"], ["0.0.0.0/1"]]) {
    const ranges = complementOf(excluded)
      .map(parseCidr)
      .map((range) => {
        assert.ok(range, "every emitted prefix must reparse");
        return range;
      })
      .sort((a, b) => a.start - b.start);

    const holes = excluded
      .map(parseCidr)
      .filter((r) => r !== null)
      .sort((a, b) => a.start - b.start);
    let cursor = 0;
    for (const range of ranges) {
      // no overlap, and every gap must be fully covered by an exclusion —
      // checked as ranges, not per address, or this walks 2^32 iterations
      assert.ok(range.start >= cursor, `overlap at ${range.start} in ${excluded}`);
      let gap = cursor;
      while (gap < range.start) {
        const hole = holes.find((h) => h.start <= gap && gap <= h.end);
        assert.ok(hole, `address ${gap} is in neither the complement nor an exclusion`);
        gap = hole.end + 1;
      }
      cursor = range.end + 1;
    }
    assert.equal(cursor, 4_294_967_296, `complement of ${excluded} does not reach the top`);
  }
});

test("addresses above 128.0.0.0 terminate (signed 32-bit regression)", () => {
  // value & -value would go negative here and spin forever
  const out = complementOf(["10.0.0.0/8"]);
  assert.ok(
    out.some((cidr) => cidr.startsWith("128.")),
    "high half must be covered",
  );
  assert.ok(out.length < 100, "should stay a compact prefix list");
});
