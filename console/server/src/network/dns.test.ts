import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

process.env.AISOC_DATA_DIR = mkdtempSync(join(tmpdir(), "aisoc-dns-test-"));
process.env.AISOC_PIHOLE_URL = "http://resolver.test";
process.env.AISOC_PIHOLE_PASSWORD = "hunter2";

const { dnsSummary, setBlockingEnabled } = await import("./dns.js");

interface Call {
  path: string;
  method: string;
  body: unknown;
}

const calls: Call[] = [];
type Route = (call: Call) => { status?: number; body?: unknown };
let routes: Record<string, Route> = {};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
  const path = String(input).replace("http://resolver.test", "");
  const call: Call = {
    path,
    method: init?.method ?? "GET",
    body: init?.body ? JSON.parse(String(init.body)) : undefined,
  };
  calls.push(call);
  if (path === "/api/auth") return json({ session: { sid: "sid-1", validity: 300 } });
  const route = routes[path.replace(/\?.*$/, "")];
  if (!route) return json({}, 404);
  const { status = 200, body = {} } = route(call);
  return json(body, status);
}) as typeof fetch;

function reset(next: Record<string, Route>) {
  calls.length = 0;
  routes = next;
}

const blockingBody = (active: boolean) => ({ config: { dns: { blocking: { active } } } });

/** The four reads dnsSummary always makes, all empty. */
const statRoutes: Record<string, Route> = {
  "/api/stats/summary": () => ({ body: { queries: { total: 0, blocked: 0 }, clients: {} } }),
  "/api/queries": () => ({ body: { queries: [] } }),
  "/api/stats/top_domains": () => ({ body: { domains: [] } }),
  "/api/stats/top_clients": () => ({ body: { clients: [] } }),
};

test("a write goes out as a PATCH with the v6 nested config body", async () => {
  reset({ "/api/config": (call) => ({ body: call.body }) });

  await setBlockingEnabled(false);

  const write = calls.find((call) => call.path === "/api/config");
  assert.equal(write?.method, "PATCH");
  assert.deepEqual(write?.body, blockingBody(false));
});

test("a session that expires mid-write replays the PATCH, not a bare GET", async () => {
  let seen = 0;
  reset({
    "/api/config": (call) => {
      seen += 1;
      if (seen === 1) return { status: 401 };
      return { body: call.body };
    },
  });

  await setBlockingEnabled(true);

  const writes = calls.filter((call) => call.path === "/api/config");
  assert.equal(writes.length, 2);
  assert.deepEqual(
    writes.map((call) => call.method),
    ["PATCH", "PATCH"],
  );
  assert.deepEqual(writes.at(1)?.body, blockingBody(true));
});

test("a resolver that reports the old state fails the write", async () => {
  reset({ "/api/config": () => ({ body: blockingBody(true) }) });

  await assert.rejects(setBlockingEnabled(false), /did not apply/);
});

test("an unrecognised write response is confirmed by re-reading the switch", async () => {
  reset({
    "/api/config": () => ({ body: { took: 0.01 } }),
    "/api/config/dns/blocking/active": () => ({ body: blockingBody(false) }),
  });

  await setBlockingEnabled(false);

  assert.ok(calls.some((call) => call.path === "/api/config/dns/blocking/active"));
});

test("the summary carries the blocking switch", async () => {
  reset({
    ...statRoutes,
    "/api/config/dns/blocking/active": () => ({ body: blockingBody(false) }),
  });

  const summary = await dnsSummary();

  assert.equal(summary.available, true);
  assert.equal(summary.blockingEnabled, false);
});

test("a resolver without the blocking endpoint still renders the ledger", async () => {
  reset({ ...statRoutes, "/api/config/dns/blocking/active": () => ({ status: 404 }) });

  const summary = await dnsSummary();

  assert.equal(summary.available, true);
  assert.equal(summary.blockingEnabled, null);
});
