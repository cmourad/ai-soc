import assert from "node:assert/strict";
import test from "node:test";
import { runDetection } from "../detect/engine.js";
import { clusterRecordToEvent, subjectIdentity } from "./cluster.js";

function tetragonExec(process: Record<string, unknown>, ts = "2026-08-25T13:00:00.000Z") {
  return {
    _stream: "tetragon",
    ts,
    record: {
      kind: "process_exec",
      process: { pid: 100, uid: 1000, auid: 1000, cwd: "/opt/aisoc", pod: {}, ...process },
      parent: { binary: "/usr/bin/bash", pid: 99 },
      node: "soc-host",
    },
  };
}

function auditLine(record: Record<string, unknown>) {
  return {
    _stream: "k3s-audit",
    ts: "2026-08-25T13:00:00.000Z",
    record: {
      auditId: "a1",
      verb: "get",
      user: "system:serviceaccount:prod:builder",
      resource: "secrets",
      namespace: "prod",
      objectName: "db",
      sourceIPs: ["10.42.0.9"],
      decision: "allow",
      code: 200,
      ...record,
    },
  };
}

test("a container exec keeps its workload identity and stays informational", () => {
  const event = clusterRecordToEvent(
    tetragonExec({
      binary: "/usr/bin/curl",
      arguments: "-s https://example.test/x.sh",
      auid: 4294967295,
      pod: { namespace: "prod", name: "web-1", workload: "web", container: "app" },
    }),
  );
  assert.ok(event);
  assert.equal(event.source, "tetragon");
  assert.equal(event.processName, "curl");
  assert.equal(event.assetId, "pod:prod/web-1");
  assert.equal(event.k8s?.workload, "web");
  // Hundreds of these arrive per second: admission is the detection engine's
  // job, not the sensor's.
  assert.equal(event.severity, 4);
});

test("a host exec from a login session outranks a container exec", () => {
  const event = clusterRecordToEvent(tetragonExec({ binary: "/usr/bin/sudo", auid: 1000 }));
  assert.equal(event?.severity, 3);
  assert.equal(event?.assetId, "host");
});

test("audit events carry the subject's own namespace, not just the object's", () => {
  const event = clusterRecordToEvent(auditLine({}));
  assert.equal(event?.k8s?.subjectKind, "serviceaccount");
  assert.equal(event?.k8s?.subjectNamespace, "prod");
  assert.equal(event?.k8s?.namespace, "prod");
  assert.equal(event?.srcIp, "10.42.0.9");
});

test("subject parsing separates service accounts, nodes, users and anonymous", () => {
  assert.equal(subjectIdentity("system:serviceaccount:kube-system:x").kind, "serviceaccount");
  assert.equal(subjectIdentity("system:node:soc-host").kind, "node");
  assert.equal(subjectIdentity("system:anonymous").kind, "anonymous");
  assert.equal(subjectIdentity(undefined).kind, "anonymous");
  assert.equal(subjectIdentity("aisoc").kind, "user");
});

// The collector drops request and response bodies, but the console must not
// depend on that: a field it does not know is a field it does not copy.
test("unknown fields in a spool record never reach the event", () => {
  const line = auditLine({ requestObject: { password: "SHOULD-NEVER-APPEAR" } });
  const event = clusterRecordToEvent(line);
  assert.ok(event);
  assert.ok(!JSON.stringify(event).includes("SHOULD-NEVER-APPEAR"));
});

test("control characters in process arguments are stripped before triage", () => {
  const esc = String.fromCharCode(0x1b);
  const event = clusterRecordToEvent(
    tetragonExec({ binary: "/bin/sh", arguments: `-c ${esc}[2Jclear` }),
  );
  assert.ok(event);
  const printable = [...(event.url ?? "")].every((ch) => {
    const code = ch.codePointAt(0) ?? 0;
    return code >= 0x20 && code !== 0x7f;
  });
  assert.ok(printable);
});

const hits = (record: unknown) => {
  const event = clusterRecordToEvent(record);
  assert.ok(event);
  return runDetection(event).hits.map((hit) => hit.ruleId);
};

test("curl followed by a bare shell is a piped-shell execution", () => {
  const actor = { auid: 1000, uid: 1000, pod: {} };
  hits(
    tetragonExec({ binary: "/usr/bin/curl", arguments: "-s http://127.0.0.1:8899/x.sh", ...actor }),
  );
  assert.ok(
    hits(tetragonExec({ binary: "/usr/bin/bash", arguments: "", ...actor })).includes(
      "AISOC-HOST-2001",
    ),
  );
});

test("the pair is detected whichever half reaches the exec tracepoint first", () => {
  const actor = { uid: 1002, auid: 1002, pod: {} };
  hits(tetragonExec({ binary: "/usr/bin/bash", arguments: "", ...actor }));
  assert.ok(
    hits(
      tetragonExec({ binary: "/usr/bin/curl", arguments: "-s http://127.0.0.1/x.sh", ...actor }),
    ).includes("AISOC-HOST-2001"),
  );
});

test("a shell running a named script is not a piped-shell execution", () => {
  const actor = { uid: 1000, auid: 1000, pod: {} };
  hits(tetragonExec({ binary: "/usr/bin/curl", arguments: "-s http://127.0.0.1/x.sh", ...actor }));
  assert.ok(
    !hits(
      tetragonExec({ binary: "/usr/bin/bash", arguments: "/usr/local/bin/deploy.sh", ...actor }),
    ).includes("AISOC-HOST-2001"),
  );
});

test("a shell an hour after a fetch is not correlated with it", () => {
  const actor = { uid: 1001, auid: 1001, pod: {} };
  hits(
    tetragonExec(
      { binary: "/usr/bin/curl", arguments: "-s http://127.0.0.1/x.sh", ...actor },
      "2026-08-25T12:00:00.000Z",
    ),
  );
  assert.ok(
    !hits(
      tetragonExec(
        { binary: "/usr/bin/bash", arguments: "", ...actor },
        "2026-08-25T13:00:00.000Z",
      ),
    ).includes("AISOC-HOST-2001"),
  );
});

test("a service account reading another namespace's secrets is credential access", () => {
  assert.ok(
    hits(auditLine({ namespace: "authentik", objectName: "oidc" })).includes("AISOC-K8S-2103"),
  );
});

test("a service account reading its own namespace's secrets is not", () => {
  assert.ok(!hits(auditLine({})).includes("AISOC-K8S-2103"));
});

test("deleting a tracing policy is impairing defenses", () => {
  const ids = hits(
    auditLine({
      verb: "delete",
      resource: "tracingpolicies",
      objectName: "socket-bind-listen",
      user: "aisoc",
      namespace: "",
    }),
  );
  assert.ok(ids.includes("AISOC-K8S-2104"));
});

test("an authority change by Argo CD is expected, by anyone else is not", () => {
  const change = {
    verb: "create",
    resource: "clusterrolebindings",
    objectName: "x",
    namespace: "",
  };
  assert.ok(
    !hits(
      auditLine({
        ...change,
        user: "system:serviceaccount:argocd:argocd-application-controller",
      }),
    ).includes("AISOC-K8S-2101"),
  );
  assert.ok(
    hits(auditLine({ ...change, user: "system:serviceaccount:dev:builder" })).includes(
      "AISOC-K8S-2101",
    ),
  );
});

test("an anonymous request that the API server allowed is a finding", () => {
  const ids = hits(
    auditLine({ user: "system:anonymous", verb: "list", resource: "secrets", code: 200 }),
  );
  assert.ok(ids.includes("AISOC-K8S-2105"));
});

test("the bootstrap identity writing outside a run is a finding", () => {
  const ids = hits(
    auditLine({
      user: "system:serviceaccount:kube-system:platform-bootstrap",
      verb: "create",
      resource: "clusterrolebindings",
      namespace: "",
    }),
  );
  assert.ok(ids.includes("AISOC-K8S-2106"));
});

test("the collector reporting shed load becomes a triageable event", () => {
  const event = clusterRecordToEvent({
    _stream: "collector",
    ts: "2026-08-25T13:00:00.000Z",
    record: { dropped: 4200, window_seconds: 60 },
  });
  assert.equal(event?.severity, 2);
  assert.match(event?.signature ?? "", /shed/);
});
