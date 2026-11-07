Technical reference: Adversary emulation program, telemetry inventory, and findings register.

# Adversary emulation & detection engineering — lab environment

Authorized emulation against lab infrastructure: the `soc-host`
workstation, its k3s cluster, and the four control planes that govern them. The blue
side is **aisoc** — not Grafana. Local inference (`llama-server`, `:8082`) proposes;
deterministic tooling executes; a human runs every red action.

## Charter

The program exists to answer one question per technique: *if this happened
tonight while nobody was watching, would aisoc have said so?*

**A technique is covered when all five hold.** Anything less is an open finding.

1. A versioned detection artifact exists at a known path — an `AISOC-*` rule in
   `console/server/src/detect/rules.ts`, a Tetragon `TracingPolicy`, or an
   auditd rule. A LogQL query in a document is evidence, never coverage.
2. It has a unit test with a real event fixture, so it survives refactors.
3. It fired on replay, end to end, into an aisoc incident — not just into Loki.
4. Its false-positive behaviour is characterised and budgeted (round 2's legit
   `sudo` BLOCK is the reference case).
5. A named source of telemetry backs it, and that source has a deadman.

**Non-goal:** breadth of ATT&CK coverage. Eight scenarios that match this
estate's real blast radius beat sixty atomics that match somebody else's.

## The estate and its trust boundaries

Five control planes, ordered by what their compromise yields:

| Plane | Authority | Compromise yields | Detection consumer today |
|---|---|---|---|
| Scalr workspace + run agent | every bootstrap secret; runs arbitrary code on an agent mounting a cluster-admin kubeconfig (`/var/lib/scalr-agent/kubeconfig`) | cluster-admin **and** host RCE — the crown jewel | none |
| Git (`aisoc-org/platform`) → Argo CD | cluster desired state, applied with cluster-admin, self-healing | persistent cluster-admin that repairs itself after you delete it | none |
| Authentik (`auth.home.arpa`) | human identity for Argo CD, Grafana, Headlamp — and, per the plan below, aisoc | every console an operator has | none |
| Infisical (`secrets` ns) + ESO | every application runtime secret | app-level credential theft, quietly | none |
| aisoc (host) | nftables enforcement, evidence, triage | the ability to be blind and to blame it on quiet | itself |

Four of five planes have no detection consumer. That, not the ATT&CK matrix, is
the gap this program closes.

## The independence rule

**aisoc must never depend on what aisoc defends.** Every integration below is
designed so that losing the cluster degrades aisoc's convenience, never its
ability to detect, decide, enforce, or be operated.

| Dependency | Normal path | Cluster down / compromised |
|---|---|---|
| Console identity | Authentik OIDC (`aisoc` provider, groups → `viewer`/`analyst`/`admin`) | loopback break-glass via `AISOC_BOOTSTRAP_FILE`; use is a privileged audit event and pages |
| Runtime API keys | Infisical machine identity → host credential cache | last-known-good cache keeps serving; refresh failure marks intel degraded, never blocks triage |
| Evidence storage | push to `platform-loki` **and** local SQLite/JSONL | local store is authoritative; Loki is a queryable copy |
| Enforcement | `aisoc-enforcer` on the host, nftables | unaffected by design — no cluster in the path |
| Audit-chain signing key | host-held (TPM / `LoadCredentialEncrypted`) | never in Infisical: whoever owns the cluster must not be able to forge the record of owning it |

Corollary, and it is a hard rule: **no security-critical aisoc secret may live
only in Infisical, and no aisoc control path may traverse the cluster.**

## Scenarios, ranked by blast radius

Each carries emulation, the telemetry it needs, where the detection lands, and
whether it may run on this node. `S` numbers are stable — the coverage ledger
and findings register reference them.

### S1 — Scalr run agent → cluster-admin + host RCE *(needs scratch node)*
T1078.004, T1195.002. A malicious `.tf` or provider in a run executes on the
agent container, which mounts a cluster-admin kubeconfig. **Emulate** by adding
a benign `local-exec`/data source to a throwaway workspace that reads the
kubeconfig path and lists secrets.
**Telemetry:** Tetragon exec + `security_file_open` on the kubeconfig path,
scoped to the agent's cgroup; k3s audit for `platform-bootstrap` acting outside
a declared run window.
**Detection:** `AISOC-K8S-*` rule "bootstrap identity used outside a run
window" + TracingPolicy `scalr-agent-kubeconfig-read`.
Full-privilege variant never runs on this node.

### S2 — Git write → Argo CD applies attacker state *(runs here, read-only variant)*
T1195.001, T1053. The ARC PAT holds classic `repo` scope on the very repo Argo
CD applies with cluster-admin; a PR merge is a cluster-admin write primitive.
**Emulate** by committing a benign, clearly-marked manifest to a scratch branch
and pointing a disposable Application at it — never `main`.
**Telemetry:** k3s audit (create by `argocd-application-controller` of an object
no human approved), Argo CD's own event stream (**not currently collected**).
**Detection:** alert on Argo CD applying a resource kind outside the set the
repo has ever contained; alert on any `ClusterRoleBinding` write, period.

### S3 — Detection-stack impairment *(runs here)*
T1562.001. `kubectl delete tracingpolicy socket-bind-listen`,
`helm uninstall tetragon`, `systemctl stop aisoc-host-events`, truncate the
Tetragon export.
**Telemetry:** k3s audit delete verbs on `tetragon.io`/`cilium.io` resources;
systemd unit state; stream deadmen.
**Detection:** deadman alerts (§Telemetry) + an aisoc rule on unit stop. Once
Tetragon is Argo-managed, deletion self-heals and the *repair* is itself a
high-signal event. This scenario is the reason Tetragon must leave `helm
install` and enter GitOps.

### S4 — Authentik compromise / session theft *(runs here, benign variant)*
T1556, T1550.001. Forged group claim, stolen ID token, or an OIDC login for a
user not in the aisoc groups.
**Telemetry:** Authentik events (**not currently collected**), console auth
failures.
**Detection:** aisoc rule on `admin` role assertion without a matching recent
Authentik authentication event; step-up flow (below) makes a stolen ordinary
session insufficient for enforcement changes.

### S5 — ARC runner executing untrusted PR code *(runs here)*
T1204.003, T1610. Self-hosted runners execute repository code on the node that
runs prod, supabase and authentik. This is the most probable *real* intrusion
path in the estate and the current drill list ignores it.
**Telemetry:** Tetragon exec + egress in `arc-runners`; NetworkPolicy denials.
**Detection:** rule for a runner pod reaching the API server, the kubelet, or
any in-cluster Service that is not the registry.

### S6 — Workload escape → node → host *(needs scratch node for the real variant)*
T1610, T1611, T1552.007. `peirates`/`kdigger` from a pod; the deliberately weak
manifest (hostPath `/`, hostNetwork, cluster-admin SA) in `attack-lab`.
**Telemetry:** Tetragon `setns`/`ptrace`/SA-token read; k3s audit
`pods/exec`, `nodes/proxy`.
Weak-pod deploy runs here (namespace is quota'd and egress-denied); genuine
kernel-escape attempts do not.

### S7 — Host user compromise *(runs here — the classic desktop path)*
T1059.004, T1548, T1505, T1496. Round 1 and 2 covered the first two.
**Telemetry:** auditd → `audit_tail.py` → aisoc; Tetragon host events.

### S8 — Infisical / ESO credential theft *(runs here, read-only)*
T1552.001, T1528. Read a `ClusterSecretStore`-backed Secret from a pod that has
no business with it; use the ESO identity outside ESO.
**Telemetry:** k3s audit on `secrets` (Metadata — see finding F1), Infisical
audit log (**not currently collected**).

## Telemetry inventory

| Source | Lands | Consumed by aisoc | Deadman | Gap |
|---|---|---|---|---|
| Suricata eve | `suricata/logs/eve.json` | yes | sensor health poll (120 s) | — |
| auditd | `host-events.jsonl` | yes | none | execve only at `euid=0` (F4) |
| Tetragon | `/var/run/cilium/tetragon/*.log` → collector spool → aisoc; → Loki | **yes** | aisoc sensor health | — |
| k3s audit | `/var/log/k3s-audit/audit*.log` → collector spool → aisoc; → Loki | **yes** | aisoc sensor health | — |
| Argo CD events | — | no | — | uncollected |
| Authentik events | — | no | — | uncollected |
| Infisical audit | — | no | — | uncollected |
| Scalr run logs | hosted | no | — | uncollected |

Both source files are root-only, and stay that way. `scripts/cluster_tail.py`
runs as root, is the only reader, and appends a *minimised* record to
`/var/lib/aisoc-host-events/cluster-events.jsonl` for the unprivileged console:
no request or response bodies, no node or pod labels, every field length-capped.
That is the collector/core split from `architecture-target.md` §1 applied to
cluster telemetry — and it means a regression in the audit policy cannot push
secret material into a prompt, because the spool has no bodies to leak.

Volume is the other half. Tetragon emits ~100 events/second here, so the
collector filters to what a detection could fire on (~14/s) and rate-limits the
remainder. Shedding is **priority-aware**: host execs carrying a login session,
kprobes, emulation-namespace execs and every audit record are never dropped.
That distinction is not theoretical — the first run of the collector shed drill
round 1's `curl` while faithfully recording several hundred container health
checks around it (F17).

## Where a detection is allowed to live

| Tier | Artifact | Path | Gate |
|---|---|---|---|
| Product detection (default) | `Rule` with ATT&CK ref, score, confidence | `console/server/src/detect/rules.ts` + test | code review, pack version bump |
| Sensor policy | Tetragon `TracingPolicy` | staged in `k3s/tracing-policies/`, promoted to `platform/infra/gitops/platform/tetragon/policies/` | LSM `security_*` hooks only, ≤ 5 kprobes, 5-minute node-load watch, documented `kubectl delete` rollback |
| Host policy | auditd rule | `scripts/aisoc-audit.rules` | replay before deploy |
| Evidence / hunting only | LogQL | Loki ruler in GitOps | never counts as coverage |

A drill round is not closed until its detection has been *promoted* out of the
staging tier. A verified detection sitting in `k3s/tracing-policies/` is an open
finding, not a closed one.

Replay is the check: `tsx server/src/testing/replay-cluster.ts <spool>` runs a
captured spool through the real detection engine and exits non-zero when nothing
fires, so a drill round ends with an assertion rather than an opinion.

## Ownership: GitOps vs host vs never-GitOps

**Cannot be GitOps'd — precedes or bootstraps the API server.** Belongs in
`platform/infra/host/`, not here:

- `systemd/k3s-audit.conf` — sets apiserver flags; Argo CD runs on top of what
  it configures.
- `k3s/audit-policy.yaml` — a file the apiserver reads from disk at start, not
  an API object.
- `/etc/sysctl.d/90-inotify.conf` — exists today only as prose in this document.

**Must move into Argo CD (platform repo), currently imperative:**

- **Tetragon Helm Application** + values from `k3s/tetragon-values.yaml`,
  `selfHeal: true`. It is the primary detection control and today a hand-run
  `helm install` with zero drift protection. Self-heal is also the S3 response.
- **TracingPolicies** — detection content, versioned and pruned.
- **`attack-lab` namespace** — absent from `namespaces.yaml`, so it has no PSS
  label, no quota, and no NetworkPolicy, while being the one namespace that will
  run hostPath `/` and a miner mimic. Needs `enforce: privileged`
  (deliberately), a tight `ResourceQuota`, and **default-deny egress** — which
  turns the miner and C2 drills into a test of the NetworkPolicy.
- **Loki ruler rules** — the deadmen below.

**Must never be GitOps'd, though they are Kubernetes objects. Stay here:**

- `k3s/attack/*` (weak pods, cluster-admin SAs). With `prune + selfHeal` Argo CD
  resurrects an attack asset seconds after you delete it, and repo write access
  becomes an automated privilege-escalation primitive. Apply by hand; delete
  after; never reference from a kustomization.
- `k3s/kube-bench-job.yaml`, `k3s/kube-hunter-job.yaml` — one-shot Jobs. The
  legitimate recurring form is a CronJob in GitOps with scraped results; that is
  a different artifact.

## Platform integration — the three planes aisoc should use

### Authentik: identity for the console
Replace tailnet-header identity (a transport control, per
`architecture-target.md` invariant 5) with an OIDC Authorization Code + PKCE
flow against `auth.home.arpa`, following the existing `grafana.yaml` blueprint:

- New blueprint `platform/infra/gitops/platform/authentik/resources/blueprints/aisoc.yaml`;
  redirect URIs for `https://aisoc.lab.internal/...` only — no LAN redirect,
  no Funnel.
- Groups `aisoc-viewer` / `aisoc-analyst` / `aisoc-admin` map to the roles
  `architecture-target.md` §6 already specifies. Remote defaults to viewer.
- **Step-up for enforcement.** Reuse the Grafana pattern's dedicated
  authorization flow with `authenticatorvalidatestage`,
  `last_auth_threshold: seconds=0`, `not_configured_action: deny` — a second
  provider for the admin scope. Unblock, autonomy change, rule change and
  export require a fresh MFA assertion, so a stolen session is not enough. This
  is the concrete implementation of "recent re-authentication".
- The host must trust `Lab Local Root CA` for the console to validate the
  issuer.
- **Break-glass stays local.** `AISOC_BOOTSTRAP_FILE` on loopback, one-time,
  recorded as a privileged audit event, and it pages. Authentik being down must
  never mean the SOC is down (independence rule).

### Infisical: runtime intel and notifier keys
`AISOC_ABUSEIPDB_KEY`, `AISOC_VIRUSTOTAL_KEY`, `AISOC_DNSHISTORY_KEY`,
Telegram/ntfy/SMTP move out of unit-file `Environment=` lines:

- Infisical folder `/aisoc`, machine identity with a read-only scope.
- A host oneshot + timer pulls into `/etc/aisoc/credentials.d/*` (`0600 root`),
  consumed via systemd `LoadCredential=`. Cache is authoritative at boot; a
  failed refresh marks intel degraded and never blocks triage.
- **Excluded by policy:** the audit-checkpoint signing key and any enforcer
  credential. Those stay host-held.

### Scalr/OpenTofu: unchanged scope, new obligations
Tofu keeps owning exactly Argo CD plus the bootstrap credentials. It gains no
security runtime. What it gains is *scrutiny*: it is the S1 target, its agent's
kubeconfig read is a first-class detection, and `platform-bootstrap` acting
outside a run window is an incident.

## Safety rules for red work on a production node

This box runs prod, supabase, authentik, argocd and the operator's daily
desktop. The old "isolated VLAN / VM snapshots" guardrail was aspirational —
there is no VM. Replace it with explicit rules:

1. **Per-scenario verdict is binding:** *runs here* / *needs scratch node* /
   *never*. S1 (full), S6 (kernel escape) and destructive S3 variants need a
   scratch node.
2. **Never truncate the live audit chain.** T1070 is emulated against a decoy
   path; the real detection for log destruction is *absence*, which is why the
   deadmen come first.
3. **Egress-deny before offensive workloads.** The miner and C2 mimics test the
   NetworkPolicy; they do not talk to the Internet.
4. **Kill switch, stated before each round:** which command stops the drill, and
   which unit to restart if the detection stack itself is the target.
5. **Model-authored policies are load-tested**, per the sensor-policy gate above.
6. **Every round ends with cleanup verified**, not assumed: the weak pod is
   deleted and confirmed gone before the next round starts.

## Round record format

Each round appends: date · scenario · technique · red command · per-source
outcome (HIT/MISS with the reason) · aisoc verdict and latency · detection
artifact path · FP note · promoted (y/n).

## Coverage ledger

| Scenario | Technique | Date | auditd | Tetragon | aisoc detection | Artifact | Promoted |
|---|---|---|---|---|---|---|---|
| S7 | T1059.004 piped shell | 2026-08-25 | MISS (F4) | HIT | **HIT** `AISOC-HOST-2001` @31 suspicious | `detect/rules.ts` + `sources/cluster.test.ts` | **yes** |
| S7 | T1548 sudo | 2026-08-25 | HIT | HIT | BLOCK @0.72 (reported) | `aisoc-audit.rules` `root_exec`/`priv_esc` | n/a |
| S7 | T1505 listener | 2026-08-25 | n/a | HIT | **HIT** `AISOC-HOST-2002` @26 suspicious | `detect/rules.ts` + `socket-bind-listen` policy | **yes** |
| S3 | T1562.001 | — | — | — | rule written, not yet drilled | `AISOC-K8S-2104` | rule only |
| S1 | T1078.004 | — | — | — | rule written, not yet drilled | `AISOC-K8S-2106` | rule only |
| S8 | T1552.007 | — | — | — | rule written, not yet drilled | `AISOC-K8S-2103` | rule only |
| S2, S4, S5, S6 | — | — | — | — | — | — | not started |

Three rounds in, coverage by the charter's definition is **two techniques** —
T1059.004 and T1505 — both closed on 2026-08-25 by replaying live telemetry
through the real engine, plus T1548 which existing auditd rules already covered.
Four more rules exist for control-plane scenarios but have not been fired at, so
they are written, not covered. Rules that have never seen their own attack are
a hypothesis.

False-positive budget, measured on the round-3 replay: 163 events, 4 hits, of
which 2 were the drill and 2 were `AISOC-EXEC-0003` on containerised nginx and
Kong running `sh -c` health checks (F18). One FP per ~80 events at this volume is
too high to leave alone before the cluster scenarios start.

## Findings register

| # | Sev | Status | Finding |
|---|---|---|---|
| F1 | high | **fixed** | **Finding:** `audit-policy.yaml` logged `level: Request` on secrets.<br/>**Impact:** Secret bodies were replicated into downstream log storage.<br/>**Fix:** Changed secret/configmap logging to `Metadata`; preserved `Request` for RBAC/admission/exec paths; added `omitStages: [RequestReceived]`. |
| F2 | high | **fixed** | **Finding:** Tetragon eBPF and k3s audit streams lacked integration with aisoc engine.<br/>**Impact:** Cluster execution events (`pods/exec`) had no detection pipeline.<br/>**Fix:** Added `scripts/cluster_tail.py` reader and `k8s` event facets in `console/server/src/sources/cluster.ts`. |
| F3 | med | **fixed** | **Finding:** Tetragon export permissions were overly permissive.<br/>**Impact:** File carried unmasked execution arguments readable by unprivileged local accounts.<br/>**Fix:** Restricted export permissions to `0600`. |
| F4 | med | open | **Finding:** auditd records execve only at `euid=0`.<br/>**Impact:** Non-root execution is invisible to the auditd bridge.<br/>**Fix:** Mitigated via Tetragon eBPF coverage; evaluate widening audit rules. |
| F5 | med | **fixed** | **Finding:** Tetragon export was unthrottled and exported non-security lifecycle events.<br/>**Impact:** High log volume risked disk exhaustion.<br/>**Fix:** Dropped `PROCESS_EXIT` from allowlist, capped export rate at 30k events/s, set bounded file rotation. |
| F6 | high | **fixed** | **Finding:** Ingestion streams lacked automated deadman monitors.<br/>**Impact:** Silent sensor failure could leave detection blind indefinitely.<br/>**Fix:** Added host-side sensor health tracking with silence budgets and Prometheus alert rules. |
| F7 | med | **fixed** | **Finding:** Sensor DaemonSet deployment was unmanaged by GitOps.<br/>**Impact:** Manual modifications or deletion lacked audit trail and automatic recovery.<br/>**Fix:** Packaged Tetragon deployment under Argo CD with `selfHeal` and Git-tracked policies. |
| F8 | med | **fixed** | **Finding:** Emulation namespace lacked network isolation.<br/>**Impact:** Attack emulation probes risked generating unwanted egress traffic.<br/>**Fix:** Applied NetworkPolicies with default-deny ingress and DNS-only egress to drill namespaces. |
| F9 | med | open | **Finding:** Console session identity derived from transport headers without step-up auth.<br/>**Impact:** Compromised transport credentials could authorize firewall mutations.<br/>**Fix:** Plan OIDC PKCE flow with MFA step-up for enforcement changes. |
| F10 | low | **fixed** | **Finding:** Automated compliance scans conflated vanilla K8s paths with k3s architecture.<br/>**Impact:** Artificial failure noise masked genuine security posture.<br/>**Fix:** Documented verified live findings vs distribution-specific path variances. |
| F11 | low | open | **Finding:** RBAC audit relied solely on `auth can-i --list`.<br/>**Impact:** Blind to transitive escalation privileges (`escalate`, `bind`, `impersonate`).<br/>**Fix:** Tracked for expansion into dedicated RBAC graph analysis. |
| F12 | low | **fixed** | **Finding:** Redundant telemetry daemon evaluated alongside eBPF/auditd.<br/>**Impact:** Resource duplication without incremental detection value.<br/>**Fix:** Consolidated cluster event ingestion into k3s audit and Tetragon. |
| F13 | med | **fixed** | **Finding:** Host audit events omitted tty and parent process context.<br/>**Impact:** Legitimate administrator commands indistinguishable from automated malware escalation.<br/>**Fix:** Enhanced `audit_tail.py` to correlate SYSCALL/EXECVE/PATH records and attach session/tty/ppid. |
| F14 | high | **fixed** | **Finding:** Sensor log rotation retained only 5 x 10MB backups.<br/>**Impact:** High-volume bursts collapsed evidence retention window to minutes.<br/>**Fix:** Expanded retention to 1GB bounded buffer and added window-collapse alerting. |
| F15 | med | **fixed** | **Finding:** Socket bind probes intercepted all netlink socket creation.<br/>**Impact:** Noise from internal IPC overwhelmed analysis.<br/>**Fix:** Filtered eBPF probe to `AF_INET`/`AF_INET6` families. |
| F16 | high | **fixed** | **Finding:** Audit log shipping pinned to specific file path without rotation handling.<br/>**Impact:** Log rotation caused silent collection stall.<br/>**Fix:** Moved audit log target to dedicated directory with glob pattern matching and rotation awareness. |
| F17 | med | **fixed** | **Finding:** Flat rate-limiting shed critical execution traces under health-check load.<br/>**Impact:** High-frequency container health checks masked interactive attack commands.<br/>**Fix:** Implemented priority-aware shedding preserving interactive sessions, kprobes, and audit records. |
| F18 | med | open | **Finding:** Web-shell rule triggered on containerized web-server health checks.<br/>**Impact:** False positive rate of ~1 per 80 events during active drills.<br/>**Fix:** Tuning workload-specific allowlists for internal container health-check commands. |
| F19 | high | **fixed** | **Finding:** GitOps repo-server liveness timeout set to default 1s.<br/>**Impact:** Cache invalidation on large commits triggered liveness kill loops.<br/>**Fix:** Adjusted probe timeout, increased worker parallelism, and allocated dedicated compute. |
| F20 | med | **fixed** | **Finding:** Project boundary rejected security sensor installation.<br/>**Impact:** Security instrumentation failed deployment due to RBAC policy.<br/>**Fix:** Assigned dedicated sensor project permitted to manage cluster-scoped TracingPolicies. |
| F21 | high | **fixed** | **Finding:** Full-tunnel WireGuard profile routed Kubernetes ClusterIP CIDRs through VPN interface.<br/>**Impact:** Host-to-API-server communication timed out.<br/>**Fix:** Excluded `10.42.0.0/16` and `10.43.0.0/16` from VPN route tables in `console/server/src/vpn/wireguard.ts`. |
| F22 | med | **fixed** | **Finding:** Ingestion spools lacked automated log rotation.<br/>**Impact:** Spool files grew unboundedly on high-volume hosts.<br/>**Fix:** Configured logrotate with copytruncate and bounded sizing. |
| F23 | high | open | **Finding:** Network wire sensor container stopped.<br/>**Impact:** Packet inspection offline while development focused on host/cluster telemetry.<br/>**Fix:** Added deadman alerting to fire when expected sensor feeds go quiet. |
| F24 | med | open | **Finding:** Coverage unbalanced between host/cluster and network inspection.<br/>**Impact:** Replay verification not yet completed for all Suricata signatures.<br/>**Fix:** Planned network replay test pass against Suricata engine. |
| F25 | high | **fixed** | **Finding:** Ingestion spool permissions set to agent user rather than console user.<br/>**Impact:** Console received EACCES when attempting to ingest cluster telemetry.<br/>**Fix:** Adjusted spool file group ownership to match console service identity. |
| F26 | med | open | **Finding:** Cluster telemetry ingestion flag was not exposed in the settings UI.<br/>**Impact:** Ingestion toggle required manual configuration edits.<br/>**Fix:** Adding UI control to `IngestSection` for cluster telemetry source. |

## Phases and gates

**P0 — stop the bleeding (F1, F3, F5, F6, F14, F15, F16).** Done in code and
config; the two host-level applies are in Handoff below.
*Gate:* killing Tetragon pages within 10 minutes — not yet demonstrated, because
the alerts land with the next platform sync.

**P1 — make aisoc the consumer (F2, F13).** Done: collector, spool, source,
`k8s` facet, sensor health. Still owed from `architecture-target.md` §4: durable
cursors. The tailer starts at end of file, so a console restart loses the
records written while it was down — acceptable while the export file and Loki
hold the evidence, not acceptable once triage decisions depend on it.
*Gate:* met for detection (round 3 replay); not yet for durability.

**P2 — detections as product (F4, F7, F8).** Tetragon into GitOps, namespace
hardened, eight new rules with tests. Remaining: fire at the four control-plane
rules that have never seen their own attack, and tune F18.
*Gate:* met for the ledger; not met for the rules that are hypotheses.

**P3 — control-plane scenarios (S1–S5, S8).** Requires the four uncollected
sources. Start with Argo CD and Authentik events — both are in-cluster and
Alloy already runs.
*Gate:* deleting a TracingPolicy, and Argo CD healing it, both appear as aisoc
events.

**P4 — identity and secrets (F9, Infisical).** OIDC with step-up; keys out of
unit files; break-glass tested with the cluster deliberately stopped.
*Gate:* `systemctl stop k3s`, then log in and enforce a block.

## Model role boundaries

Huihui may: tailor atomics to this host; triage scanner output; draft detection
rules; write the deliberately-weak manifests.

Huihui must not: execute its own commands; touch anything beyond
loopback/private targets; be reachable beyond loopback/tailnet; author a sensor
policy that reaches production without the load-test gate.

Observed limits, twice confirmed: it burns its token budget on reasoning and
returns empty `content` unless the prompt forbids thinking aloud
(`enable_thinking: false`), and it could not emit a valid TracingPolicy in three
attempts — `k3s/tetragon-socket-policy.yaml` was hand-written. Useful for
triage and query authoring; not yet for CRD authoring.

## Drill log

### Round 1 — S7 / T1059.004 `curl|bash` as uid 1000 (2026-08-25)

- **Red:** `curl -s http://127.0.0.1:8899/x.sh | bash` (locally served, benign
  echo, no external fetch).
- **auditd: MISS**, as predicted — `aisoc-audit.rules` records execve only at
  `euid=0` (F4). Nothing in `host-events.jsonl`.
- **Tetragon: MISS**, new root cause — the chart default
  `exportDenyList: {"namespace": [""]}` silently drops every *host* event, which
  is precisely what desktop drills produce. `exportAllowList: '{}'` never lifted
  it. Fixed with `exportDenyList: '{"health_check": true}'` (capital L;
  `exportDenylist` is silently ignored), helm rev 6.
- **Replay: HIT** — `/usr/bin/curl -s …x.sh` → `/usr/bin/bash`
  (`arguments: null`, stdin pipe) at 01:44:06Z, queryable in platform-loki via
  Alloy (`{job="tetragon"}`).
- **Blue (Huihui):** two-stream LogQL correlation — a `curl` exec with an
  `https?://` argument followed by a `bash` exec with `arguments: null` (the
  piped-shell signature), scoped by uid:
  ```logql
  {job="tetragon"} |~ '"binary":"/usr/bin/curl".*"arguments":"[^"]*https?://'
  {job="tetragon"} |~ '"binary":"/(usr/bin/)?(b)?a?sh","arguments":null'
  ```
  FP note: package installers and dev tooling legitimately pipe curl to bash;
  tune by uid allowlist.
- **Not promoted at the time.** Per the charter the round was **not covered**:
  the detection was a query in a document, aisoc never saw the event, and there
  was no test. Closed in round 3 by `AISOC-HOST-2001`.

### Round 2 — S7 / T1548 `sudo whoami` (2026-08-25)

- **Red:** interactive `sudo whoami`, human-run (no passwordless sudo here).
- **auditd/aisoc: HIT** — `root_exec` ×3 and `priv_esc` ×9 into
  `host-events.jsonl` within seconds.
- **Triage loop, live:** sev-1 floored to WATCH @0.78 (cron noise), WATCH @0.72
  on the sudo exec, then **BLOCK @0.72 → `host_block_reported`** ("non-root user
  successfully executed an unusual setuid sudo binary … likely local privilege
  escalation") — reported, never enforced, exactly per design. Correctly IGNOREd
  `unix_chkpwd` @0.85.
- **Tetragon: HIT** — `sudo whoami` → `unix_chkpwd operator *` → `/usr/bin/whoami`
  (uid 0), with parent linkage.
- **FP finding (F13):** the model BLOCKs a legitimate interactive admin `sudo`.
  Root cause is telemetry poverty, not judgment — the auditd-derived alert
  carries no tty or parent-exe, so "admin at a terminal" and "malware
  escalating" are the same event. Fix in `audit_tail.py`, not in the prompt.
- No new detection required; existing controls met the metric.

### Round 3 — S7 / T1059.004 and T1505 replayed against the product (2026-08-25)

The point of this round was not the technique — round 1 already ran it — but the
charter: does the *product* see it, or only Grafana?

- **Red**: `python3 -m http.server 8899` (local, benign payload), then
  `curl -s http://127.0.0.1:8899/x.sh | bash` as uid 1000, with the collector
  running against the live Tetragon export.
- **Collector: MISS, then HIT.** The first run shed the `curl` exec at the rate
  limiter while recording several hundred container health checks around it
  (F17). With priority-aware shedding, both halves of the pipeline appear in the
  spool.
- **aisoc: HIT, twice.** Replaying the 163-event spool through the real
  detection engine:
  - `AISOC-HOST-2001` piped-shell execution, score 31, band suspicious;
  - `AISOC-HOST-2002` interpreter opened a listener, score 26 — fired on the
    drill's own `http.server` calling `listen()`, which is T1505's signal and
    came free from the tightened socket policy.
- **Rule defect found by the replay**: the first version of `AISOC-HOST-2001`
  only matched fetch-then-shell. Both halves of a pipeline are forked at once and
  either can reach the exec tracepoint first, so the detection was a coin flip.
  It now matches in both directions, with a test for each.
- **False positives**: 2 of 4 hits (F18).
- **Promoted**: yes — rules, tests and the replay harness are in the repository.
  Round 1's LogQL is superseded; it stays useful for hunting, not as coverage.

## Baseline audit — 2026-08-25

- **kube-bench** (cis-1.10, `k3s/kube-bench-job.yaml`): 1 PASS / 63 FAIL /
  66 WARN, full output `docs/reference/scans/kube-bench-2026-08-25.txt`. **Verified live:**
  apiserver `:6443` and kubelet `:10250` (`/pods`, `/healthz`) return 401
  unauthenticated, so the auth-related FAILs are confirmed noise. The remaining
  FAILs are *presumed* vanilla-vs-k3s path mismatches — presumed, not verified
  (F10).
- **kube-hunter** (`--pod`, hostNetwork, `k3s/kube-hunter-job.yaml`): full JSON
  in `docs/reference/scans/kube-hunter-2026-08-25.txt`. CAP_NET_RAW (containerd default), pod
  SA-token readable (inherent), version disclosure, "API access via SA token"
  (its own token; anonymous is 401). Kubelet reachable from the pod network but
  requires client certs — acceptable on one node.
- **RBAC sweep** (113 SAs): least-privilege except two chart defaults —
  `observability/platform-alloy` can get secrets cluster-wide (unused by its
  config; trim), `arc-systems/arc-gha-rs-controller` gets secrets in its own
  namespace (by design). `default` SAs in attack-lab, prod, supabase, dev hold
  nothing. Blind spots per F11.

## Host facts

`soc-host` / 192.0.2.9, Ubuntu 26.04, standard user account (the
operator runs sudo blocks). k3s v1.36.3 single node, KUBECONFIG
`/etc/rancher/k3s/kubeconfig`, `k3s kubectl` works as the user. Huihui at
`http://localhost:8082/v1/chat/completions`
(`Huihui-Qwen3.8-27B-abliterated-Q5_K`). helm at `/usr/local/bin/helm`.
Tetragon export `/var/run/cilium/tetragon/tetragon.log`; k3s audit
`/var/lib/rancher/k3s/server/audit.log`; both shipped by `platform-alloy`
(labels `job="tetragon"` / `job="k3s-audit"`).
`fs.inotify.max_user_instances` raised 256 → 1024 in
`/etc/sysctl.d/90-inotify.conf` — still documented nowhere but here, and still
owed a home in `platform/infra/host/`.
Setup details and their rationale live beside the things they configure —
`platform/infra/gitops/platform/tetragon/values.yaml`, `systemd/k3s-audit.conf`,
`scripts/cluster_tail.py` — and this document does not repeat them.

## Status — 2026-08-25

Everything in the first handoff is applied and verified on this node:

| Step | State |
|---|---|
| Audit policy + drop-in + `systemctl restart k3s` | done — stream back at ~6 records/s on `/var/log/k3s-audit/audit.log` |
| Tetragon export mode | done — `0600`, confirmed on the live file |
| `deploy.sh` + `aisoc-cluster-events.service` | done — unit active, spool writing |
| `clusterTelemetry.enabled` | reported done; not independently verified (settings.json is root-only) |
| Platform repo pushed, Argo synced | done — 36 apps Synced/Healthy |
| Stale Helm release secret removed | done — `helm list -n tetragon` is empty, Argo CD owns the sensor |

Two of those uncovered failures of their own, recorded as F19–F22.

### What is still owed

**Needs root, and it is the one open fault.** F21: the kubernetes ClusterIP is
unreachable from the host's network namespace. Tetragon is routed around it;
anything else here using hostNetwork is not.

```sh
sudo iptables -t nat -S | grep 10.43.0.1
sudo nft list ruleset | grep -c 10.43.0.1
```

**Needs a Scalr run.** `infra/gitops/bootstrap/argocd-values.yaml` carries the
repo-server probe fix (F19). It is applied live by hand; the next `tofu apply`
reverts it unless that run happens, and the next large commit then repeats the
outage.

**Needs a decision.** F4 (widen the auditd execve rule or accept Tetragon as the
sole source), F11 (RBAC sweep blind spots), F18 (tune the web-shell rule against
containerised health checks), F23 (Suricata rule updates have been failing since
00:58).

**Not started.** Authentik OIDC with step-up for enforcement (F9), Infisical key
delivery, and durable ingest cursors — the console tailer starts at end of file,
so records written while it is down are not replayed. That last one is the
remaining debt from P1, and it is what stands between "detections fire" and
"detections can be trusted to have fired".

**Verify a drill end to end** whenever you want the current number rather than
the recorded one:

```sh
tsx console/server/src/testing/replay-cluster.ts \
  /var/lib/aisoc-host-events/cluster-events.jsonl
```
