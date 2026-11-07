import type { MitreRef, SecurityEvent, Severity } from "@aisoc/shared";
import { isLocal, mitre, outboundPayloadBytes, remoteIp } from "@aisoc/shared";

/**
 * Sigma-style detection rules: a named predicate over event fields, each one
 * carrying its own score, confidence, and ATT&CK mapping. They are deliberately
 * plain functions rather than a parsed rule DSL — the DSL buys nothing until
 * rules come from outside the binary, and a function keeps the match evidence
 * (which field, which value) exact.
 */

export interface RuleMatch {
  field: string;
  value: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  score: number;
  confidence: number;
  origin: string;
  mitre: MitreRef[];
  match: (event: SecurityEvent) => RuleMatch | null;
}

const PACK = "aisoc-core-rules 2026.08.5";

const has = (haystack: string | undefined, needle: string): boolean =>
  Boolean(haystack?.toLowerCase().includes(needle.toLowerCase()));

const hit = (field: string, value: string | number | undefined): RuleMatch | null =>
  value === undefined ? null : { field, value: String(value) };

/** Shannon entropy per character — high values mean random-looking labels. */
export function entropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let sum = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    sum -= p * Math.log2(p);
  }
  return sum;
}

const RANSOM_EXTENSIONS = [".lockbit", ".encrypted", ".locked", ".crypt", ".ryk", ".conti"];

const SHELL_TOOLS = ["nc", "ncat", "netcat", "socat", "bash -i", "sh -i"];

// --- Cluster and host telemetry ---------------------------------------------
//
// Tetragon and the k3s audit log arrive through the collector spool
// (sources/cluster.ts). Their rules read `event.k8s` and the process fields
// rather than the network ones — a `pods/exec` has no port to reason about.

/** Shells and interpreters: the second half of a piped-shell execution. */
const SHELL_BINARIES = new Set(["sh", "bash", "dash", "zsh", "ash", "ksh", "busybox"]);
const INTERPRETERS = new Set([
  ...SHELL_BINARIES,
  "python",
  "python3",
  "perl",
  "ruby",
  "php",
  "node",
]);
const FETCH_TOOLS = new Set(["curl", "wget"]);

/**
 * `curl … | bash` produces two sibling execs, not one: the fetch and the shell
 * that reads its stdout. Neither is suspicious alone — package installers do
 * exactly this — so the signal is the pairing, which means this rule needs a
 * memory. Keyed by user because that is the actor the pairing belongs to, and
 * bounded because an unbounded map in a detection path is a denial of service
 * waiting for an attacker to notice it.
 */
const FETCH_WINDOW_MS = 60_000;
const recentFetch = new Map<string, { at: number; what: string }>();
const recentBareShell = new Map<string, { at: number; what: string }>();

function remember(
  store: Map<string, { at: number; what: string }>,
  actor: string,
  what: string,
  at: number,
): void {
  store.set(actor, { at, what });
  if (store.size > 512) {
    for (const [key, value] of store) {
      if (at - value.at > FETCH_WINDOW_MS) store.delete(key);
    }
  }
}

/** The other half of the pair, if it happened recently enough to be related. */
function takeRecent(
  store: Map<string, { at: number; what: string }>,
  actor: string,
  at: number,
): string | null {
  const seen = store.get(actor);
  if (!seen || at - seen.at > FETCH_WINDOW_MS) return null;
  store.delete(actor);
  return seen.what;
}

function actorOf(event: SecurityEvent): string {
  return `${event.assetId ?? "host"}:${event.user ?? "?"}`;
}

const CLUSTER_AUTHORITY = new Set(["clusterroles", "clusterrolebindings", "roles", "rolebindings"]);
const DETECTION_RESOURCES = new Set([
  "tracingpolicies",
  "tracingpoliciesnamespaced",
  "prometheusrules",
  "networkpolicies",
  "validatingadmissionpolicies",
  "validatingadmissionpolicybindings",
  "validatingwebhookconfigurations",
  "mutatingwebhookconfigurations",
]);
const DESTRUCTIVE_VERBS = new Set(["delete", "deletecollection"]);

export const RULES: Rule[] = [
  {
    id: "AISOC-EXP-0001",
    name: "SQL injection attempt in request URI",
    description: "UNION SELECT or a quoted tautology in the query string of an inbound request.",
    severity: 1,
    score: 45,
    confidence: 0.85,
    origin: PACK,
    mitre: mitre("T1190"),
    match: (event) => {
      const url = event.url ?? "";
      if (!/union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|--\s*$|sleep\(\d+\)/i.test(url)) return null;
      return hit("url", url);
    },
  },
  {
    id: "AISOC-EXP-0002",
    name: "OGNL / expression-language injection",
    description: "Struts-style OGNL payload in a header or user agent (CVE-2017-5638 pattern).",
    severity: 1,
    score: 55,
    confidence: 0.9,
    origin: PACK,
    mitre: mitre("T1190", "T1059"),
    match: (event) => {
      const agent = event.userAgent ?? "";
      if (!/%\{|\$\{.*\}|#_memberAccess|ognl/i.test(agent)) return null;
      return hit("userAgent", agent);
    },
  },
  {
    id: "AISOC-EXP-0003",
    name: "Automated exploitation tooling in user agent",
    description: "The client identifies itself as sqlmap, nikto, nmap NSE, or similar.",
    severity: 2,
    score: 30,
    confidence: 0.92,
    origin: PACK,
    mitre: mitre("T1190", "T1046"),
    match: (event) => {
      const agent = event.userAgent ?? "";
      if (!/sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra/i.test(agent)) return null;
      return hit("userAgent", agent);
    },
  },
  {
    id: "AISOC-C2-0001",
    name: "Beacon check-in URI pattern",
    description: "Short pixel- or submit-style URI on 443 with a stale desktop user agent.",
    severity: 1,
    score: 40,
    confidence: 0.75,
    origin: PACK,
    mitre: mitre("T1071.001"),
    match: (event) => {
      const url = event.url ?? "";
      if (!/^\/(pixel\.gif|submit\.php|updates?|__utm\.gif|jquery-[\d.]+\.min\.js)/i.test(url)) {
        return null;
      }
      if (!has(event.userAgent, "Trident/7.0") && !has(event.userAgent, "MSIE")) return null;
      return hit("url", url);
    },
  },
  {
    id: "AISOC-C2-0002",
    name: "TLS to a non-standard C2 port",
    description: "A TLS handshake on 4444, 8443, 9001, or 50050 — common team-server ports.",
    severity: 2,
    score: 28,
    confidence: 0.6,
    origin: PACK,
    mitre: mitre("T1573", "T1071"),
    match: (event) => {
      if (event.appProto !== "tls") return null;
      if (![4444, 8443, 9001, 50_050].includes(event.destPort)) return null;
      return hit("destPort", event.destPort);
    },
  },
  {
    id: "AISOC-C2-0003",
    name: "High-entropy DNS label",
    description: "A queried hostname whose label entropy matches algorithmic generation.",
    severity: 1,
    score: 35,
    confidence: 0.7,
    origin: PACK,
    mitre: mitre("T1568.002", "T1071.004"),
    match: (event) => {
      const host = event.hostname;
      if (!host || event.appProto !== "dns") return null;
      const label = host.split(".")[0] ?? "";
      if (label.length < 8 || entropy(label) < 3.2) return null;
      return hit("hostname", host);
    },
  },
  {
    id: "AISOC-C2-0004",
    name: "DNS tunnelling — oversized query label",
    description: "A DNS label long enough to be carrying encoded payload rather than a name.",
    severity: 1,
    score: 42,
    confidence: 0.78,
    origin: PACK,
    mitre: mitre("T1071.004", "T1048"),
    match: (event) => {
      const host = event.hostname;
      if (!host || event.appProto !== "dns") return null;
      const label = host.split(".")[0] ?? "";
      if (label.length < 40) return null;
      return hit("hostname", host);
    },
  },
  {
    id: "AISOC-CRED-0001",
    name: "Credentials in cleartext over HTTP",
    description: "A POST to a login path on port 80 — credentials crossing the wire unencrypted.",
    severity: 2,
    score: 25,
    confidence: 0.8,
    origin: PACK,
    mitre: mitre("T1040", "T1552"),
    match: (event) => {
      if (event.destPort !== 80 || !event.url) return null;
      if (!/login|signin|auth|session/i.test(event.url)) return null;
      return hit("url", event.url);
    },
  },
  {
    id: "AISOC-CRED-0002",
    name: "Authentication brute force against a service port",
    description: "Repeated inbound attempts to SSH, RDP, or SMB from one remote address.",
    severity: 2,
    score: 30,
    confidence: 0.7,
    origin: PACK,
    mitre: mitre("T1110"),
    match: (event) => {
      if (![22, 3389, 445].includes(event.destPort)) return null;
      if (!has(event.signature, "brute") && !has(event.signature, "login")) return null;
      return hit("destPort", event.destPort);
    },
  },
  {
    id: "AISOC-DISC-0001",
    name: "Service discovery sweep",
    description: "Inbound probe to a database or management port from an external address.",
    severity: 3,
    score: 18,
    confidence: 0.65,
    origin: PACK,
    mitre: mitre("T1046"),
    match: (event) => {
      if (![1433, 3306, 5432, 6379, 27_017, 9200, 5900].includes(event.destPort)) return null;
      return hit("destPort", event.destPort);
    },
  },
  {
    id: "AISOC-EXEC-0001",
    name: "Download piped straight to a shell",
    description: "curl or wget whose output is piped into an interpreter — no file ever lands.",
    severity: 1,
    score: 50,
    confidence: 0.9,
    origin: PACK,
    mitre: mitre("T1059.004", "T1105"),
    match: (event) => {
      const line = `${event.processName ?? ""} ${event.processPath ?? ""} ${event.url ?? ""}`;
      if (!/(curl|wget)[^|]*\|\s*(ba)?sh/i.test(line)) return null;
      return hit("process", line.trim());
    },
  },
  {
    id: "AISOC-EXEC-0002",
    name: "Reverse shell tooling launched",
    description: "netcat, socat, or an interactive shell spawned with a network redirect.",
    severity: 1,
    score: 52,
    confidence: 0.88,
    origin: PACK,
    mitre: mitre("T1059.004", "T1071"),
    match: (event) => {
      const name = event.processName ?? "";
      if (!SHELL_TOOLS.some((tool) => name.toLowerCase().startsWith(tool))) return null;
      if (!/-e|\/dev\/tcp|exec/i.test(name)) return null;
      return hit("processName", name);
    },
  },
  {
    id: "AISOC-EXEC-0003",
    name: "Interpreter spawned by a network-facing service",
    description: "A shell whose parent is a web server or database — the shape of a web shell.",
    severity: 1,
    score: 48,
    confidence: 0.85,
    origin: PACK,
    mitre: mitre("T1059", "T1190"),
    match: (event) => {
      const parent = (event.parentProcess ?? "").toLowerCase();
      const child = (event.processName ?? "").toLowerCase();
      const servers = ["nginx", "apache", "httpd", "java", "php-fpm", "postgres", "mysqld"];
      const shells = ["sh", "bash", "dash", "zsh", "python", "perl"];
      if (!servers.some((server) => parent.includes(server))) return null;
      if (!shells.some((shell) => child.split(/[\s/]/).includes(shell))) return null;
      return hit("processName", `${parent} → ${child}`);
    },
  },
  {
    id: "AISOC-IMP-0001",
    name: "Ransomware file extension written",
    description: "A file created with an extension used by a known encryptor family.",
    severity: 1,
    score: 60,
    confidence: 0.95,
    origin: PACK,
    mitre: mitre("T1486"),
    match: (event) => {
      const path = event.filePath ?? "";
      if (!RANSOM_EXTENSIONS.some((ext) => path.toLowerCase().endsWith(ext))) return null;
      return hit("filePath", path);
    },
  },
  {
    id: "AISOC-IMP-0002",
    name: "Recovery inhibited",
    description: "Snapshot, shadow-copy, or backup deletion — the step before an encryptor runs.",
    severity: 1,
    score: 58,
    confidence: 0.93,
    origin: PACK,
    mitre: mitre("T1490"),
    match: (event) => {
      const line = `${event.processName ?? ""} ${event.signature}`;
      if (
        !/(btrfs|zfs|lvm).*(delete|destroy)|snapshot.*delete|shadowcopy|vssadmin|timeshift.*--delete/i.test(
          line,
        )
      ) {
        return null;
      }
      return hit("processName", event.processName ?? event.signature);
    },
  },
  {
    id: "AISOC-IMP-0003",
    name: "Ransom note dropped",
    description: "A README/HOW-TO-DECRYPT file written into a user data directory.",
    severity: 1,
    score: 55,
    confidence: 0.9,
    origin: PACK,
    mitre: mitre("T1486"),
    match: (event) => {
      const path = event.filePath ?? "";
      if (!/(readme|how[-_]?to[-_]?decrypt|restore[-_]?files|recover)/i.test(path)) return null;
      if (!/\.(txt|html|hta)$/i.test(path)) return null;
      return hit("filePath", path);
    },
  },
  {
    id: "AISOC-EXFIL-0001",
    name: "Bulk outbound transfer to an untrusted destination",
    description: "A single outbound flow moving more than 25 MB to an external address.",
    severity: 1,
    score: 38,
    confidence: 0.72,
    origin: PACK,
    mitre: mitre("T1041", "T1048"),
    match: (event) => {
      if (isLocal(remoteIp(event))) return null;
      const sent = outboundPayloadBytes(event);
      if (sent < 25_000_000) return null;
      return hit("bytesToServer", `${(sent / 1_000_000).toFixed(1)} MB sent`);
    },
  },
  {
    id: "AISOC-EXFIL-0002",
    name: "Archive staged in a temporary directory",
    description: "A compressed archive written under /tmp or /dev/shm — collection before upload.",
    severity: 2,
    score: 32,
    confidence: 0.75,
    origin: PACK,
    mitre: mitre("T1560", "T1005"),
    match: (event) => {
      const path = event.filePath ?? "";
      if (!/^\/(tmp|dev\/shm|var\/tmp)\//.test(path)) return null;
      if (!/\.(tar\.gz|tgz|zip|7z|rar|tar\.zst)$/i.test(path)) return null;
      return hit("filePath", path);
    },
  },
  {
    id: "AISOC-CRED-0003",
    name: "Credential store accessed by an unexpected process",
    description: "A read of shadow, SSH private keys, or a browser credential database.",
    severity: 1,
    score: 50,
    confidence: 0.85,
    origin: PACK,
    mitre: mitre("T1552"),
    match: (event) => {
      const path = event.filePath ?? "";
      if (
        !/\/etc\/shadow|\.ssh\/id_(rsa|ed25519)$|Login Data|logins\.json|\.aws\/credentials/i.test(
          path,
        )
      ) {
        return null;
      }
      return hit("filePath", path);
    },
  },
  {
    id: "AISOC-PERS-0001",
    name: "Persistence via scheduled job or unit file",
    description:
      "A systemd unit, cron entry, or autostart file written outside package management.",
    severity: 2,
    score: 36,
    confidence: 0.8,
    origin: PACK,
    mitre: mitre("T1053", "T1543"),
    match: (event) => {
      const path = event.filePath ?? "";
      if (
        !/\/etc\/cron|\/var\/spool\/cron|\.config\/systemd\/user\/|\/etc\/systemd\/system\/|\.config\/autostart\//.test(
          path,
        )
      ) {
        return null;
      }
      return hit("filePath", path);
    },
  },
  {
    id: "AISOC-EVAS-0001",
    name: "Security tooling stopped",
    description: "A command disabling the firewall, the IDS, or audit logging.",
    severity: 1,
    score: 46,
    confidence: 0.88,
    origin: PACK,
    mitre: mitre("T1562", "T1070"),
    match: (event) => {
      const line = event.processName ?? "";
      if (
        !/(systemctl\s+(stop|disable)\s+(suricata|auditd|ufw|firewalld))|setenforce\s+0|iptables\s+-F/i.test(
          line,
        )
      ) {
        return null;
      }
      return hit("processName", line);
    },
  },
  {
    id: "AISOC-EVAS-0002",
    name: "Shell history or log cleared",
    description: "Truncation of shell history or system logs immediately after activity.",
    severity: 2,
    score: 34,
    confidence: 0.82,
    origin: PACK,
    mitre: mitre("T1070"),
    match: (event) => {
      const line = `${event.processName ?? ""} ${event.filePath ?? ""}`;
      if (
        !/(history\s+-c)|(>\s*\/var\/log\/)|(rm\s+.*\.bash_history)|shred\s+.*\/var\/log/i.test(
          line,
        )
      ) {
        return null;
      }
      return hit("processName", line.trim());
    },
  },
  {
    id: "AISOC-LAT-0001",
    name: "Internal SSH from a host that does not normally use it",
    description: "An east-west SSH session between two managed hosts.",
    severity: 2,
    score: 30,
    confidence: 0.6,
    origin: PACK,
    mitre: mitre("T1021.004", "T1018"),
    match: (event) => {
      if (event.destPort !== 22) return null;
      if (!event.srcIp.startsWith("192.0.2.") || !event.destIp.startsWith("192.0.2.")) {
        return null;
      }
      return hit("destIp", `${event.srcIp} → ${event.destIp}`);
    },
  },
  {
    id: "AISOC-HOST-2001",
    name: "Remote script piped straight into a shell",
    description:
      "A fetch tool downloaded a URL and a shell was executed by the same actor moments later with no script argument — the shape of curl | bash.",
    severity: 1,
    score: 45,
    confidence: 0.7,
    origin: PACK,
    mitre: mitre("T1059.004", "T1105"),
    match: (event) => {
      if (event.source !== "tetragon" || !event.processName) return null;
      const at = Date.parse(event.ts) || Date.now();
      const actor = actorOf(event);

      if (FETCH_TOOLS.has(event.processName)) {
        const url = /https?:\/\/[^\s"']+/.exec(event.url ?? "")?.[0];
        if (!url) return null;
        // Both halves of a pipeline are forked at once, so either can reach the
        // exec tracepoint first. Matching in one direction only would make the
        // detection a coin flip — which is exactly what the first replay of
        // this rule against live telemetry showed.
        const shell = takeRecent(recentBareShell, actor, at);
        if (shell) return hit("processName", `${url} | ${shell}`);
        remember(recentFetch, actor, url, at);
        return null;
      }
      if (!SHELL_BINARIES.has(event.processName)) return null;
      // A shell invoked to run a named script or a -c command is ordinary; the
      // piped case is the one that reads its program from stdin.
      if ((event.url ?? "").trim().length > 0) return null;

      const url = takeRecent(recentFetch, actor, at);
      if (!url) {
        remember(recentBareShell, actor, event.processName, at);
        return null;
      }
      return hit("processName", `${url} | ${event.processName}`);
    },
  },
  {
    id: "AISOC-HOST-2002",
    name: "Interpreter opened a network listener",
    description:
      "A shell or scripting interpreter called listen() on an IP socket. Legitimate services are not usually started by one.",
    severity: 1,
    score: 40,
    confidence: 0.65,
    origin: PACK,
    mitre: mitre("T1505", "T1059"),
    match: (event) => {
      if (event.k8s?.kprobe !== "security_socket_listen") return null;
      const name = event.processName ?? "";
      if (!INTERPRETERS.has(name)) return null;
      return hit("processName", `${name} listen()`);
    },
  },
  {
    id: "AISOC-K8S-2101",
    name: "Cluster authority changed",
    description:
      "A role or binding was written. Every persistent cluster compromise ends here, and legitimate changes come from Argo CD alone.",
    severity: 1,
    score: 45,
    confidence: 0.7,
    origin: PACK,
    mitre: mitre("T1078.004", "T1098"),
    match: (event) => {
      const k8s = event.k8s;
      if (!k8s?.resource || !k8s.verb) return null;
      if (!CLUSTER_AUTHORITY.has(k8s.resource)) return null;
      if (k8s.verb === "get" || k8s.verb === "list" || k8s.verb === "watch") return null;
      // Argo CD reconciling declared state is the expected author of these
      // writes; anything else touching authority is the finding.
      if ((k8s.subject ?? "").includes("argocd")) return null;
      return hit(
        "k8s.resource",
        `${k8s.verb} ${k8s.resource}/${k8s.objectName ?? "?"} by ${k8s.subject ?? "?"}`,
      );
    },
  },
  {
    id: "AISOC-K8S-2102",
    name: "Interactive session opened into a pod",
    description: "kubectl exec, attach or port-forward against a running container.",
    severity: 2,
    score: 30,
    confidence: 0.6,
    origin: PACK,
    mitre: mitre("T1609"),
    match: (event) => {
      const k8s = event.k8s;
      if (!k8s?.resource) return null;
      if (!/^pods\/(exec|attach|portforward)$/.test(k8s.resource)) return null;
      return hit(
        "k8s.resource",
        `${k8s.resource} ${k8s.namespace ?? "?"}/${k8s.objectName ?? "?"} by ${k8s.subject ?? "?"}`,
      );
    },
  },
  {
    id: "AISOC-K8S-2103",
    name: "ServiceAccount read secrets outside its own namespace",
    description:
      "A workload identity reached for credentials belonging to another namespace — the shape of a stolen token being tried.",
    severity: 1,
    score: 50,
    confidence: 0.75,
    origin: PACK,
    mitre: mitre("T1552.007", "T1552"),
    match: (event) => {
      const k8s = event.k8s;
      if (k8s?.subjectKind !== "serviceaccount" || k8s.resource !== "secrets") return null;
      if (k8s.decision === "forbid") return null;
      const home = k8s.subjectNamespace;
      const target = k8s.namespace;
      if (!home || !target || home === target) return null;
      return hit("k8s.subject", `${k8s.subject} -> ${target}/${k8s.objectName ?? "*"}`);
    },
  },
  {
    id: "AISOC-K8S-2104",
    name: "Detection control deleted",
    description:
      "A tracing policy, alert rule, network policy or admission policy was removed. Disabling the sensor is a step in the intrusion, not an accident.",
    severity: 1,
    score: 60,
    confidence: 0.8,
    origin: PACK,
    mitre: mitre("T1562", "T1070"),
    match: (event) => {
      const k8s = event.k8s;
      if (!k8s?.resource || !k8s.verb) return null;
      if (!DESTRUCTIVE_VERBS.has(k8s.verb)) return null;
      if (!DETECTION_RESOURCES.has(k8s.resource)) return null;
      return hit(
        "k8s.resource",
        `${k8s.verb} ${k8s.resource}/${k8s.objectName ?? "?"} by ${k8s.subject ?? "?"}`,
      );
    },
  },
  {
    id: "AISOC-K8S-2105",
    name: "Unauthenticated request accepted by the API server",
    description:
      "An anonymous caller was authorized. The cluster answers 401 to anonymous requests, so an allowed one means a binding grants it.",
    severity: 1,
    score: 55,
    confidence: 0.8,
    origin: PACK,
    mitre: mitre("T1078"),
    match: (event) => {
      const k8s = event.k8s;
      if (k8s?.subjectKind !== "anonymous") return null;
      if (k8s.decision === "forbid") return null;
      const code = k8s.responseCode ?? 0;
      if (code < 200 || code >= 300) return null;
      return hit("k8s.subject", `${k8s.verb ?? "?"} ${k8s.resource ?? "?"} allowed anonymously`);
    },
  },
  {
    id: "AISOC-K8S-2106",
    name: "Bootstrap identity used outside an infrastructure run",
    description:
      "The OpenTofu ServiceAccount mounts a cluster-admin kubeconfig on the run agent. Its use is expected during a plan or apply and suspicious at any other time.",
    severity: 1,
    score: 40,
    confidence: 0.6,
    origin: PACK,
    mitre: mitre("T1078.004"),
    match: (event) => {
      const subject = event.k8s?.subject ?? "";
      if (!subject.endsWith(":platform-bootstrap")) return null;
      const verb = event.k8s?.verb ?? "";
      if (verb === "get" || verb === "list" || verb === "watch") return null;
      return hit("k8s.subject", `${subject} ${verb} ${event.k8s?.resource ?? "?"}`);
    },
  },
];

export const RULE_COUNT = RULES.length;
