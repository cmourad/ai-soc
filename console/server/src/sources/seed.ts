import { randomUUID } from "node:crypto";
import type { Protocol, SecurityEvent, Severity } from "@aisoc/shared";
import { instantiate, SCENARIOS, type Scenario } from "./scenarios.js";

type Template = {
  signature: string;
  signatureId: number;
  category: string;
  severity: Severity;
  proto: Protocol;
  destPort: number;
  appProto?: string;
  tags: string[];
  weight: number;
  /** Suricata's flow direction; only response-style signatures fire to_client. */
  direction?: "to_server" | "to_client";
  sni?: string[];
  url?: string[];
  userAgent?: string[];
};

/** Signatures and categories mirror the ET Open ruleset the Suricata sensor loads. */
const TEMPLATES: Template[] = [
  {
    signature: "ET HUNTING Observed Telegram API Domain (api .telegram .org in TLS SNI)",
    signatureId: 2033967,
    category: "Misc activity",
    severity: 3,
    proto: "TCP",
    destPort: 443,
    appProto: "tls",
    tags: ["tls", "sni", "informational"],
    weight: 18,
    sni: ["api.telegram.org"],
  },
  {
    signature: "ET INFO Observed DNS Query to Cloud Storage Domain (s3 .amazonaws .com)",
    signatureId: 2027758,
    category: "Misc activity",
    severity: 4,
    proto: "UDP",
    destPort: 53,
    appProto: "dns",
    tags: ["dns", "cloud", "informational"],
    weight: 22,
  },
  {
    signature: "ET INFO TLS Handshake Observed to Content Delivery Network",
    signatureId: 2029001,
    category: "Not Suspicious Traffic",
    severity: 4,
    proto: "TCP",
    destPort: 443,
    appProto: "tls",
    tags: ["tls", "cdn"],
    weight: 24,
    sni: ["cloudfront.net", "fastly.net", "akamaized.net", "cdn.jsdelivr.net"],
  },
  {
    signature: "ET SCAN Potential SSH Scan OUTBOUND",
    signatureId: 2003068,
    category: "Attempted Information Leak",
    severity: 2,
    proto: "TCP",
    destPort: 22,
    tags: ["scan", "ssh", "recon"],
    weight: 8,
  },
  {
    signature: "ET SCAN Suspicious inbound to MSSQL port 1433",
    signatureId: 2010935,
    category: "Potentially Bad Traffic",
    severity: 3,
    proto: "TCP",
    destPort: 1433,
    tags: ["scan", "database", "recon"],
    weight: 7,
  },
  {
    signature: "GPL ATTACK_RESPONSE id check returned root",
    signatureId: 2100498,
    category: "Potentially Bad Traffic",
    severity: 2,
    proto: "TCP",
    destPort: 80,
    appProto: "http",
    tags: ["exploit", "response", "http"],
    weight: 5,
    direction: "to_client",
    url: ["/uid/index.html", "/cgi-bin/status"],
    userAgent: ["curl/8.5.0"],
  },
  {
    signature: "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT",
    signatureId: 2006446,
    category: "Web Application Attack",
    severity: 1,
    proto: "TCP",
    destPort: 80,
    appProto: "http",
    tags: ["sqli", "web", "exploit"],
    weight: 4,
    url: ["/products.php?id=1' UNION SELECT null,version()--", "/search?q=%27+UNION+SELECT"],
    userAgent: ["sqlmap/1.8#stable", "Mozilla/5.0 (compatible; Nmap Scripting Engine)"],
  },
  {
    signature: "ET EXPLOIT Apache Struts OGNL Injection (CVE-2017-5638)",
    signatureId: 2024188,
    category: "Attempted Administrator Privilege Gain",
    severity: 1,
    proto: "TCP",
    destPort: 8080,
    appProto: "http",
    tags: ["cve-2017-5638", "rce", "struts", "exploit"],
    weight: 3,
    url: ["/struts2-showcase/index.action"],
    userAgent: ["%{(#_='multipart/form-data')...}"],
  },
  {
    signature: "ET DROP Spamhaus DROP Listed Traffic Inbound",
    signatureId: 2400000,
    category: "Misc Attack",
    severity: 2,
    proto: "TCP",
    destPort: 445,
    tags: ["reputation", "spamhaus", "autoblock"],
    weight: 4,
  },
  {
    signature: "ET CINS Active Threat Intelligence Poor Reputation IP group 42",
    signatureId: 2403341,
    category: "Misc Attack",
    severity: 2,
    proto: "TCP",
    destPort: 23,
    tags: ["reputation", "cins", "autoblock"],
    weight: 4,
  },
  {
    signature: "ET MALWARE Cobalt Strike Beacon Observed (HTTP GET)",
    signatureId: 2028094,
    category: "Malware Command and Control Activity Detected",
    severity: 1,
    proto: "TCP",
    destPort: 443,
    appProto: "http",
    tags: ["c2", "cobaltstrike", "malware"],
    weight: 2,
    url: ["/pixel.gif", "/submit.php?id=8934721"],
    userAgent: ["Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"],
  },
  {
    signature: "ET TROJAN Observed DNS Query to DGA Domain",
    signatureId: 2027847,
    category: "A Network Trojan was Detected",
    severity: 1,
    proto: "UDP",
    destPort: 53,
    appProto: "dns",
    tags: ["dga", "trojan", "dns"],
    weight: 2,
  },
  {
    signature: "ET POLICY Cleartext Credentials Observed over HTTP POST",
    signatureId: 2012887,
    category: "Potential Corporate Privacy Violation",
    severity: 3,
    proto: "TCP",
    destPort: 80,
    appProto: "http",
    tags: ["policy", "credentials", "cleartext"],
    weight: 5,
    url: ["/login"],
  },
];

const HOSTILE_IPS = [
  "45.155.205.233",
  "185.220.101.34",
  "193.35.18.77",
  "103.108.229.14",
  "89.248.165.201",
  "5.188.206.18",
];

const BENIGN_IPS = [
  "142.250.185.78",
  "13.107.42.14",
  "151.101.1.140",
  "149.154.166.110",
  "104.18.32.47",
  "52.94.236.248",
];

const LOCAL_IPS = ["192.0.2.9", "192.0.2.14", "192.0.2.32"];

const DGA_DOMAINS = ["kqxvbnrtplm.biz", "wzjfhdqoprs.info", "mnbvcxzlkjh.top", "qplwoskdjfh.xyz"];

function pick<T>(list: readonly T[]): T {
  return list[Math.floor(Math.random() * list.length)]!;
}

function weightedTemplate(): Template {
  const total = TEMPLATES.reduce((sum, t) => sum + t.weight, 0);
  let roll = Math.random() * total;
  for (const template of TEMPLATES) {
    roll -= template.weight;
    if (roll <= 0) return template;
  }
  return TEMPLATES[0]!;
}

function makeEvent(): SecurityEvent {
  const template = weightedTemplate();
  const hostile = template.severity <= 2;
  const inbound = hostile && Math.random() < 0.7;
  const remote = pick(hostile ? HOSTILE_IPS : BENIGN_IPS);
  const local = pick(LOCAL_IPS);

  const event: SecurityEvent = {
    id: randomUUID(),
    ts: new Date().toISOString(),
    srcIp: inbound ? remote : local,
    srcPort: inbound
      ? 1024 + Math.floor(Math.random() * 64_000)
      : 32_768 + Math.floor(Math.random() * 28_000),
    destIp: inbound ? local : remote,
    destPort: template.destPort,
    proto: template.proto,
    appProto: template.appProto,
    signature: template.signature,
    signatureId: template.signatureId,
    category: template.category,
    severity: template.severity,
    tags: template.tags,
    direction: template.direction ?? "to_server",
    bytesToServer: 200 + Math.floor(Math.random() * 40_000),
    bytesToClient: 200 + Math.floor(Math.random() * 90_000),
    source: "seed",
  };

  if (template.sni) event.sni = pick(template.sni);
  if (template.url) event.url = pick(template.url);
  if (template.userAgent) event.userAgent = pick(template.userAgent);
  if (template.tags.includes("dga")) event.hostname = pick(DGA_DOMAINS);

  return event;
}

function weightedScenario(): Scenario {
  const total = SCENARIOS.reduce((sum, scenario) => sum + scenario.weight, 0);
  let roll = Math.random() * total;
  for (const scenario of SCENARIOS) {
    roll -= scenario.weight;
    if (roll <= 0) return scenario;
  }
  return SCENARIOS[0]!;
}

/**
 * Poisson-ish emitter: a fixed tick with a per-tick probability derived from the
 * configured rate, so the stream bursts and lulls like real traffic instead of
 * arriving on a metronome.
 *
 * Layered on top is a scenario scheduler. Background noise alone can never
 * exercise the behavioural heuristics or incident correlation, because both are
 * about the shape across ordered events — so a scripted attack runs periodically
 * against the seeded estate, and one runs shortly after startup so the console
 * has something to show immediately.
 */
export function startSeedSource(
  rate: () => number,
  paused: () => boolean,
  emit: (event: SecurityEvent) => void,
): () => void {
  const TICK_MS = 200;
  const pending: NodeJS.Timeout[] = [];

  const runScenario = (scenario: Scenario): void => {
    for (const { delayMs, event } of instantiate(scenario)) {
      pending.push(
        setTimeout(() => {
          if (!paused()) emit(event);
        }, delayMs),
      );
    }
  };

  const timer = setInterval(() => {
    if (paused()) return;
    const expected = (rate() * TICK_MS) / 1000;
    let count = Math.floor(expected);
    if (Math.random() < expected - count) count += 1;
    // Occasional burst — a scan or a beacon check-in cluster.
    if (Math.random() < 0.02) count += 2 + Math.floor(Math.random() * 4);
    for (let i = 0; i < count; i += 1) emit(makeEvent());
  }, TICK_MS);

  const firstRun = setTimeout(() => runScenario(weightedScenario()), 4_000);
  const scenarioTimer = setInterval(() => {
    if (paused()) return;
    runScenario(weightedScenario());
  }, 150_000);

  return () => {
    clearInterval(timer);
    clearInterval(scenarioTimer);
    clearTimeout(firstRun);
    for (const handle of pending) clearTimeout(handle);
  };
}

/** Runs one named scenario immediately; the console exposes this as a drill. */
export function fireScenario(id: string, emit: (event: SecurityEvent) => void): Scenario | null {
  const scenario = SCENARIOS.find((entry) => entry.id === id);
  if (!scenario) return null;
  for (const { delayMs, event } of instantiate(scenario)) {
    setTimeout(() => emit(event), delayMs);
  }
  return scenario;
}
