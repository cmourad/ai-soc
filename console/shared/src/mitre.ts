import type { MitreRef } from "./types.js";

/**
 * The slice of ATT&CK Enterprise this console can actually justify from network
 * and host telemetry. Keeping it small and curated is deliberate: a mapping that
 * claims a technique the evidence does not support is worse than no mapping.
 */
const TACTICS: Record<string, string> = {
  TA0001: "Initial Access",
  TA0002: "Execution",
  TA0003: "Persistence",
  TA0004: "Privilege Escalation",
  TA0005: "Defense Evasion",
  TA0006: "Credential Access",
  TA0007: "Discovery",
  TA0008: "Lateral Movement",
  TA0009: "Collection",
  TA0010: "Exfiltration",
  TA0011: "Command and Control",
  TA0040: "Impact",
};

type Technique = { id: string; name: string; tactic: keyof typeof TACTICS };

const TECHNIQUES: Technique[] = [
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "TA0001" },
  { id: "T1133", name: "External Remote Services", tactic: "TA0001" },
  { id: "T1059", name: "Command and Scripting Interpreter", tactic: "TA0002" },
  { id: "T1059.004", name: "Unix Shell", tactic: "TA0002" },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "TA0003" },
  { id: "T1505", name: "Server Software Component", tactic: "TA0003" },
  { id: "T1609", name: "Container Administration Command", tactic: "TA0002" },
  { id: "T1610", name: "Deploy Container", tactic: "TA0002" },
  { id: "T1543", name: "Create or Modify System Process", tactic: "TA0003" },
  { id: "T1098", name: "Account Manipulation", tactic: "TA0003" },
  { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "TA0004" },
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "TA0004" },
  { id: "T1611", name: "Escape to Host", tactic: "TA0004" },
  { id: "T1078", name: "Valid Accounts", tactic: "TA0004" },
  { id: "T1078.004", name: "Cloud Accounts", tactic: "TA0004" },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "TA0005" },
  { id: "T1070", name: "Indicator Removal", tactic: "TA0005" },
  { id: "T1562", name: "Impair Defenses", tactic: "TA0005" },
  { id: "T1110", name: "Brute Force", tactic: "TA0006" },
  { id: "T1110.004", name: "Credential Stuffing", tactic: "TA0006" },
  { id: "T1552", name: "Unsecured Credentials", tactic: "TA0006" },
  { id: "T1552.007", name: "Container API", tactic: "TA0006" },
  { id: "T1040", name: "Network Sniffing", tactic: "TA0006" },
  { id: "T1046", name: "Network Service Discovery", tactic: "TA0007" },
  { id: "T1613", name: "Container and Resource Discovery", tactic: "TA0007" },
  { id: "T1018", name: "Remote System Discovery", tactic: "TA0007" },
  { id: "T1021", name: "Remote Services", tactic: "TA0008" },
  { id: "T1021.004", name: "SSH", tactic: "TA0008" },
  { id: "T1005", name: "Data from Local System", tactic: "TA0009" },
  { id: "T1560", name: "Archive Collected Data", tactic: "TA0009" },
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "TA0010" },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "TA0010" },
  { id: "T1567", name: "Exfiltration Over Web Service", tactic: "TA0010" },
  { id: "T1071", name: "Application Layer Protocol", tactic: "TA0011" },
  { id: "T1071.001", name: "Web Protocols", tactic: "TA0011" },
  { id: "T1071.004", name: "DNS", tactic: "TA0011" },
  { id: "T1568", name: "Dynamic Resolution", tactic: "TA0011" },
  { id: "T1568.002", name: "Domain Generation Algorithms", tactic: "TA0011" },
  { id: "T1573", name: "Encrypted Channel", tactic: "TA0011" },
  { id: "T1105", name: "Ingress Tool Transfer", tactic: "TA0011" },
  { id: "T1090", name: "Proxy", tactic: "TA0011" },
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "TA0040" },
  { id: "T1496", name: "Resource Hijacking", tactic: "TA0040" },
  { id: "T1490", name: "Inhibit System Recovery", tactic: "TA0040" },
  { id: "T1498", name: "Network Denial of Service", tactic: "TA0040" },
];

const BY_ID = new Map(TECHNIQUES.map((technique) => [technique.id, technique]));

/** Resolves technique ids to full refs, dropping any the catalogue does not know. */
export function mitre(...techniqueIds: string[]): MitreRef[] {
  const out: MitreRef[] = [];
  for (const id of techniqueIds) {
    const technique = BY_ID.get(id);
    if (!technique) continue;
    out.push({
      tacticId: technique.tactic,
      tactic: TACTICS[technique.tactic]!,
      techniqueId: technique.id,
      technique: technique.name,
    });
  }
  return out;
}

export function dedupeMitre(refs: MitreRef[]): MitreRef[] {
  const seen = new Map<string, MitreRef>();
  for (const ref of refs) seen.set(ref.techniqueId, ref);
  return [...seen.values()].sort((a, b) => a.techniqueId.localeCompare(b.techniqueId));
}

/** Tactic order for the ATT&CK matrix strip, left to right as the kill chain runs. */
export const TACTIC_ORDER: { id: string; name: string }[] = Object.entries(TACTICS).map(
  ([id, name]) => ({ id, name }),
);

export const MITRE_TECHNIQUE_COUNT = TECHNIQUES.length;
