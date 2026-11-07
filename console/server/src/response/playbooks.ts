import type { Playbook } from "@aisoc/shared";

/**
 * Multi-step containment sequences. A playbook is chosen by the detection
 * layer's rule ids and tags — never by the model alone — so what runs is a
 * function of evidence, not of prose. The model may recommend one; a human or
 * the autonomy setting decides whether it fires.
 */
export const DEFAULT_PLAYBOOKS: Playbook[] = [
  {
    id: "pb-c2-containment",
    name: "C2 containment",
    description:
      "Cut the channel first, then take the process and the host out of the attacker's reach.",
    triggerRuleIds: ["AISOC-C2-0001", "AISOC-C2-0002", "AISOC-C2-0003", "AISOC-BEH-BEACON"],
    triggerTags: ["c2", "cobaltstrike", "beacon"],
    minScore: 55,
    steps: [
      {
        type: "block_ip",
        targetFrom: "remote_ip",
        reason: "Sever the beacon's route to its controller.",
      },
      {
        type: "block_domain",
        targetFrom: "hostname",
        reason: "Deny the fallback name so a new A record does not restore the channel.",
      },
      {
        type: "kill_process",
        targetFrom: "process",
        reason: "Stop the implant that is checking in.",
      },
    ],
    enabled: true,
  },
  {
    id: "pb-ransomware",
    name: "Ransomware containment",
    description:
      "Isolation comes first — every second of network access is more files encrypted and more shares reached.",
    triggerRuleIds: ["AISOC-IMP-0001", "AISOC-IMP-0002", "AISOC-IMP-0003", "AISOC-BEH-MASSWRITE"],
    triggerTags: ["ransomware", "encryptor"],
    minScore: 60,
    steps: [
      {
        type: "isolate_host",
        targetFrom: "asset",
        reason: "Stop lateral spread and cut the encryptor off from network shares.",
      },
      {
        type: "kill_process",
        targetFrom: "process",
        reason: "Halt the encryptor mid-run to preserve the files it has not reached.",
      },
      {
        type: "quarantine_file",
        targetFrom: "file_path",
        reason: "Preserve the sample for analysis and stop it being re-executed.",
      },
      {
        type: "block_ip",
        targetFrom: "remote_ip",
        reason: "Deny the key-exchange endpoint.",
      },
    ],
    enabled: true,
  },
  {
    id: "pb-exfil",
    name: "Exfiltration containment",
    description: "Close the egress path and preserve the staged archive as evidence.",
    triggerRuleIds: ["AISOC-EXFIL-0001", "AISOC-EXFIL-0002", "AISOC-BEH-EXFIL", "AISOC-C2-0004"],
    triggerTags: ["exfil", "dns-tunnel"],
    minScore: 50,
    steps: [
      {
        type: "block_ip",
        targetFrom: "remote_ip",
        reason: "Close the destination the data is leaving through.",
      },
      {
        type: "quarantine_file",
        targetFrom: "file_path",
        reason: "Hold the staged archive so its contents can be established.",
      },
    ],
    enabled: true,
  },
  {
    id: "pb-credential-attack",
    name: "Credential attack containment",
    description: "Block the source before the attempt list runs out and one of them lands.",
    triggerRuleIds: ["AISOC-CRED-0002", "AISOC-BEH-STUFF", "AISOC-CRED-0003"],
    triggerTags: ["bruteforce", "credentials"],
    minScore: 40,
    steps: [
      {
        type: "block_ip",
        targetFrom: "remote_ip",
        reason: "Stop the attempt stream at the perimeter.",
      },
    ],
    enabled: true,
  },
];
