import type { IocType, MitreRef, RulePack, Severity } from "@aisoc/shared";
import { mitre } from "@aisoc/shared";

/**
 * Indicator feeds and the offline reputation set.
 *
 * These stand in for the subscription feeds a commercial sensor ships with
 * (abuse.ch, Spamhaus DROP, CINS, a vendor hash set). They are versioned like
 * real packs so the update view has something honest to report, and the
 * reputation table doubles as the geolocation source for the threat map when no
 * VirusTotal or AbuseIPDB key is configured.
 */

export const ENGINE_VERSION = "aisoc-engine/1.4.0";

export interface IocEntry {
  type: IocType;
  value: string;
  name: string;
  description: string;
  severity: Severity;
  confidence: number;
  score: number;
  origin: string;
  mitre: MitreRef[];
}

const C2_FEED = "abuse.ch feodotracker 2026.08.04";
const DROP_FEED = "spamhaus DROP 2026.08.03";
const HASH_FEED = "aisoc malware hashes 2026.07.29";
const DOMAIN_FEED = "aisoc dga+phish domains 2026.08.01";

export const IOCS: IocEntry[] = [
  {
    type: "ip",
    value: "45.155.205.233",
    name: "Cobalt Strike team server",
    description: "Listed as an active Cobalt Strike C2 by feodotracker for 11 days.",
    severity: 1,
    confidence: 0.95,
    score: 55,
    origin: C2_FEED,
    mitre: mitre("T1071.001", "T1573"),
  },
  {
    type: "ip",
    value: "185.220.101.34",
    name: "Tor exit node, repeat abuse",
    description: "Tor exit with a sustained credential-stuffing history against SSH and HTTP.",
    severity: 2,
    confidence: 0.8,
    score: 40,
    origin: DROP_FEED,
    mitre: mitre("T1090"),
  },
  {
    type: "ip",
    value: "193.35.18.77",
    name: "Bulletproof host, exfiltration sink",
    description: "Hosting provider with no abuse contact; observed receiving staged archives.",
    severity: 1,
    confidence: 0.88,
    score: 50,
    origin: DROP_FEED,
    mitre: mitre("T1048"),
  },
  {
    type: "ip",
    value: "103.108.229.14",
    name: "Mass scanner",
    description: "High-volume opportunistic scanner across 1433/3389/22.",
    severity: 3,
    confidence: 0.7,
    score: 25,
    origin: DROP_FEED,
    mitre: mitre("T1046"),
  },
  {
    type: "ip",
    value: "89.248.165.201",
    name: "Recon infrastructure",
    description: "Long-lived internet-wide scanning host.",
    severity: 3,
    confidence: 0.65,
    score: 22,
    origin: DROP_FEED,
    mitre: mitre("T1046"),
  },
  {
    type: "ip",
    value: "5.188.206.18",
    name: "Credential stuffing source",
    description: "Rotating proxy front observed replaying breached credential sets.",
    severity: 2,
    confidence: 0.82,
    score: 42,
    origin: DROP_FEED,
    mitre: mitre("T1110.004"),
  },
  {
    type: "ip",
    value: "91.243.59.120",
    name: "Ransomware affiliate staging host",
    description: "Distributes loaders and receives victim key material for a LockBit affiliate.",
    severity: 1,
    confidence: 0.93,
    score: 58,
    origin: C2_FEED,
    mitre: mitre("T1105", "T1486"),
  },
  {
    type: "domain",
    value: "cdn-telemetry-sync.net",
    name: "C2 domain masquerading as telemetry",
    description: "Registered 9 days ago, wildcard DNS, single ASN — classic disposable C2.",
    severity: 1,
    confidence: 0.9,
    score: 50,
    origin: DOMAIN_FEED,
    mitre: mitre("T1071.001", "T1568"),
  },
  {
    type: "domain",
    value: "kqxvbnrtplm.biz",
    name: "DGA domain",
    description: "Matches the character distribution of a known banker DGA family.",
    severity: 1,
    confidence: 0.85,
    score: 45,
    origin: DOMAIN_FEED,
    mitre: mitre("T1568.002", "T1071.004"),
  },
  {
    type: "domain",
    value: "secure-mail-verify.top",
    name: "Credential phishing domain",
    description: "Hosts a cloned webmail login harvesting corporate credentials.",
    severity: 2,
    confidence: 0.87,
    score: 44,
    origin: DOMAIN_FEED,
    mitre: mitre("T1110"),
  },
  {
    type: "hash",
    value: "9f2b7c4e1a86d35f0b7e4a2c9d81f6350a4e7b2c8d1f9a3e6b0c5d8f2a7e4b19",
    name: "LockBit-family encryptor",
    description: "Static hash of a LockBit 3.0 encryptor build seen in the wild since June.",
    severity: 1,
    confidence: 0.98,
    score: 60,
    origin: HASH_FEED,
    mitre: mitre("T1486", "T1490"),
  },
  {
    type: "hash",
    value: "3c8a1f6b0e5d29471c6a8f3b5d0e7c249a1b8f6d3e0c5a7b2f9d4e18c6b3a05f",
    name: "Cobalt Strike stageless beacon",
    description: "ELF beacon with a default Malleable C2 profile.",
    severity: 1,
    confidence: 0.94,
    score: 58,
    origin: HASH_FEED,
    mitre: mitre("T1071.001"),
  },
  {
    type: "hash",
    value: "7d1e4a90c3b62f85d0a7e1c4b9f36208d5a2c7e0b4f18d963a0c5e2b7f4a1d86",
    name: "Credential dumper",
    description: "Memory-scraping credential dumper packed with UPX.",
    severity: 1,
    confidence: 0.9,
    score: 52,
    origin: HASH_FEED,
    mitre: mitre("T1552", "T1027"),
  },
];

export interface ReputationRecord {
  country: string;
  countryCode: string;
  asn: string;
  lat: number;
  lon: number;
  /** 0–100, higher is worse. */
  score: number;
  malicious: number;
  total: number;
  firstSeen: string;
  detail: string;
}

/**
 * Offline reputation and geolocation. Real deployments replace this with
 * VirusTotal and AbuseIPDB; the console falls back here so the threat map and
 * enrichment panel work with no keys and no outbound calls.
 */
export const LOCAL_REPUTATION: Record<string, ReputationRecord> = {
  "45.155.205.233": {
    country: "Netherlands",
    countryCode: "NL",
    asn: "AS202425 IP Volume inc",
    lat: 52.3676,
    lon: 4.9041,
    score: 96,
    malicious: 47,
    total: 89,
    firstSeen: "2026-07-25T00:00:00.000Z",
    detail: "47/89 engines flag this address as a Cobalt Strike controller.",
  },
  "185.220.101.34": {
    country: "Germany",
    countryCode: "DE",
    asn: "AS205100 F3 Netze e.V.",
    lat: 50.1109,
    lon: 8.6821,
    score: 74,
    malicious: 21,
    total: 89,
    firstSeen: "2026-05-02T00:00:00.000Z",
    detail: "Tor exit node; 21/89 engines flag it, abuse confidence 74%.",
  },
  "193.35.18.77": {
    country: "Russia",
    countryCode: "RU",
    asn: "AS49505 Selectel",
    lat: 55.7558,
    lon: 37.6173,
    score: 88,
    malicious: 33,
    total: 89,
    firstSeen: "2026-06-14T00:00:00.000Z",
    detail: "Bulletproof hosting; repeated reports of receiving staged archives.",
  },
  "103.108.229.14": {
    country: "India",
    countryCode: "IN",
    asn: "AS132335 Ishan Netsol",
    lat: 19.076,
    lon: 72.8777,
    score: 61,
    malicious: 12,
    total: 89,
    firstSeen: "2026-03-19T00:00:00.000Z",
    detail: "Opportunistic scanner, 12/89 engines, abuse confidence 61%.",
  },
  "89.248.165.201": {
    country: "Netherlands",
    countryCode: "NL",
    asn: "AS202425 IP Volume inc",
    lat: 52.3676,
    lon: 4.9041,
    score: 58,
    malicious: 9,
    total: 89,
    firstSeen: "2026-01-08T00:00:00.000Z",
    detail: "Internet-wide scanning host operated by a research-branded network.",
  },
  "5.188.206.18": {
    country: "Bulgaria",
    countryCode: "BG",
    asn: "AS204601 SS-Net",
    lat: 42.6977,
    lon: 23.3219,
    score: 81,
    malicious: 26,
    total: 89,
    firstSeen: "2026-04-30T00:00:00.000Z",
    detail: "Rotating proxy front used for credential stuffing.",
  },
  "91.243.59.120": {
    country: "Ukraine",
    countryCode: "UA",
    asn: "AS204957 Solar Ltd",
    lat: 50.4501,
    lon: 30.5234,
    score: 94,
    malicious: 41,
    total: 89,
    firstSeen: "2026-07-11T00:00:00.000Z",
    detail: "Ransomware affiliate staging host, 41/89 engines.",
  },
  "142.250.185.78": {
    country: "United States",
    countryCode: "US",
    asn: "AS15169 Google LLC",
    lat: 37.4056,
    lon: -122.0775,
    score: 0,
    malicious: 0,
    total: 89,
    firstSeen: "2015-01-01T00:00:00.000Z",
    detail: "Google frontend. No engine flags this address.",
  },
  "13.107.42.14": {
    country: "United States",
    countryCode: "US",
    asn: "AS8075 Microsoft Corporation",
    lat: 47.6062,
    lon: -122.3321,
    score: 0,
    malicious: 0,
    total: 89,
    firstSeen: "2016-01-01T00:00:00.000Z",
    detail: "Microsoft edge network. Clean.",
  },
  "151.101.1.140": {
    country: "United States",
    countryCode: "US",
    asn: "AS54113 Fastly",
    lat: 37.7749,
    lon: -122.4194,
    score: 0,
    malicious: 0,
    total: 89,
    firstSeen: "2016-01-01T00:00:00.000Z",
    detail: "Fastly CDN edge. Clean.",
  },
  "149.154.166.110": {
    country: "United Kingdom",
    countryCode: "GB",
    asn: "AS62041 Telegram Messenger",
    lat: 51.5074,
    lon: -0.1278,
    score: 0,
    malicious: 0,
    total: 89,
    firstSeen: "2017-01-01T00:00:00.000Z",
    detail: "Telegram API frontend — this console's own alerting path.",
  },
  "104.18.32.47": {
    country: "United States",
    countryCode: "US",
    asn: "AS13335 Cloudflare",
    lat: 37.7749,
    lon: -122.4194,
    score: 0,
    malicious: 0,
    total: 89,
    firstSeen: "2015-01-01T00:00:00.000Z",
    detail: "Cloudflare edge. Clean.",
  },
  "52.94.236.248": {
    country: "United States",
    countryCode: "US",
    asn: "AS16509 Amazon.com",
    lat: 39.0438,
    lon: -77.4874,
    score: 3,
    malicious: 0,
    total: 89,
    firstSeen: "2015-01-01T00:00:00.000Z",
    detail: "AWS us-east-1. Clean, though shared infrastructure.",
  },
};

const IOC_INDEX = new Map<string, IocEntry>(
  IOCS.map((entry) => [`${entry.type}:${entry.value.toLowerCase()}`, entry]),
);

export function lookupIoc(type: IocType, value: string): IocEntry | undefined {
  return IOC_INDEX.get(`${type}:${value.toLowerCase()}`);
}

/**
 * Domain indicators match the registrable suffix too, so `login.kqxvbnrtplm.biz`
 * hits the feed entry for `kqxvbnrtplm.biz`.
 */
export function lookupDomain(hostname: string): IocEntry | undefined {
  const lower = hostname.toLowerCase().replace(/\.$/, "");
  const direct = lookupIoc("domain", lower);
  if (direct) return direct;
  const labels = lower.split(".");
  for (let i = 1; i < labels.length - 1; i += 1) {
    const suffix = labels.slice(i).join(".");
    const hit = lookupIoc("domain", suffix);
    if (hit) return hit;
  }
  return undefined;
}

export function reputationFor(ip: string): ReputationRecord | undefined {
  return LOCAL_REPUTATION[ip];
}

const iocCount = (type: IocType): number => IOCS.filter((entry) => entry.type === type).length;

/** Advertised pack inventory, shown and refreshed from the update view. */
export function defaultRulePacks(ruleCount: number, techniqueCount: number): RulePack[] {
  const updatedAt = "2026-08-04T06:00:00.000Z";
  return [
    {
      id: "pack-core-rules",
      name: "AI SOC core detection rules",
      kind: "rules",
      version: "2026.08.4",
      entries: ruleCount,
      updatedAt,
      enabled: true,
      origin: "bundled",
    },
    {
      id: "pack-ioc-c2",
      name: "C2 infrastructure indicators",
      kind: "ioc",
      version: "2026.08.4",
      entries: iocCount("ip") + iocCount("domain"),
      updatedAt,
      enabled: true,
      origin: C2_FEED,
    },
    {
      id: "pack-ioc-hash",
      name: "Malware hash set",
      kind: "ioc",
      version: "2026.07.29",
      entries: iocCount("hash"),
      updatedAt: "2026-07-29T06:00:00.000Z",
      enabled: true,
      origin: HASH_FEED,
    },
    {
      id: "pack-mitre",
      name: "MITRE ATT&CK Enterprise mapping",
      kind: "mitre",
      version: "v16.1",
      entries: techniqueCount,
      updatedAt: "2026-04-22T00:00:00.000Z",
      enabled: true,
      origin: "attack.mitre.org",
    },
  ];
}
