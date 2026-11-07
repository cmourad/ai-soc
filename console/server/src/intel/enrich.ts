import type { Enrichment, IntelSource, IocType, SecurityEvent } from "@aisoc/shared";
import { getSecret } from "../crypto.js";
import { isLocal, remoteIp } from "../detect/engine.js";
import { lookupDomain, lookupIoc, reputationFor } from "../detect/feeds.js";
import { getSettings } from "../settings.js";
import { geolocate } from "./geo.js";

/**
 * Reputation lookup for the remote indicator on an alert.
 *
 * Providers are optional and additive: with no API keys configured the bundled
 * offline set still supplies country, ASN, and a reputation figure, so the
 * enrichment panel and threat map are never empty and no outbound request is
 * made from a machine that may be compromised. When keys are present, the live
 * verdicts are merged in and the worst score wins.
 */

type CacheEntry = { at: number; value: Enrichment };
const cache = new Map<string, CacheEntry>();

/** The indicator worth looking up: a hostname if we have one, else the remote IP. */
export function indicatorFor(event: SecurityEvent): { value: string; type: IocType } | null {
  const host = event.sni ?? event.hostname;
  if (host && /[a-z]/i.test(host)) return { value: host.replace(/\.$/, ""), type: "domain" };
  const ip = remoteIp(event);
  if (!ip || isLocal(ip)) return null;
  return { value: ip, type: "ip" };
}

function localSource(value: string, type: IocType): IntelSource {
  const record = type === "ip" ? reputationFor(value) : undefined;
  if (record) {
    return {
      provider: "local",
      ok: true,
      score: record.score,
      detail: record.detail,
      malicious: record.malicious,
      total: record.total,
      error: null,
    };
  }
  const ioc = type === "domain" ? lookupDomain(value) : lookupIoc(type, value);
  if (ioc) {
    return {
      provider: "local",
      ok: true,
      score: Math.round(ioc.confidence * 100),
      detail: ioc.description,
      malicious: null,
      total: null,
      error: null,
    };
  }
  return {
    provider: "local",
    ok: true,
    score: null,
    detail: "No entry in the bundled reputation set.",
    malicious: null,
    total: null,
    error: null,
  };
}

async function virusTotal(value: string, type: IocType, key: string): Promise<IntelSource> {
  const path = type === "domain" ? `domains/${value}` : `ip_addresses/${value}`;
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/${path}`, {
      headers: { "x-apikey": key },
      signal: AbortSignal.timeout(8_000),
    });
    if (!response.ok) {
      return {
        provider: "virustotal",
        ok: false,
        score: null,
        detail: "",
        malicious: null,
        total: null,
        error: `${response.status} ${response.statusText}`,
      };
    }
    const body = (await response.json()) as {
      data?: { attributes?: { last_analysis_stats?: Record<string, number> } };
    };
    const stats = body.data?.attributes?.last_analysis_stats ?? {};
    const malicious = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
    const total = Object.values(stats).reduce((sum, count) => sum + count, 0);
    return {
      provider: "virustotal",
      ok: true,
      score: total > 0 ? Math.round((malicious / total) * 100) : 0,
      detail: `${malicious}/${total} engines flag this indicator.`,
      malicious,
      total,
      error: null,
    };
  } catch (error) {
    return {
      provider: "virustotal",
      ok: false,
      score: null,
      detail: "",
      malicious: null,
      total: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

async function abuseIpdb(value: string, key: string): Promise<IntelSource> {
  try {
    const url = new URL("https://api.abuseipdb.com/api/v2/check");
    url.searchParams.set("ipAddress", value);
    url.searchParams.set("maxAgeInDays", "90");
    const response = await fetch(url, {
      headers: { key, accept: "application/json" },
      signal: AbortSignal.timeout(8_000),
    });
    if (!response.ok) {
      return {
        provider: "abuseipdb",
        ok: false,
        score: null,
        detail: "",
        malicious: null,
        total: null,
        error: `${response.status} ${response.statusText}`,
      };
    }
    const body = (await response.json()) as {
      data?: { abuseConfidenceScore?: number; totalReports?: number; countryCode?: string };
    };
    const score = body.data?.abuseConfidenceScore ?? 0;
    return {
      provider: "abuseipdb",
      ok: true,
      score,
      detail: `Abuse confidence ${score}% from ${body.data?.totalReports ?? 0} reports.`,
      malicious: body.data?.totalReports ?? null,
      total: null,
      error: null,
    };
  } catch (error) {
    return {
      provider: "abuseipdb",
      ok: false,
      score: null,
      detail: "",
      malicious: null,
      total: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function enrich(event: SecurityEvent): Promise<Enrichment | null> {
  const settings = getSettings();
  if (!settings.intel.enabled) return null;
  const indicator = indicatorFor(event);
  if (!indicator) return null;

  const key = `${indicator.type}:${indicator.value.toLowerCase()}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < settings.intel.cacheMinutes * 60_000) {
    return { ...hit.value, cached: true };
  }

  const sources: IntelSource[] = [];
  if (settings.intel.useLocalFeed) sources.push(localSource(indicator.value, indicator.type));

  const vtKey = getSecret(settings.intel.virusTotalSecret);
  const abuseKey = getSecret(settings.intel.abuseIpdbSecret);
  const live = await Promise.all([
    vtKey ? virusTotal(indicator.value, indicator.type, vtKey) : null,
    abuseKey && indicator.type === "ip" ? abuseIpdb(indicator.value, abuseKey) : null,
  ]);
  for (const source of live) if (source) sources.push(source);

  const geo = indicator.type === "ip" ? reputationFor(indicator.value) : undefined;
  // The reputation set knows a city for the handful of addresses it tracks; the
  // delegation table knows a country for nearly every other one. Prefer the
  // former where it exists and fall back rather than leaving the map empty.
  const delegated = indicator.type === "ip" ? geolocate(indicator.value) : null;
  const scores = sources
    .map((source) => source.score)
    .filter((score): score is number => score !== null);

  const value: Enrichment = {
    indicator: indicator.value,
    type: indicator.type,
    reputation: scores.length > 0 ? Math.max(...scores) : 0,
    sources,
    country: geo?.country ?? delegated?.country ?? null,
    countryCode: geo?.countryCode ?? delegated?.countryCode ?? null,
    asn: geo?.asn ?? delegated?.asn ?? null,
    organization: delegated?.organization ?? null,
    lat: geo?.lat ?? delegated?.lat ?? null,
    lon: geo?.lon ?? delegated?.lon ?? null,
    firstSeen: geo?.firstSeen ?? null,
    fetchedAt: new Date().toISOString(),
    cached: false,
  };

  cache.set(key, { at: Date.now(), value });
  return value;
}
