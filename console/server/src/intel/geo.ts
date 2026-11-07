import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Offline IP attribution over a bundled snapshot of routed IPv4 and IPv6 space.
 *
 * This exists so the threat map has something to draw on a network that is not
 * under attack from a demo scenario. Resolving locally means a
 * possibly-compromised host never announces its traffic to a geolocation or
 * ASN API.
 */

export interface GeoLocation {
  countryCode: string | null;
  country: string | null;
  lat: number | null;
  lon: number | null;
  asn: string | null;
  organization: string | null;
}

const TABLE = join(dirname(fileURLToPath(import.meta.url)), "geo-table.txt");
const MASK_64 = (1n << 64n) - 1n;

interface Ranges32 {
  starts: Uint32Array;
  ends: Uint32Array;
}

interface Ranges128 {
  startHigh: BigUint64Array;
  startLow: BigUint64Array;
  endHigh: BigUint64Array;
  endLow: BigUint64Array;
}

interface Table {
  country4: Ranges32 & { codes: string };
  country6: Ranges128 & { codes: string };
  asn4: Ranges32 & { asns: Uint32Array };
  asn6: Ranges128 & { asns: Uint32Array };
  countries: Record<string, { name: string; lat: number; lon: number }>;
  organizations: string[];
}

/** Read and decoded on first lookup so startup does not pay for unused intel. */
let table: Table | null = null;

function base36BigInt(value: string): bigint {
  let result = 0n;
  for (const char of value) {
    const digit = BigInt(Number.parseInt(char, 36));
    result = result * 36n + digit;
  }
  return result;
}

function decodeAsns(line: string, count: number): Uint32Array {
  const encoded = line.split(" ");
  if (encoded.length !== count) throw new Error("invalid IP intelligence ASN table");
  const values = new Uint32Array(count);
  for (let index = 0; index < count; index += 1) {
    values[index] = Number.parseInt(encoded[index]!, 36);
  }
  return values;
}

function decode32(startLine: string, lengthLine: string): Ranges32 {
  const deltas = startLine.split(" ");
  const lengths = lengthLine.split(" ");
  if (deltas.length !== lengths.length) {
    throw new Error("invalid IPv4 intelligence table");
  }
  const starts = new Uint32Array(deltas.length);
  const ends = new Uint32Array(deltas.length);
  let cursor = 0;
  for (let index = 0; index < deltas.length; index += 1) {
    const start = cursor + Number.parseInt(deltas[index]!, 36);
    const end = start + Number.parseInt(lengths[index]!, 36) - 1;
    starts[index] = start;
    ends[index] = end;
    cursor = end + 1;
  }
  return { starts, ends };
}

function decode128(startLine: string, lengthLine: string): Ranges128 {
  const deltas = startLine.split(" ");
  const lengths = lengthLine.split(" ");
  if (deltas.length !== lengths.length) {
    throw new Error("invalid IPv6 intelligence table");
  }
  const startHigh = new BigUint64Array(deltas.length);
  const startLow = new BigUint64Array(deltas.length);
  const endHigh = new BigUint64Array(deltas.length);
  const endLow = new BigUint64Array(deltas.length);
  let cursor = 0n;
  for (let index = 0; index < deltas.length; index += 1) {
    const start = cursor + base36BigInt(deltas[index]!);
    const end = start + base36BigInt(lengths[index]!) - 1n;
    startHigh[index] = start >> 64n;
    startLow[index] = start & MASK_64;
    endHigh[index] = end >> 64n;
    endLow[index] = end & MASK_64;
    cursor = end + 1n;
  }
  return {
    startHigh,
    startLow,
    endHigh,
    endLow,
  };
}

function load(): Table {
  const lines = readFileSync(TABLE, "utf8").trimEnd().split("\n");
  if (lines[0] !== "aisoc-ip-intel-v2" || lines.length !== 15) {
    throw new Error("unsupported IP intelligence table");
  }
  const country4 = decode32(lines[1]!, lines[2]!);
  const country6 = decode128(lines[4]!, lines[5]!);
  const asn4 = decode32(lines[7]!, lines[8]!);
  const asn6 = decode128(lines[10]!, lines[11]!);
  return {
    // Copy the two retained slices so V8 can release the 13 MiB source string.
    country4: { ...country4, codes: Buffer.from(lines[3]!, "ascii").toString("ascii") },
    country6: { ...country6, codes: Buffer.from(lines[6]!, "ascii").toString("ascii") },
    asn4: { ...asn4, asns: decodeAsns(lines[9]!, asn4.starts.length) },
    asn6: { ...asn6, asns: decodeAsns(lines[12]!, asn6.startHigh.length) },
    countries: JSON.parse(lines[13]!),
    organizations: JSON.parse(lines[14]!),
  };
}

export function toUint32(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

export function toUint128(ip: string): bigint | null {
  if (!ip.includes(":") || ip.includes("%")) return null;
  let value = ip;
  const lastColon = value.lastIndexOf(":");
  const tail = value.slice(lastColon + 1);
  if (tail.includes(".")) {
    const ipv4 = toUint32(tail);
    if (ipv4 === null) return null;
    value = `${value.slice(0, lastColon)}:${(ipv4 >>> 16).toString(16)}:${(ipv4 & 0xffff).toString(16)}`;
  }

  const halves = value.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const words = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/i.test(word))) return null;

  let result = 0n;
  for (const word of words) result = (result << 16n) | BigInt(Number.parseInt(word, 16));
  return result;
}

function find32(value: number, ranges: Ranges32): number {
  let low = 0;
  let high = ranges.starts.length - 1;
  while (low <= high) {
    const mid = (low + high) >>> 1;
    if (value < ranges.starts[mid]!) high = mid - 1;
    else if (value > ranges.ends[mid]!) low = mid + 1;
    else return mid;
  }
  return -1;
}

function compare128(high: bigint, low: bigint, otherHigh: bigint, otherLow: bigint): number {
  if (high !== otherHigh) return high < otherHigh ? -1 : 1;
  if (low === otherLow) return 0;
  return low < otherLow ? -1 : 1;
}

function find128(value: bigint, ranges: Ranges128): number {
  const highValue = value >> 64n;
  const lowValue = value & MASK_64;
  let low = 0;
  let high = ranges.startHigh.length - 1;
  while (low <= high) {
    const mid = (low + high) >>> 1;
    if (compare128(highValue, lowValue, ranges.startHigh[mid]!, ranges.startLow[mid]!) < 0) {
      high = mid - 1;
    } else if (compare128(highValue, lowValue, ranges.endHigh[mid]!, ranges.endLow[mid]!) > 0) {
      low = mid + 1;
    } else {
      return mid;
    }
  }
  return -1;
}

export function geolocate(ip: string): GeoLocation | null {
  const ipv4 = toUint32(ip);
  const ipv6 = ipv4 === null ? toUint128(ip) : null;
  if (ipv4 === null && ipv6 === null) return null;
  table ??= load();
  const countryRanges = ipv4 === null ? table.country6 : table.country4;
  const asnRanges = ipv4 === null ? table.asn6 : table.asn4;
  const countryIndex =
    ipv4 === null ? find128(ipv6!, table.country6) : find32(ipv4, table.country4);
  const asnIndex = ipv4 === null ? find128(ipv6!, table.asn6) : find32(ipv4, table.asn4);
  if (countryIndex < 0 && asnIndex < 0) return null;

  const countryCode =
    countryIndex < 0 ? null : countryRanges.codes.slice(countryIndex * 2, countryIndex * 2 + 2);
  const country = countryCode ? table.countries[countryCode] : undefined;
  const asn = asnIndex < 0 ? null : (table.organizations[asnRanges.asns[asnIndex]!] ?? null);
  return {
    countryCode: country ? countryCode : null,
    country: country?.name ?? null,
    lat: country?.lat ?? null,
    lon: country?.lon ?? null,
    asn,
    organization: asn?.replace(/^AS\d+\s*/, "") ?? null,
  };
}
