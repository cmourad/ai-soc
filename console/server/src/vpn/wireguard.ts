/**
 * WireGuard config generation.
 *
 * The interesting part is `allowedIpsFor`. WireGuard has no notion of "route
 * everything except these" — a peer's AllowedIPs is a whitelist and nothing
 * else. Exclude-mode split tunnelling therefore has to be compiled down to the
 * complement of the excluded ranges, which is what real clients do behind their
 * "bypass these networks" checkbox. Getting this wrong sends traffic the user
 * asked to keep local through the tunnel, or worse, leaks tunnel traffic
 * locally, so it is computed rather than approximated.
 */

type Range = { start: number; end: number };

const IPV4_CIDR = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;

function toInt(a: number, b: number, c: number, d: number): number {
  return ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;
}

function toDotted(value: number): string {
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}

export function parseCidr(cidr: string): Range | null {
  const match = IPV4_CIDR.exec(cidr.trim());
  if (!match) return null;
  const octets = [match[1], match[2], match[3], match[4]].map(Number);
  const bits = Number(match[5]);
  if (octets.some((octet) => octet > 255) || bits > 32) return null;
  const base = toInt(octets[0]!, octets[1]!, octets[2]!, octets[3]!);
  const size = bits === 0 ? 2 ** 32 : 2 ** (32 - bits);
  const start = bits === 0 ? 0 : Math.floor(base / size) * size;
  return { start, end: start + size - 1 };
}

/**
 * Largest power of two that divides `value` — the biggest prefix that can start
 * at this address. Done with arithmetic rather than `value & -value`: JavaScript
 * bitwise operators truncate to *signed* 32-bit, so every address above
 * 128.0.0.0 comes back negative and the loop below never terminates.
 */
function alignmentOf(value: number): number {
  if (value === 0) return 2 ** 32;
  let size = 1;
  while (value % (size * 2) === 0) size *= 2;
  return size;
}

/** Greedily emits the largest aligned prefixes that exactly cover [start, end]. */
function rangeToCidrs(start: number, end: number): string[] {
  const out: string[] = [];
  let cursor = start;
  while (cursor <= end) {
    // Largest block that starts here without overshooting the range end.
    let size = alignmentOf(cursor);
    while (size > 1 && cursor + size - 1 > end) size /= 2;
    out.push(`${toDotted(cursor)}/${32 - Math.log2(size)}`);
    cursor += size;
  }
  return out;
}

/** Everything in 0.0.0.0/0 that none of `excluded` covers. */
export function complementOf(excluded: string[]): string[] {
  const ranges = excluded
    .map(parseCidr)
    .filter((range): range is Range => range !== null)
    .sort((a, b) => a.start - b.start);
  if (ranges.length === 0) return ["0.0.0.0/0"];

  // Merge overlaps first, or the gaps between them come out wrong.
  const merged: Range[] = [];
  for (const range of ranges) {
    const last = merged[merged.length - 1];
    if (last && range.start <= last.end + 1) last.end = Math.max(last.end, range.end);
    else merged.push({ ...range });
  }

  const out: string[] = [];
  let cursor = 0;
  for (const range of merged) {
    if (range.start > cursor) out.push(...rangeToCidrs(cursor, range.start - 1));
    cursor = range.end + 1;
    if (cursor > 0xff_ff_ff_ff) break;
  }
  if (cursor <= 0xff_ff_ff_ff) out.push(...rangeToCidrs(cursor, 0xff_ff_ff_ff));
  return out;
}

/**
 * Ranges the tunnel may never carry, whatever the profile says.
 *
 * This host runs the k3s control plane, and a full-tunnel profile takes the
 * route to every ClusterIP with it. On 2026-08-25 that severed the host from
 * its own API server: the Tetragon sensor crash-looped for an hour on
 * "10.43.0.1:443: i/o timeout" while the NAT path was provably intact, because
 * `ip route get 10.43.0.1` resolved to aisoc0. A VPN that swallows the cluster
 * is the routing equivalent of the firewall blocking its own gateway, so this
 * is a mandatory exclusion rather than a checkbox someone has to remember.
 *
 * IPv4 only: the cluster is IPv4, and ::/0 carries nothing that resolves here.
 */
export const NEVER_TUNNELED = ["10.42.0.0/16", "10.43.0.0/16"];

/** `includes` minus `excludes`, as CIDRs. */
function subtractRanges(includes: Range[], excludes: Range[]): string[] {
  let current = includes.map((range) => ({ ...range }));
  for (const cut of excludes) {
    const next: Range[] = [];
    for (const range of current) {
      if (cut.end < range.start || cut.start > range.end) {
        next.push(range);
        continue;
      }
      if (cut.start > range.start) next.push({ start: range.start, end: cut.start - 1 });
      if (cut.end < range.end) next.push({ start: cut.end + 1, end: range.end });
    }
    current = next;
  }
  return current.flatMap((range) => rangeToCidrs(range.start, range.end));
}

/**
 * A pathological exclusion set (many single addresses scattered across the
 * space) expands into thousands of prefixes. wg-quick would install every one as
 * a route, so the list is capped and the caller told, rather than quietly
 * emitting a config that takes minutes to apply.
 */
const MAX_ALLOWED_IPS = 512;

export function allowedIpsFor(splitTunnel: {
  mode: "off" | "include" | "exclude";
  networks: string[];
}): string[] {
  const networks = splitTunnel.networks.map((n) => n.trim()).filter(Boolean);
  const never = NEVER_TUNNELED.map(parseCidr).filter((range): range is Range => range !== null);

  if (splitTunnel.mode === "include" && networks.length > 0) {
    const included = networks.map(parseCidr).filter((range): range is Range => range !== null);
    // A profile that explicitly includes the cluster network is still refused
    // the part of it that would strand this host; the rest of the request stands.
    return included.length > 0 ? subtractRanges(included, never) : networks;
  }
  if (splitTunnel.mode === "exclude" && networks.length > 0) {
    const complement = complementOf([...networks, ...NEVER_TUNNELED]);
    if (complement.length === 0) {
      throw new Error(
        "those exclusions cover the whole address space — the tunnel would carry nothing",
      );
    }
    if (complement.length > MAX_ALLOWED_IPS) {
      throw new Error(
        `excluding those ${networks.length} networks expands to ${complement.length} routes (limit ${MAX_ALLOWED_IPS}) — use fewer, larger exclusions`,
      );
    }
    return complement;
  }
  return [...complementOf(NEVER_TUNNELED), "::/0"];
}

export function buildConfig(input: {
  privateKey: string;
  tunnelIp: string;
  dns: string;
  dnsLeakProtection: boolean;
  peerPublicKey: string;
  endpoint: string;
  allowedIps: string[];
}): string {
  const lines = [
    "[Interface]",
    `PrivateKey = ${input.privateKey}`,
    `Address = ${input.tunnelIp}/32`,
  ];
  // Without this the resolver stays local and every lookup leaks the sites being
  // visited, whatever the tunnel is carrying.
  if (input.dnsLeakProtection && input.dns) lines.push(`DNS = ${input.dns}`);
  lines.push(
    "",
    "[Peer]",
    `PublicKey = ${input.peerPublicKey}`,
    `Endpoint = ${input.endpoint}`,
    `AllowedIPs = ${input.allowedIps.join(", ")}`,
    "PersistentKeepalive = 25",
    "",
  );
  return lines.join("\n");
}
