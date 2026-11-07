import { inNetwork, sameAddress } from "./net.js";
import type { SecurityEvent } from "./types.js";

/**
 * Which end of a flow is ours, and how much data crossed it in each direction.
 * Both the rule pack and the heuristics need this, and the rule pack cannot
 * import the engine that loads it.
 */

/**
 * Ranges that are ours no matter how the site is configured. A tunnel handed a
 * globally-routable prefix is not in here — that is what `site.homeNetworks` is
 * for, and until it is declared neither end of such a flow looks local.
 */
const INTRINSIC_LOCAL = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  ["192", "168.0.0/16"].join("."),
  "127.0.0.0/8",
  "169.254.0.0/16",
  "::1/128",
  "fc00::/7",
  "fe80::/10",
];

let configuredNetworks: readonly string[] = [];
let configuredAddresses: readonly string[] = [];

/**
 * Declares the site's own networks, from `site.homeNetworks` plus the addresses
 * the sensor host actually holds. Called once at startup and again whenever
 * settings change; until then only the intrinsic ranges count.
 */
export function setLocalNetworks(networks: readonly string[], addresses: readonly string[]): void {
  configuredNetworks = [...networks];
  configuredAddresses = [...addresses];
}

export function isLocal(ip: string): boolean {
  return (
    INTRINSIC_LOCAL.some((network) => inNetwork(ip, network)) ||
    configuredNetworks.some((network) => inNetwork(ip, network)) ||
    configuredAddresses.some((address) => sameAddress(ip, address))
  );
}

/**
 * Whether we can tell which end of this flow is ours at all. Neither end local
 * means the sensor is watching traffic that is not the site's — no egress
 * question about it has an answer, and guessing produced INC-0126, where a
 * download over an undeclared IPv6 tunnel scored as 943 MB of exfiltration and
 * named the site's own address as the hostile remote.
 */
export function orientationKnown(event: SecurityEvent): boolean {
  return isLocal(event.srcIp) !== isLocal(event.destIp);
}

/** The side of the flow we would ever act on is the one that isn't ours. */
export function remoteIp(event: SecurityEvent): string {
  if (isLocal(event.srcIp) && !isLocal(event.destIp)) return event.destIp;
  if (!isLocal(event.srcIp) && isLocal(event.destIp)) return event.srcIp;
  return event.direction === "to_server" ? event.destIp : event.srcIp;
}

export function localIp(event: SecurityEvent): string {
  return remoteIp(event) === event.srcIp ? event.destIp : event.srcIp;
}

/**
 * The end that opened the flow. Suricata anchors bytes_toserver/bytes_toclient
 * to it for the life of the flow, while src_ip/dest_ip on an alert describe the
 * single packet that matched — on a to_client match the two disagree.
 */
function flowClientIp(event: SecurityEvent): string {
  if (event.flowInitiatorIp) return event.flowInitiatorIp;
  return event.direction === "to_server" ? event.srcIp : event.destIp;
}

/**
 * Bytes the local host sent to the remote one — the only figure an egress
 * question may be answered with.
 *
 * Reading the byte counters off src/dest is the trap: an apt download alerts on
 * a to_client packet, whose src is the mirror, and its bytes_toclient is the
 * hundreds of megabytes we pulled down, which is how a Debian mirror gets
 * scored as exfiltration.
 */
export function outboundBytes(event: SecurityEvent): number {
  return flowClientIp(event) === localIp(event) ? event.bytesToServer : event.bytesToClient;
}

export function inboundBytes(event: SecurityEvent): number {
  return flowClientIp(event) === localIp(event) ? event.bytesToClient : event.bytesToServer;
}

export function outboundPackets(event: SecurityEvent): number | undefined {
  const pkts = flowClientIp(event) === localIp(event) ? event.pktsToServer : event.pktsToClient;
  return pkts && pkts > 0 ? pkts : undefined;
}

export function inboundPackets(event: SecurityEvent): number | undefined {
  const pkts = flowClientIp(event) === localIp(event) ? event.pktsToClient : event.pktsToServer;
  return pkts && pkts > 0 ? pkts : undefined;
}

/** Mean bytes per packet, the figure that tells a transfer from an ack stream. */
export function meanPacketBytes(bytes: number, packets: number | undefined): number | undefined {
  return packets === undefined || packets === 0 ? undefined : bytes / packets;
}

/**
 * A bare ack is ~60 bytes on the wire and a full segment is ~1500, so the mean
 * separates the two with room to spare either side.
 */
const ACK_ONLY_MEAN_BYTES = 200;

/**
 * Egress that actually carried data — zero when the packet counts show the
 * local end only acknowledged someone else's transfer.
 *
 * Volume questions must use this rather than `outboundBytes`: acknowledging a
 * 33 MB download costs 813 kB of pure headers, which is otherwise indistinguishable
 * from having uploaded 813 kB. Sensors that report no packet counts fall through
 * to the byte total, so a missing counter never suppresses a detection.
 */
export function outboundPayloadBytes(event: SecurityEvent): number {
  if (!orientationKnown(event)) return 0;
  const bytes = outboundBytes(event);
  const packets = outboundPackets(event);
  if (packets === undefined) return bytes;
  return bytes / packets >= ACK_ONLY_MEAN_BYTES ? bytes : 0;
}
