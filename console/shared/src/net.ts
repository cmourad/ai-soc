/**
 * Address arithmetic. Both the Network Compass and the detection engine have to
 * answer "is this address one of ours", and answering it two different ways is
 * how a VPN's own endpoint ends up correlated as a hostile remote.
 */

export function ipv4Number(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return octets.reduce((value, part) => ((value << 8) | part) >>> 0, 0);
}

function ipv6Number(input: string): bigint | null {
  let ip = input.toLowerCase().split("%", 1)[0]!;
  if (!ip.includes(":")) return null;
  if (ip.includes(".")) {
    const lastColon = ip.lastIndexOf(":");
    const v4 = ipv4Number(ip.slice(lastColon + 1));
    if (v4 === null) return null;
    ip = `${ip.slice(0, lastColon)}:${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  if ((ip.match(/::/g) ?? []).length > 1) return null;
  const [leftText, rightText] = ip.split("::", 2);
  const left = leftText ? leftText.split(":") : [];
  const right = rightText ? rightText.split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((ip.includes("::") && missing < 1) || (!ip.includes("::") && missing !== 0)) return null;
  const groups = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  return groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group}`), 0n);
}

/** Canonical key so `2001:db8::1` and its expanded form share a cache entry. */
export function addressKey(ip: string): string | null {
  const v4 = ipv4Number(ip);
  if (v4 !== null) return `4:${v4}`;
  const v6 = ipv6Number(ip);
  return v6 === null ? null : `6:${v6.toString(16)}`;
}

export function sameAddress(left: string, right: string): boolean {
  const leftKey = addressKey(left);
  return leftKey !== null && leftKey === addressKey(right);
}

export function inNetwork(ip: string, network: string): boolean {
  const [base, prefixText] = network.split("/", 2);
  if (!base) return false;
  if (!prefixText) return sameAddress(ip, base);
  const value = ipv4Number(ip);
  const baseValue = ipv4Number(base);
  const prefix = Number(prefixText);
  if (value === null || baseValue === null) {
    const value6 = ipv6Number(ip);
    const base6 = ipv6Number(base);
    if (
      value6 === null ||
      base6 === null ||
      !Number.isInteger(prefix) ||
      prefix < 0 ||
      prefix > 128
    ) {
      return false;
    }
    const shift = BigInt(128 - prefix);
    return value6 >> shift === base6 >> shift;
  }
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (baseValue & mask);
}
