/**
 * WireGuard `.conf` parser.
 *
 * The format is the same whoever issued it — Mullvad, ProtonVPN, IVPN, a
 * self-hosted server — so this is deliberately generic rather than
 * provider-specific. It is also the one place raw private key material enters
 * the console, so it validates hard and says exactly what is wrong: a person
 * pasting a config that silently half-parses ends up with a tunnel that fails
 * at connect time with a useless error.
 */

export interface ParsedConfig {
  privateKey: string;
  addresses: string[];
  dns: string[];
  mtu: number | null;
  peerPublicKey: string;
  presharedKey: string | null;
  endpointHost: string;
  endpointPort: number;
  allowedIps: string[];
  persistentKeepalive: number | null;
  /** Non-fatal notes worth showing the operator. */
  warnings: string[];
}

/** WireGuard keys are 32 raw bytes, which is exactly 44 base64 characters. */
function isWireGuardKey(value: string): boolean {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) return false;
  try {
    return Buffer.from(value, "base64").length === 32;
  } catch {
    return false;
  }
}

const splitList = (value: string): string[] =>
  value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

export function parseWireGuardConfig(text: string): ParsedConfig {
  if (text.length > 20_000) throw new Error("that file is too large to be a WireGuard config");

  const warnings: string[] = [];
  const iface: Record<string, string> = {};
  const peers: Record<string, string>[] = [];
  let current: Record<string, string> | null = null;

  for (const rawLine of text.split(/\r?\n/)) {
    // Strip comments, but only ones that start a token — base64 never contains
    // '#' or ';', so this cannot truncate a key.
    const line = rawLine
      .replace(/\s+[#;].*$/, "")
      .replace(/^\s*[#;].*$/, "")
      .trim();
    if (!line) continue;

    const section = /^\[(\w+)\]$/.exec(line);
    if (section) {
      const name = section[1]!.toLowerCase();
      if (name === "interface") current = iface;
      else if (name === "peer") {
        current = {};
        peers.push(current);
      } else {
        current = null;
        warnings.push(`ignored unknown section [${section[1]}]`);
      }
      continue;
    }

    const equals = line.indexOf("=");
    if (equals === -1 || current === null) continue;
    // Keys never contain '='; values (base64) always end with one, so split on
    // the first occurrence only.
    const key = line.slice(0, equals).trim().toLowerCase();
    const value = line.slice(equals + 1).trim();
    if (key) current[key] = value;
  }

  if (Object.keys(iface).length === 0) {
    throw new Error("no [Interface] section — is this a WireGuard config?");
  }
  if (peers.length === 0) throw new Error("no [Peer] section — nothing to connect to");
  if (peers.length > 1) {
    warnings.push(`config lists ${peers.length} peers; using the first and ignoring the rest`);
  }
  const peer = peers[0]!;

  const privateKey = iface.privatekey ?? "";
  if (!privateKey) throw new Error("[Interface] has no PrivateKey");
  if (!isWireGuardKey(privateKey)) {
    throw new Error("[Interface] PrivateKey is not a valid 44-character WireGuard key");
  }

  const peerPublicKey = peer.publickey ?? "";
  if (!peerPublicKey) throw new Error("[Peer] has no PublicKey");
  if (!isWireGuardKey(peerPublicKey)) {
    throw new Error("[Peer] PublicKey is not a valid 44-character WireGuard key");
  }

  const presharedKey = peer.presharedkey ?? null;
  if (presharedKey && !isWireGuardKey(presharedKey)) {
    throw new Error("[Peer] PresharedKey is not a valid 44-character WireGuard key");
  }

  const endpoint = peer.endpoint ?? "";
  if (!endpoint) throw new Error("[Peer] has no Endpoint");
  // Endpoint may be host:port or [v6]:port.
  const match = /^(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})$/.exec(endpoint);
  if (!match) throw new Error(`[Peer] Endpoint "${endpoint}" is not host:port`);
  const endpointHost = (match[1] ?? match[2] ?? "").trim();
  const endpointPort = Number(match[3]);
  if (!endpointHost || endpointPort < 1 || endpointPort > 65_535) {
    throw new Error(`[Peer] Endpoint "${endpoint}" has no usable host and port`);
  }

  const addresses = splitList(iface.address ?? "");
  if (addresses.length === 0) throw new Error("[Interface] has no Address");

  const mtu = iface.mtu ? Number(iface.mtu) : null;
  if (mtu !== null && (!Number.isInteger(mtu) || mtu < 576 || mtu > 9_000)) {
    throw new Error(`[Interface] MTU "${iface.mtu}" is out of range`);
  }

  const keepalive = peer.persistentkeepalive ? Number(peer.persistentkeepalive) : null;
  if (keepalive !== null && (!Number.isInteger(keepalive) || keepalive < 0 || keepalive > 65_535)) {
    throw new Error(`[Peer] PersistentKeepalive "${peer.persistentkeepalive}" is out of range`);
  }

  const allowedIps = splitList(peer.allowedips ?? "");
  if (allowedIps.length === 0) {
    warnings.push("[Peer] had no AllowedIPs; defaulting to routing everything");
  }

  // wg-quick applies these itself and they can break routing in ways this
  // console does not model, so they are dropped rather than silently honoured.
  for (const key of ["table", "fwmark", "preup", "postup", "predown", "postdown"]) {
    if (iface[key]) warnings.push(`ignored [Interface] ${key} — not applied by this console`);
  }

  return {
    privateKey,
    addresses,
    dns: splitList(iface.dns ?? ""),
    mtu,
    peerPublicKey,
    presharedKey,
    endpointHost,
    endpointPort,
    allowedIps: allowedIps.length > 0 ? allowedIps : ["0.0.0.0/0", "::/0"],
    persistentKeepalive: keepalive,
    warnings,
  };
}

/**
 * A readable default name. Providers name files things like
 * `mullvad-se-sto-wg-001.conf`, which is more useful than "Imported profile".
 */
export function nameFromSource(source: string, host: string): string {
  const base = source
    .replace(/\.conf$/i, "")
    .replace(/[_-]+/g, " ")
    .trim();
  return base || host;
}
