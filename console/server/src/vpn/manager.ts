import { execFile } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import type { VpnCheck, VpnConnection, VpnProfile, VpnServer } from "@aisoc/shared";
import { getSecret } from "../crypto.js";
import { AGENT_CONTROL_SOCKET, DATA_DIR } from "../paths.js";
import { agentVpn, agentVpnStatus } from "../response/agent.js";
import { getSettings } from "../settings.js";
import {
  addAudit,
  addNotification,
  getRemoteAccess,
  getVpn,
  listVpnProfiles,
  setVpn,
} from "../store.js";
import { VpnOperationGate } from "./lifecycle.js";
import { getProfile } from "./profiles.js";
import { publishVpnState } from "./publish.js";
import { getServer, recommendServer, refreshLoad } from "./servers.js";
import { allowedIpsFor, buildConfig } from "./wireguard.js";

const run = promisify(execFile);

/**
 * VPN tunnel lifecycle.
 *
 * Two execution modes, mirroring how response actions work elsewhere in this
 * console: `simulate` describes the tunnel it would build without touching the
 * network stack, and `wg-quick` actually brings it up. Simulate is the default
 * because a VPN client that silently reroutes every packet on a machine running
 * an IDS is not something to switch on by surprise.
 *
 * The kill switch is deliberately not a separate firewall rule. It is expressed
 * as `AllowedIPs = 0.0.0.0/0` on the peer, so when the tunnel is down there is
 * simply no route — fail-closed by construction, with no extra chain that could
 * outlive the process and lock the operator out of their own machine.
 */

const CONFIG_DIR = join(DATA_DIR, "wg");
const CONTROL_SOCKET = AGENT_CONTROL_SOCKET;

function site() {
  const { site: config } = getSettings();
  return { lat: config.lat, lon: config.lon };
}

function blank(interfaceName: string): VpnConnection {
  return {
    status: "disconnected",
    serverId: null,
    profileId: null,
    tunnelIp: null,
    exitIp: null,
    interfaceName,
    connectedAt: null,
    lastHandshake: null,
    bytesUp: 0,
    bytesDown: 0,
    simulated: true,
    killSwitchEngaged: false,
    error: null,
  };
}

export function initialVpnState(): VpnConnection {
  return blank(getSettings().vpn.interfaceName);
}

function update(patch: Partial<VpnConnection>): VpnConnection {
  const next = { ...getVpn(), ...patch };
  setVpn(next);
  publishVpnState();
  return next;
}

/**
 * A stable in-tunnel address per server, so reconnecting to the same exit does
 * not look like a different client every time.
 */
function hashOf(value: string, seed: number): number {
  let hash = 0;
  for (const ch of value) hash = (Math.imul(hash, seed) + ch.charCodeAt(0)) >>> 0;
  return hash;
}

/** Octet from a 32-bit hash. Unsigned shift throughout — `>>` sign-extends. */
function octet(hash: number, shift: number, modulo: number, offset = 0): number {
  return (((hash >>> shift) & 0xff) % modulo) + offset;
}

function tunnelIpFor(server: VpnServer): string {
  const hash = hashOf(server.id, 31);
  return `10.64.${octet(hash, 8, 254)}.${octet(hash, 0, 253, 2)}`;
}

/** The address the world sees once traffic leaves the exit. */
function exitIpFor(server: VpnServer): string {
  const hash = hashOf(server.publicKey, 17);
  return `${45 + (hash % 150)}.${octet(hash, 4, 254)}.${octet(hash, 12, 254)}.${octet(hash, 20, 253, 1)}`;
}

/**
 * Renders an imported profile. The provider's own AllowedIPs is the default, but
 * the operator's kill-switch and split-tunnel choices override it — those are
 * this console's policy, and a provider config that routes everything should not
 * quietly undo a deliberate split-tunnel setting.
 */
function profileConfig(profile: VpnProfile, redactKey: boolean): string {
  const { vpn } = getSettings();
  const privateKey = getSecret(profile.privateKeySecret);
  if (!privateKey && !redactKey) {
    throw new Error("this profile's private key is missing from the secret store — re-import it");
  }
  const presharedKey = profile.presharedKeySecret ? getSecret(profile.presharedKeySecret) : null;

  const allowedIps = vpn.killSwitch
    ? allowedIpsFor({ mode: "off", networks: [] })
    : vpn.splitTunnel.mode === "off"
      ? profile.allowedIps
      : allowedIpsFor(vpn.splitTunnel);

  const lines = [
    "[Interface]",
    `PrivateKey = ${redactKey ? "<stored private key>" : privateKey}`,
    `Address = ${profile.addresses.join(", ")}`,
  ];
  const dns = vpn.dnsLeakProtection ? (profile.dns.length > 0 ? profile.dns : [vpn.dns]) : [];
  if (dns.length > 0) lines.push(`DNS = ${dns.join(", ")}`);
  if (profile.mtu) lines.push(`MTU = ${profile.mtu}`);

  lines.push("", "[Peer]", `PublicKey = ${profile.peerPublicKey}`);
  if (presharedKey || (redactKey && profile.hasPresharedKey)) {
    lines.push(`PresharedKey = ${redactKey ? "<stored preshared key>" : presharedKey}`);
  }
  lines.push(
    `Endpoint = ${profile.host}:${profile.port}`,
    `AllowedIPs = ${allowedIps.join(", ")}`,
    `PersistentKeepalive = ${profile.persistentKeepalive ?? 25}`,
    "",
  );
  return lines.join("\n");
}

/**
 * The config the current settings would produce, with the key redacted. Split
 * tunnelling can be configured into something that has no valid expansion, so
 * the failure is returned as the config body — the preview is exactly where an
 * operator should find that out.
 */
export function previewConfig(target: ConnectTarget): string {
  try {
    if (target.profileId) {
      const profile = getProfile(target.profileId);
      if (!profile) return "# that profile no longer exists";
      return profileConfig(profile, true);
    }
    return buildPreview(target.serverId ?? null);
  } catch (error) {
    return `# cannot build a config with these settings:\n# ${error instanceof Error ? error.message : String(error)}`;
  }
}

function buildPreview(serverId: string | null): string {
  const { vpn } = getSettings();
  const server = serverId
    ? getServer(serverId, site())
    : recommendServer(site(), vpn.preferredCountry);
  if (!server) return "# no server selected";
  return buildConfig({
    privateKey: getSecret(vpn.privateKeySecret) ? "<stored client private key>" : "<not set>",
    tunnelIp: tunnelIpFor(server),
    dns: vpn.dns,
    dnsLeakProtection: vpn.dnsLeakProtection,
    peerPublicKey: server.publicKey,
    endpoint: `${server.host}:${server.port}`,
    allowedIps: vpn.killSwitch
      ? allowedIpsFor({ mode: "off", networks: [] })
      : allowedIpsFor(vpn.splitTunnel),
  });
}

let connectingTimer: NodeJS.Timeout | null = null;
const operations = new VpnOperationGate();

/**
 * Whether routes were ever actually installed. The kill switch only holds
 * traffic down if there is a real default route pointing into a dead tunnel —
 * a simulated tunnel changes no routing, and a connect that failed before
 * `wg-quick` ran changed nothing either. Reporting "egress is blocked" in those
 * cases tells the operator their machine is offline when it is fine, which is
 * exactly the kind of false statement a security tool must never make.
 */
let routesApplied = false;

function killSwitchHolding(): boolean {
  return getSettings().vpn.killSwitch && routesApplied;
}

/**
 * Egress is only actually held down when the routes were applied *and* the
 * interface is gone. If it is still up, traffic is still flowing through it and
 * telling the operator otherwise is simply false.
 */
async function killSwitchHoldingNow(): Promise<boolean> {
  const { vpn } = getSettings();
  if (!vpn.killSwitch || !routesApplied) return false;
  return !(await interfaceExists(vpn.interfaceName));
}

/**
 * Tunnel status is privileged in this kernel: WireGuard's netlink family enforces
 * GENL_UNS_ADMIN_PERM, so an unprivileged `wg show` is denied. Read the dump
 * through the agent, the one process holding CAP_NET_ADMIN, instead of running
 * `wg` as the console user.
 */
async function wgShow(interfaceName: string): Promise<string> {
  return agentVpnStatus(interfaceName);
}

/**
 * Whether the privileged WireGuard control plane can see this tunnel.
 *
 * The console service is intentionally unprivileged, so a local `ip link`
 * subprocess is not an authoritative ownership check.  In production that
 * probe can fail even while the agent (and wg-quick) can see the live tunnel,
 * which used to make reconnect skip `down` and fail with "already exists".
 */
async function interfaceExists(name: string): Promise<boolean> {
  try {
    await wgShow(name);
    return true;
  } catch {
    return false;
  }
}

/**
 * The core never invokes sudo. Real tunnel mutation goes through the agent's
 * peer-authenticated control socket; the agent is the only process with
 * CAP_NET_ADMIN and invokes a fixed wg-quick path.
 */
async function wgQuick(action: "up" | "down" | "replace", path: string): Promise<void> {
  try {
    const interfaceName =
      path
        .split("/")
        .pop()
        ?.replace(/\.conf$/, "") ?? "";
    await agentVpn(
      action,
      interfaceName,
      action !== "down" ? readFileSync(path, "utf8") : undefined,
    );
  } catch (error) {
    const detail = error as { stderr?: string; message?: string; code?: string };
    const stderr = (detail.stderr ?? "").trim();
    if (detail.code === "ENOENT") {
      throw new Error("wg-quick is not installed — install the wireguard package");
    }
    if (/operation not permitted|permission denied|not permitted/i.test(stderr))
      throw new Error("the dedicated VPN helper was not permitted to change the tunnel");
    throw new Error(stderr || detail.message || `wg-quick ${action} failed`);
  }
}

export type ConnectTarget = { serverId?: string | null; profileId?: string | null };

export function connect(target: ConnectTarget, by: string): Promise<VpnConnection> {
  return operations.run(() => connectUnlocked(target, by));
}

async function connectUnlocked(target: ConnectTarget, by: string): Promise<VpnConnection> {
  const { vpn } = getSettings();
  if (!vpn.enabled) throw new Error("the VPN is disabled in settings");

  const profile = target.profileId ? getProfile(target.profileId) : undefined;
  if (target.profileId && !profile) throw new Error("that VPN profile no longer exists");

  // Real execution against a demo exit is the trap this console must not let a
  // person fall into: the catalogue is scenery, so wg-quick would dial a
  // hostname that does not resolve and fail with something unhelpful.
  if (!profile && vpn.execution === "wg-quick") {
    throw new Error(
      listVpnProfiles().length === 0
        ? "The built-in exit list is demo data with no real servers behind it. Import a WireGuard config from a VPN provider to connect for real, or switch execution back to simulate."
        : "Pick one of your imported profiles — the built-in exit list is demo data and cannot be dialled for real.",
    );
  }

  const server = profile
    ? undefined
    : target.serverId
      ? getServer(target.serverId, site())
      : recommendServer(site(), vpn.preferredCountry);
  if (!profile && !server) throw new Error("no exit server matches the current preference");

  if (connectingTimer) {
    clearTimeout(connectingTimer);
    connectingTimer = null;
  }
  const before = getVpn();
  const sameTarget = target.profileId
    ? before.profileId === target.profileId
    : before.serverId === target.serverId;
  if (before.status === "connected" && sameTarget && (await interfaceExists(vpn.interfaceName))) {
    return before;
  }
  if (before.status === "connected") await disconnectUnlocked(by, { quiet: true });

  const label = profile ? profile.name : `${server!.city}, ${server!.country}`;
  const tunnelIp = profile ? (profile.addresses[0]?.split("/")[0] ?? null) : tunnelIpFor(server!);

  update({
    status: "connecting",
    serverId: server?.id ?? null,
    profileId: profile?.id ?? null,
    interfaceName: vpn.interfaceName,
    error: null,
    killSwitchEngaged: false,
  });

  const finish = () => {
    const connected = update({
      status: "connected",
      tunnelIp,
      // A real tunnel's public address is whatever the provider egresses from;
      // the console does not know it without asking an external service, so it
      // reports the endpoint rather than inventing one.
      exitIp: profile ? profile.host : exitIpFor(server!),
      connectedAt: new Date().toISOString(),
      lastHandshake: new Date().toISOString(),
      bytesUp: 0,
      bytesDown: 0,
      simulated: vpn.execution === "simulate",
    });
    addAudit(
      by,
      "vpn.connect",
      label,
      `${vpn.execution === "simulate" ? "[simulated] " : ""}${vpn.protocol} tunnel up on ${vpn.interfaceName}; kill switch ${vpn.killSwitch ? "on" : "off"}`,
    );
    addNotification({
      kind: "system",
      level: "info",
      title: `VPN connected — ${label}`,
      body: `${vpn.protocol}${connected.simulated ? " (simulated — no routes changed)" : ""}. Kill switch ${vpn.killSwitch ? "armed" : "off"}.`,
      linkView: "vpn",
      linkId: null,
    });
    return connected;
  };

  if (vpn.execution === "simulate") {
    // A handshake is not instant, and a client that snaps to "connected" hides
    // the one state where things actually go wrong.
    return await new Promise<VpnConnection>((resolve) => {
      connectingTimer = setTimeout(() => {
        connectingTimer = null;
        resolve(finish());
      }, 900);
    });
  }

  try {
    const path = writeProfileConfig(profile!);
    // Down+up is one helper request. Keeping the pair atomic prevents another
    // console instance from interleaving its own up between our two commands.
    await wgQuick("replace", path);
    routesApplied = true;
    return finish();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // Clear the facts that describe a live tunnel. Leaving uptime and an exit
    // on screen next to "Tunnel failed" is how the view ended up contradicting
    // itself in three places at once.
    const failed = update({
      status: "error",
      error: message,
      connectedAt: null,
      lastHandshake: null,
      tunnelIp: null,
      bytesUp: 0,
      bytesDown: 0,
      killSwitchEngaged: await killSwitchHoldingNow(),
    });
    addAudit(by, "vpn.connect", label, message, false);
    addNotification({
      kind: "system",
      level: killSwitchHolding() ? "critical" : "warning",
      title: "VPN failed to connect",
      body: killSwitchHolding()
        ? `${message} Kill switch is holding egress down until a tunnel comes back up.`
        : `${message} No routes were changed, so normal traffic is unaffected.`,
      linkView: "vpn",
      linkId: null,
    });
    return failed;
  }
}

function writeProfileConfig(profile: VpnProfile): string {
  const { vpn } = getSettings();
  mkdirSync(CONFIG_DIR, { recursive: true });
  const path = join(CONFIG_DIR, `${vpn.interfaceName}.conf`);
  writeFileSync(path, profileConfig(profile, false), { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

export function disconnect(by: string, options: { quiet?: boolean } = {}): Promise<VpnConnection> {
  return operations.run(() => disconnectUnlocked(by, options));
}

async function disconnectUnlocked(
  by: string,
  options: { quiet?: boolean } = {},
): Promise<VpnConnection> {
  const { vpn } = getSettings();
  const current = getVpn();
  if (connectingTimer) {
    clearTimeout(connectingTimer);
    connectingTimer = null;
  }

  if (!current.simulated && vpn.execution === "wg-quick") {
    try {
      await wgQuick("down", join(CONFIG_DIR, `${vpn.interfaceName}.conf`));
    } catch (error) {
      // A tunnel that is already down is the state we wanted; anything else is
      // worth surfacing rather than swallowing.
      const message = error instanceof Error ? error.message : String(error);
      if (!/is not a WireGuard interface|does not exist/i.test(message)) {
        update({ status: "error", error: message });
        addAudit(by, "vpn.disconnect", vpn.interfaceName, message, false);
        return getVpn();
      }
    }
  }

  // Dropping the tunnel with the kill switch armed is exactly when egress should
  // stay shut — but only if there were real routes to lose in the first place.
  const wasHolding = killSwitchHolding();
  routesApplied = false;
  const next = update({ ...blank(vpn.interfaceName), killSwitchEngaged: wasHolding });

  if (!options.quiet) {
    addAudit(by, "vpn.disconnect", vpn.interfaceName, "Tunnel brought down.");
    if (wasHolding) {
      addNotification({
        kind: "system",
        level: "warning",
        title: "VPN disconnected — kill switch engaged",
        body: "Egress stays blocked until a tunnel is back up. Turn the kill switch off to restore direct traffic.",
        linkView: "vpn",
        linkId: null,
      });
    }
  }
  return next;
}

/**
 * The endpoints this console depends on for its own reachability. Response
 * actions consult this so the console can never firewall the path its traffic
 * leaves through — a self-inflicted outage that looks exactly like a successful
 * containment.
 *
 * Covers the live VPN exit and the tailnet surface (remote access): the CGNAT
 * tailnet address is not matched by `isPrivate`, so block_ip on it would sail
 * past the private-range rail and cut the operator's own way into the box.
 */
export function activeEndpoints(): string[] {
  const out: string[] = [];

  const current = getVpn();
  if (current.status !== "disconnected" && current.serverId) {
    const server = getServer(current.serverId, site());
    if (server) out.push(server.host);
    if (current.exitIp) out.push(current.exitIp);
  }

  const remote = getRemoteAccess();
  if (remote.tailnetIP) out.push(remote.tailnetIP);
  if (remote.dnsName) out.push(remote.dnsName.replace(/\.$/, ""));

  return out;
}

/** Polls tunnel health, drives reconnection, and keeps the counters moving. */
export async function pollVpn(): Promise<void> {
  // A five-second interval must not queue status checks behind a slow tunnel
  // replacement; the mutation will leave authoritative state when it finishes.
  if (operations.busy) return;
  await operations.run(pollVpnUnlocked);
}

async function pollVpnUnlocked(): Promise<void> {
  refreshLoad();
  const { vpn } = getSettings();
  const current = getVpn();

  if (current.status !== "connected") {
    // The tunnel may be up without this process having brought it up: a console
    // restart, or an earlier poll that wrongly declared it dead. Reality wins.
    if (vpn.enabled && vpn.execution === "wg-quick" && current.status !== "connecting") {
      if (await adoptRunningTunnel()) return;
    }
    if (
      vpn.enabled &&
      vpn.reconnectOnDrop &&
      current.status === "error" &&
      (current.serverId !== null || current.profileId !== null)
    ) {
      update({ status: "reconnecting" });
      void connect(
        { serverId: current.serverId, profileId: current.profileId },
        "vpn-watchdog",
      ).catch(() => {
        // The failure path already recorded itself.
      });
    }
    return;
  }

  if (vpn.execution === "simulate") {
    // Plausible throughput so the counters and the handshake clock move.
    update({
      bytesUp: current.bytesUp + Math.floor(20_000 + Math.random() * 180_000),
      bytesDown: current.bytesDown + Math.floor(80_000 + Math.random() * 900_000),
      lastHandshake: new Date().toISOString(),
    });
    return;
  }

  try {
    const stdout = await wgShow(vpn.interfaceName);
    // The first line is the interface; peers follow. Fields on a peer line are
    // key, psk, endpoint, allowed-ips, latest-handshake, rx, tx, keepalive.
    const peer = stdout.split("\n")[1]?.split("\t") ?? [];
    const handshake = Number(peer[4] ?? 0);
    const rx = Number(peer[5] ?? 0);
    const tx = Number(peer[6] ?? 0);
    const staleFor = handshake > 0 ? Date.now() / 1000 - handshake : Number.POSITIVE_INFINITY;

    update({
      bytesDown: Number.isFinite(rx) ? rx : current.bytesDown,
      bytesUp: Number.isFinite(tx) ? tx : current.bytesUp,
      lastHandshake:
        handshake > 0 ? new Date(handshake * 1000).toISOString() : current.lastHandshake,
    });

    // WireGuard rekeys well inside three minutes; past that the peer is gone.
    if (staleFor > 180) {
      update({
        status: "error",
        error: "no handshake in over three minutes",
        killSwitchEngaged: killSwitchHolding(),
      });
      addNotification({
        kind: "system",
        level: vpn.killSwitch ? "critical" : "warning",
        title: "VPN tunnel went stale",
        body: `No handshake on ${vpn.interfaceName} for ${Math.round(staleFor)}s.${vpn.killSwitch ? " Kill switch is holding egress down." : ""}`,
        linkView: "vpn",
        linkId: null,
      });
    }
  } catch (error) {
    // A failed status read is not proof the tunnel died — but a missing
    // interface is. Distinguishing the two is what stops a permissions problem
    // from being reported as a dropped connection.
    if (await interfaceExists(vpn.interfaceName)) {
      update({ error: `status unavailable: ${describe(error)}` });
      return;
    }
    update({
      status: "error",
      error: describe(error),
      connectedAt: null,
      tunnelIp: null,
      killSwitchEngaged: await killSwitchHoldingNow(),
    });
  }
}

function describe(error: unknown): string {
  const detail = error as { stderr?: string; message?: string };
  return (detail.stderr ?? "").trim() || detail.message || String(error);
}

/**
 * Picks up a tunnel that is already running on our interface name and reports it
 * as connected, matching it to a profile by endpoint. Without this, restarting
 * the console leaves a live tunnel showing as disconnected and every attempt to
 * reconnect fails with "already exists".
 */
async function adoptRunningTunnel(): Promise<boolean> {
  const { vpn } = getSettings();
  if (!(await interfaceExists(vpn.interfaceName))) return false;

  let dump = "";
  try {
    dump = await wgShow(vpn.interfaceName);
  } catch {
    return false;
  }

  const peer = dump.split("\n")[1]?.split("\t") ?? [];
  const endpoint = peer[2] ?? "";
  const handshake = Number(peer[4] ?? 0);
  const host = endpoint.split(":")[0] ?? "";
  const profile = listVpnProfiles().find((entry) => entry.host === host);

  routesApplied = true;
  update({
    status: "connected",
    profileId: profile?.id ?? null,
    serverId: null,
    interfaceName: vpn.interfaceName,
    tunnelIp: profile?.addresses[0]?.split("/")[0] ?? null,
    exitIp: host || null,
    connectedAt:
      handshake > 0 ? new Date(handshake * 1000).toISOString() : new Date().toISOString(),
    lastHandshake: handshake > 0 ? new Date(handshake * 1000).toISOString() : null,
    bytesDown: Number(peer[5] ?? 0) || 0,
    bytesUp: Number(peer[6] ?? 0) || 0,
    simulated: false,
    killSwitchEngaged: false,
    error: null,
  });
  return true;
}

/** Brings the tunnel up at startup when the operator asked for it. */
export function autoConnectIfConfigured(): void {
  const { vpn } = getSettings();
  if (!vpn.enabled) return;
  // Adopt first: a tunnel this console left running is already the desired
  // state, and dialling over it would only fail.
  void adoptRunningTunnel().then((adopted) => {
    if (adopted || !vpn.autoConnect) return;
    startAutoConnect();
  });
}

function startAutoConnect(): void {
  const profile = listVpnProfiles()[0];
  void connect({ profileId: profile?.id ?? null }, "auto-connect").catch(() => {
    // Recorded on the connection state; startup must not fail over a VPN.
  });
}

/**
 * Everything that has to be true before a real tunnel can come up, each with the
 * command that fixes it. A checklist an operator can act on beats an error
 * message they have to interpret — especially when four separate things
 * (package, permissions, profile, resolver) can each independently block a
 * connection.
 */
export async function preflight(): Promise<VpnCheck[]> {
  const { vpn } = getSettings();
  const checks: VpnCheck[] = [];

  const present = async (binary: string): Promise<boolean> => {
    try {
      await run("which", [binary]);
      return true;
    } catch {
      return false;
    }
  };

  if (vpn.execution === "simulate") {
    checks.push({
      id: "mode",
      label: "Execution mode",
      ok: true,
      detail:
        "Simulate — the tunnel is described but no routes are changed. Nothing below is required.",
      fix: null,
    });
    return checks;
  }

  const hasWg = await present("wg");
  const hasWgQuick = await present("wg-quick");
  checks.push({
    id: "wireguard",
    label: "WireGuard installed",
    ok: hasWg && hasWgQuick,
    detail: hasWg && hasWgQuick ? "wg and wg-quick are both on PATH." : "wg-quick was not found.",
    fix: hasWg && hasWgQuick ? null : "sudo apt install wireguard wireguard-tools",
  });

  checks.push({
    id: "helper",
    label: "Dedicated VPN helper",
    ok: existsSync(CONTROL_SOCKET),
    detail: existsSync(CONTROL_SOCKET)
      ? "The agent control socket is present; VPN mutations are peer-authenticated and run with its CAP_NET_ADMIN boundary."
      : "The agent control socket is unavailable, so real tunnel mutation cannot be requested.",
    fix: existsSync(CONTROL_SOCKET) ? null : "Restart aisoc-agent.service and inspect its journal.",
  });

  if (vpn.dnsLeakProtection) {
    const hasResolvconf = (await present("resolvconf")) || (await present("resolvectl"));
    checks.push({
      id: "resolver",
      label: "DNS integration",
      ok: hasResolvconf,
      detail: hasResolvconf
        ? "A resolver helper is available, so wg-quick can apply the tunnel's DNS."
        : "wg-quick needs resolvconf or systemd-resolved to set DNS, and will fail without one.",
      fix: hasResolvconf ? null : "sudo apt install openresolv",
    });
  }

  const profiles = listVpnProfiles();
  checks.push({
    id: "profile",
    label: "A real VPN profile imported",
    ok: profiles.length > 0,
    detail:
      profiles.length > 0
        ? `${profiles.length} profile${profiles.length === 1 ? "" : "s"} imported.`
        : "The built-in exit list is demo data. Import a .conf file from your VPN provider.",
    fix: null,
  });

  for (const profile of profiles) {
    const hasKey = Boolean(getSecret(profile.privateKeySecret));
    if (hasKey) continue;
    checks.push({
      id: `key-${profile.id}`,
      label: `Key stored for "${profile.name}"`,
      ok: false,
      detail: "The private key is missing from the secret store.",
      fix: "Remove the profile and import the .conf file again.",
    });
  }

  return checks;
}
