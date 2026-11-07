import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { RemoteAccessState, TailnetDevice, VpnCheck } from "@aisoc/shared";
import { blankRemoteAccessState } from "@aisoc/shared";
import { getSettings } from "../settings.js";
import { addAudit, getRemoteAccess, setRemoteAccess } from "../store.js";

const run = promisify(execFile);

/**
 * Tailscale lifecycle for remote access.
 *
 * Runs the tailscale CLI unprivileged: the operator grants this once with
 * `sudo tailscale set --operator=$USER`, which is narrower than a NOPASSWD
 * sudoers entry for the binary (that would also allow `set --ssh`). When the
 * operator flag is missing, `tailscale up`/`down` fail with a clear hint and
 * the error is surfaced in the state rather than swallowed.
 *
 * State is polled from `tailscale status --json` — read-only, so this always
 * works — and reconciled against the `remoteAccess.enabled` setting: enabled
 * keeps the tailnet up and serves the console over the tailnet, disabled takes
 * both down. Funnel is refused outright: tailscale serve is tailnet-only, and
 * this console is never one `tailscale funnel` away from the public internet.
 */

async function call(args: string[]): Promise<string> {
  const { stdout } = await run("tailscale", args, { timeout: 15_000 });
  return stdout;
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function funnelFromServe(raw: string): boolean {
  try {
    const d = JSON.parse(raw) as { Funnel?: unknown };
    const funnel = d.Funnel;
    if (typeof funnel === "boolean") return funnel;
    if (funnel !== null && typeof funnel === "object") {
      return Object.values(funnel as Record<string, unknown>).some(Boolean);
    }
    return false;
  } catch {
    return false;
  }
}

/** One entry from the status map — `Self` and each `Peer` share this shape. */
interface StatusNode {
  ID?: string;
  HostName?: string;
  DNSName?: string;
  OS?: string;
  TailscaleIPs?: string[];
  Online?: boolean;
  UserID?: number;
  CurAddr?: string;
  Relay?: string;
  RxBytes?: number;
  TxBytes?: number;
  LastSeen?: string;
  KeyExpiry?: string;
  ExitNode?: boolean;
}

/** The daemon writes a zero timestamp rather than omitting it while a peer is up. */
function realTimestamp(value: string | undefined): string | null {
  if (!value || value.startsWith("0001-01-01")) return null;
  return value;
}

function toDevice(
  node: StatusNode,
  options: { self: boolean; users: Record<string, { LoginName?: string }>; allowed: string[] },
): TailnetDevice {
  const owner = options.users[String(node.UserID ?? "")]?.LoginName ?? null;
  return {
    id: node.ID ?? node.DNSName ?? node.HostName ?? "",
    hostname: node.HostName ?? "",
    dnsName: (node.DNSName ?? "").replace(/\.$/, ""),
    os: node.OS ?? "",
    tailnetIP: (node.TailscaleIPs ?? []).find((ip) => ip.includes(".")) ?? null,
    online: node.Online === true,
    owner,
    self: options.self,
    // An empty CurAddr means the path is going through a DERP relay rather
    // than peer-to-peer; showing which is which explains latency the operator
    // would otherwise have no account for.
    directAddr: node.CurAddr && node.CurAddr.length > 0 ? node.CurAddr : null,
    relay: node.Relay && node.Relay.length > 0 ? node.Relay : null,
    rxBytes: node.RxBytes ?? 0,
    txBytes: node.TxBytes ?? 0,
    lastSeen: realTimestamp(node.LastSeen),
    keyExpiry: realTimestamp(node.KeyExpiry),
    exitNode: node.ExitNode === true,
    allowed: owner !== null && options.allowed.includes(owner),
  };
}

/** Reparse daemon state from `tailscale status --json` and broadcast it. */
export async function refreshRemoteAccess(): Promise<RemoteAccessState> {
  const next = blankRemoteAccessState();
  try {
    const parsed = JSON.parse(await call(["status", "--json"])) as {
      BackendState?: string;
      AuthURL?: string;
      // `Peer` is a map keyed by node key, not an array. Treating it as an
      // array silently reports zero devices however many are connected.
      Peer?: Record<string, StatusNode>;
      User?: Record<string, { LoginName?: string }>;
      Self?: StatusNode;
    };
    const self = parsed.Self ?? {};
    const users = parsed.User ?? {};
    const allowed = getSettings().remoteAccess.allowedLogins;

    next.present = true;
    next.online = self.Online === true;
    next.backendState = typeof parsed.BackendState === "string" ? parsed.BackendState : null;
    next.node = self.HostName ?? "";
    next.dnsName = self.DNSName ?? "";
    next.tailnetIP = (self.TailscaleIPs ?? []).find((ip) => ip.includes(".")) ?? null;

    const peers = Object.values(parsed.Peer ?? {}).map((node) =>
      toDevice(node, { self: false, users, allowed }),
    );
    // This host first, then online devices, then the rest by name.
    peers.sort((a, b) => {
      if (a.online !== b.online) return a.online ? -1 : 1;
      return a.hostname.localeCompare(b.hostname);
    });
    next.devices = [toDevice(self, { self: true, users, allowed }), ...peers];
    next.peerCount = peers.length;
    next.authUrl = typeof parsed.AuthURL === "string" ? parsed.AuthURL : null;
    next.funnelOn = funnelFromServe(await call(["serve", "status", "--json"]));
  } catch (err) {
    next.error = describe(err);
  }
  setRemoteAccess(next);
  return next;
}

/**
 * Bring the tailnet up or down, then republish state. On failure the error is
 * preserved on the state so the UI can show exactly why (missing operator flag
 * is the common case).
 */
export async function setRemoteAccessWanted(wanted: boolean): Promise<{
  ok: boolean;
  state: RemoteAccessState;
}> {
  try {
    await call(wanted ? ["up"] : ["down"]);
  } catch (err) {
    const message = describe(err);
    const current = getRemoteAccess();
    setRemoteAccess({
      ...current,
      error: message,
    });
    return { ok: false, state: getRemoteAccess() };
  }
  return { ok: true, state: await refreshRemoteAccess() };
}

/** HTTPS port tailscale serve binds on the tailnet DNS name (443 may be taken). */
const SERVE_HTTPS_PORT = Number(process.env.AISOC_SERVE_PORT ?? 8443);

/**
 * Point `tailscale serve` at the remote listener, or tear serving down.
 * `servePort` is the second loopback listener only reachable over the tailnet.
 * Funnel is refused as a separate best-effort call so its absence never marks
 * the serve itself as failed.
 */
async function ensureServe(wanted: boolean, servePort: number): Promise<void> {
  try {
    if (wanted) {
      await call(["serve", "--bg", `--https=${SERVE_HTTPS_PORT}`, `http://127.0.0.1:${servePort}`]);
      await refuseFunnel();
    } else {
      await call(["serve", "reset"]);
    }
  } catch (err) {
    const text = describe(err);
    const hint = text.includes("Serve is not enabled")
      ? "serve: enable Serve on your tailnet at login.tailscale.com/f/serve — funnel stays off."
      : `serve: ${text}`;
    setRemoteAccess({ ...getRemoteAccess(), error: hint });
  }
}

/** Make sure no configured proxy is exposed publicly; a funnel off is fine. */
async function refuseFunnel(): Promise<void> {
  try {
    await call(["funnel", "off"]);
  } catch {
    // Already off / never on is the happy path: do not disturb the state.
  }
}

/** Make the daemon (up/down + serve) match the setting, then broadcast state. */
export async function configureRemoteAccess(servePort: number): Promise<RemoteAccessState> {
  const { enabled } = getSettings().remoteAccess;
  if (enabled) {
    const before = await refreshRemoteAccess();
    if (!before.online) {
      const { ok } = await setRemoteAccessWanted(true);
      addAudit("analyst", "remoteaccess", "up", "reconciled to setting", ok);
    }
    await ensureServe(true, servePort);
  } else {
    await ensureServe(false, servePort);
    const before = await refreshRemoteAccess();
    if (before.online) {
      const { ok } = await setRemoteAccessWanted(false);
      addAudit("analyst", "remoteaccess", "down", "reconciled to setting", ok);
    }
  }
  return refreshRemoteAccess();
}

/**
 * Everything that must be true before a tailnet device can reach this console.
 * Mirrors the VPN readiness panel: each check carries a fix the operator can
 * run verbatim.
 */
export async function preflightRemoteAccess(): Promise<VpnCheck[]> {
  const state = await refreshRemoteAccess();
  const { allowedLogins } = getSettings().remoteAccess;
  const checks: VpnCheck[] = [];

  checks.push({
    id: "binary",
    label: "Tailscale installed and daemon responsive",
    ok: state.present,
    detail: state.present
      ? "The tailscale CLI answers on this host."
      : "tailscale is missing or the daemon is not running.",
    fix: state.present
      ? null
      : "Install Tailscale (curl -fsSL https://tailscale.com/install.sh | sh).",
  });

  let operatorSet = false;
  try {
    const prefs = JSON.parse(await call(["debug", "prefs"])) as { OperatorUser?: string };
    operatorSet = typeof prefs.OperatorUser === "string" && prefs.OperatorUser.length > 0;
  } catch {
    operatorSet = false;
  }
  checks.push({
    id: "operator",
    label: "Operator flag set (no sudo for up/down/serve)",
    ok: operatorSet,
    detail: operatorSet
      ? "tailscale controls run as the current user."
      : "Controls need root unless the operator flag is set once.",
    fix: operatorSet ? null : "sudo tailscale set --operator=$USER",
  });

  checks.push({
    id: "online",
    label: "Node connected to the tailnet",
    ok: state.online,
    detail: state.online
      ? `${state.node} is online at ${state.tailnetIP ?? "…"}.`
      : `Daemon state: ${state.backendState ?? "unknown"}.`,
    fix: state.online ? null : "Enable remote access (brings the tailnet up).",
  });

  checks.push({
    id: "allowlist",
    label: "At least one tailnet identity allowlisted",
    ok: allowedLogins.length > 0,
    detail:
      allowedLogins.length > 0
        ? `${allowedLogins.length} identity(ies) may reach this console.`
        : "Nobody can get in remotely until a login is allowlisted.",
    fix: allowedLogins.length > 0 ? null : "Add a tailnet login (user@domain) in the access list.",
  });

  let serveOn = false;
  try {
    const served = JSON.parse(await call(["serve", "status", "--json"])) as { Web?: unknown };
    serveOn =
      served.Web !== null && typeof served.Web === "object" && Object.keys(served.Web).length > 0;
  } catch {
    serveOn = false;
  }
  checks.push({
    id: "serve",
    label: "Console is served over the tailnet",
    ok: serveOn,
    detail: serveOn
      ? `https://${state.dnsName.replace(/\.$/, "")}:${SERVE_HTTPS_PORT}/ reaches the console.`
      : "tailscale serve is not proxying the remote listener yet.",
    fix: serveOn ? null : "Enable remote access below.",
  });

  checks.push({
    id: "funnel",
    label: "Not exposed publicly (funnel off)",
    ok: !state.funnelOn,
    detail: state.funnelOn
      ? "A serve proxy is publicly reachable — this console refuses that."
      : "Tailnet-only; nothing is exposed to the open internet.",
    fix: state.funnelOn ? "tailscale funnel off" : null,
  });

  return checks;
}
