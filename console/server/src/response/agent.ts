import { connect } from "node:net";
import { AGENT_CONTROL_SOCKET } from "../paths.js";

/**
 * Client for the triage agent's control socket.
 *
 * The console does not write to nftables. The agent owns that table, and with
 * it one `Guard` (own addresses, gateway, resolvers, docker space, allowlist),
 * one auto-expiry ladder, one rate cap, and one audit trail in decisions.jsonl.
 * A second writer would mean two policies over one set: a block the console
 * lifts that the agent re-adds, or a UI that firewalls the default gateway
 * because its own guardrails happened to disagree.
 *
 * Reaching the socket requires group membership, so a failure here is a
 * deployment fact worth surfacing verbatim rather than retrying.
 */

const SOCKET = AGENT_CONTROL_SOCKET;
// A replacement may contain a best-effort down followed by an up. The helper
// caps each wg-quick subprocess at 45s, so the control path must not manufacture
// an "agent busy" failure while that bounded operation is still running.
const TIMEOUT_MS = 105_000;
const MAX_REPLY = 8_192;
const POLICY_VERSION = "console-response-v1";

export interface BlockedElement {
  ip: string;
  set: string;
  /** Lifetime the block was created with, seconds. */
  timeout: number | null;
  /** Seconds left before nft drops the element on its own. */
  expires: number | null;
}

export interface FirewallState {
  blocked: BlockedElement[];
  protected: string[];
  blocksLastHour: number;
  maxBlocksPerHour: number;
}

interface AgentReply {
  ok: boolean;
  refused?: string;
  seconds?: number;
  offenses?: number;
  error?: string | null;
  blocked?: BlockedElement[];
  protected?: string[];
  blocks_last_hour?: number;
  max_blocks_per_hour?: number;
  dump?: string;
  process_name?: string | null;
}

export async function agentVpn(
  action: "up" | "down" | "replace",
  interfaceName: string,
  config?: string,
): Promise<void> {
  const reply = await request({
    op: action === "replace" ? "vpn_replace" : action === "up" ? "vpn_up" : "vpn_down",
    interface: interfaceName,
    ...(action !== "down" ? { config } : {}),
  });
  if (!reply.ok) throw new Error(reply.error ?? `VPN helper could not bring tunnel ${action}`);
}

/** ng show dump, read through the agent (the only process with CAP_NET_ADMIN); the
 * kernel denies unprivileged wireguard netlink dumps. */
export async function agentVpnStatus(interfaceName: string): Promise<string> {
  const reply = await request({ op: "vpn_status", interface: interfaceName });
  if (!reply.ok) throw new Error(reply.error ?? "agent could not read tunnel status");
  return reply.dump ?? "";
}

const REFUSAL_REASON: Record<string, string> = {
  protected:
    "the agent's guard refuses it: own address, gateway, resolver, docker range or allowlist",
  rate_limited: "the agent's hourly block budget is spent",
  invalid_ip: "not a valid IP address",
  invalid_action_id: "the request is missing a canonical action UUID",
  missing_policy_version: "the request does not identify its policy version",
  invalid_ttl: "the requested expiry is not an integer number of minutes",
  ttl_out_of_range: "the requested expiry is outside 1 minute to 30 days",
  unauthorized_peer: "the operating-system peer is not authorized",
  action_id_conflict: "that action ID was already used for a different request",
  action_in_progress: "that action may have been interrupted; inspect actual firewall state",
  audit_unavailable: "the agent cannot durably record this action",
};

function request(payload: object, timeoutMs = TIMEOUT_MS): Promise<AgentReply> {
  return new Promise((resolve, reject) => {
    const socket = connect(SOCKET);
    const encoded = Buffer.from(JSON.stringify(payload));
    const frame = Buffer.allocUnsafe(encoded.length + 4);
    frame.writeUInt32BE(encoded.length, 0);
    encoded.copy(frame, 4);
    let body = Buffer.alloc(0);
    const fail = (error: Error) => {
      socket.destroy();
      reject(error);
    };
    socket.setTimeout(timeoutMs, () =>
      fail(new Error(`agent did not answer within ${timeoutMs}ms`)),
    );
    socket.on("connect", () => socket.end(frame));
    socket.on("data", (chunk) => {
      body = Buffer.concat([body, chunk]);
      if (body.length > MAX_REPLY + 4) fail(new Error("agent reply exceeds protocol limit"));
    });
    socket.on("error", (error) =>
      fail(new Error(`agent control socket ${SOCKET}: ${error.message}`)),
    );
    socket.on("close", () => {
      if (body.length < 4) return reject(new Error(`agent closed ${SOCKET} without replying`));
      try {
        const length = body.readUInt32BE(0);
        if (length < 1 || length > MAX_REPLY || body.length !== length + 4) {
          throw new Error(`invalid frame length ${length}`);
        }
        resolve(JSON.parse(body.subarray(4).toString("utf8")) as AgentReply);
      } catch {
        reject(
          new Error(`agent sent an invalid framed reply: ${body.subarray(0, 200).toString()}`),
        );
      }
    });
  });
}

export async function agentProcessName(flow: {
  proto: string;
  localIp: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  endedAt: string;
}): Promise<string | null> {
  if (flow.proto !== "TCP" && flow.proto !== "UDP") return null;
  const observedAt = Date.parse(flow.endedAt) / 1_000;
  if (!Number.isFinite(observedAt)) return null;
  const reply = await request(
    {
      op: "process_lookup",
      protocol: flow.proto,
      local_ip: flow.localIp,
      local_port: flow.localPort,
      remote_ip: flow.remoteIp,
      remote_port: flow.remotePort,
      observed_at: observedAt,
    },
    2_500,
  );
  if (!reply.ok) return null;
  return typeof reply.process_name === "string" ? reply.process_name : null;
}

/** Throws with the agent's own refusal wording so the action records why. */
export async function agentBlock(
  ip: string,
  actionId: string,
  by: string,
  reason: string,
  minutes?: number,
): Promise<{ seconds: number; offenses: number }> {
  const reply = await request({
    op: "block",
    ip,
    action_id: actionId,
    requested_by: by,
    reason,
    minutes: minutes ?? null,
    policy_version: POLICY_VERSION,
  });
  if (!reply.ok) {
    const refusal = reply.refused ? (REFUSAL_REASON[reply.refused] ?? reply.refused) : reply.error;
    throw new Error(`agent refused to block ${ip}: ${refusal ?? "unknown reason"}`);
  }
  return { seconds: reply.seconds ?? 0, offenses: reply.offenses ?? 0 };
}

export async function agentUnblock(
  ip: string,
  actionId: string,
  by: string,
  reason: string,
): Promise<void> {
  const reply = await request({
    op: "unblock",
    ip,
    action_id: actionId,
    requested_by: by,
    reason,
    policy_version: POLICY_VERSION,
  });
  if (!reply.ok)
    throw new Error(`agent could not unblock ${ip}: ${reply.error ?? "unknown reason"}`);
}

export async function agentFirewall(): Promise<FirewallState> {
  const reply = await request({ op: "list" });
  if (!reply.ok) throw new Error(reply.error ?? "agent could not read the nft table");
  return {
    blocked: reply.blocked ?? [],
    protected: reply.protected ?? [],
    blocksLastHour: reply.blocks_last_hour ?? 0,
    maxBlocksPerHour: reply.max_blocks_per_hour ?? 0,
  };
}
