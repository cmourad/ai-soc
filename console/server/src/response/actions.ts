import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";
import type {
  Alert,
  AutonomyMode,
  Playbook,
  ResponseAction,
  ResponseOrigin,
  ResponseType,
} from "@aisoc/shared";
import { inNetwork } from "@aisoc/shared";
import { assetForEvent, setIsolation } from "../assets.js";
import { isLocal, remoteIp } from "../detect/engine.js";
import { recordActionOnIncident } from "../incidents/correlate.js";
import { allowlistEntry } from "../lists.js";
import { quarantineItem, restoreItem } from "../quarantine.js";
import { getSettings } from "../settings.js";
import {
  addAudit,
  addNotification,
  getAction,
  getAlert,
  listActions,
  listPlaybooks,
  listQuarantine,
  upsertAction,
  upsertAlert,
} from "../store.js";
import { activeEndpoints } from "../vpn/manager.js";
import { agentBlock, agentUnblock } from "./agent.js";
import { automaticResponseOriginHold } from "./policy.js";

const run = promisify(execFile);

/**
 * Response is the point where the console stops observing and starts acting, so
 * it is built around three rules:
 *
 *  1. Nothing acts without a deterministic reason. Every action names the
 *     detection hit or playbook that produced it; a model recommendation alone
 *     is recorded as a proposal, never self-executed.
 *  2. Guardrails are evaluated before autonomy, not after. Full autonomy still
 *     cannot block the gateway, an allowlisted indicator, or the console's own
 *     alerting path.
 *  3. Everything is reversible and attributed. Every action carries the exact
 *     command, who or what asked for it, and an undo.
 */

const ACTION_LABEL: Record<ResponseType, string> = {
  block_ip: "Block IP",
  block_domain: "Block domain",
  quarantine_file: "Quarantine file",
  isolate_host: "Isolate host",
  kill_process: "Kill process",
};

export function actionLabel(type: ResponseType): string {
  return ACTION_LABEL[type];
}

function commandFor(type: ResponseType, target: string, undo = false): string {
  switch (type) {
    case "block_ip":
    case "isolate_host":
      return `aisoc-agent ${undo ? "unblock" : "block"} ${target}`;
    case "block_domain":
      return undo
        ? `sed -i '/^0\\.0\\.0\\.0 ${target}$/d' /etc/aisoc/sinkhole.hosts`
        : `printf '0.0.0.0 %s\\n' ${target} >> /etc/aisoc/sinkhole.hosts`;
    case "quarantine_file":
      return undo
        ? `aisoc-vault restore ${target}`
        : `install -m 000 -o root -g root ${target} /var/lib/aisoc/vault/ && rm -f ${target}`;
    case "kill_process":
      return undo ? "" : `kill -9 ${target}`;
  }
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const DOMAIN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

/**
 * Targets reach the executor as command arguments, so they are validated to a
 * shape before anything is spawned — and spawned via argv, never a shell.
 */
function validTarget(type: ResponseType, target: string): boolean {
  if (type === "block_ip" || type === "isolate_host") return IPV4.test(target);
  if (type === "block_domain") return DOMAIN.test(target);
  if (type === "kill_process") return /^\d+$/.test(target);
  return target.startsWith("/") && !target.includes("..");
}

// --- Guardrails -------------------------------------------------------------

export function guardrailViolation(
  type: ResponseType,
  target: string,
  alert: Alert | null,
): string | null {
  const { response, site } = getSettings();
  const rails = response.guardrails;

  if (!validTarget(type, target)) {
    return `target "${target}" is not a valid ${type.replace(/_/g, " ")} target`;
  }
  if (rails.protectPrivateRanges && (type === "block_ip" || type === "block_domain")) {
    if (isLocal(target)) return "target is one of our own addresses";
  }
  if (rails.respectAllowlist) {
    const entry = allowlistEntry(target);
    if (entry) return `indicator is allowlisted: ${entry.note || entry.value}`;
  }
  if (type === "isolate_host") {
    const asset = alert ? assetForEvent(alert.event) : null;
    if (asset?.tags.includes("console")) {
      return "host runs this console — isolating it would sever the operator's own path";
    }
  }
  // Never firewall the address the console pages out through. Matching by
  // string prefix only ever worked for IPv4 and silently passed every v6
  // address straight through.
  if (type === "block_ip" && site.homeNetworks.some((cidr) => inNetwork(target, cidr))) {
    return "target is inside a declared home network";
  }
  // Blocking the live tunnel's own endpoint drops every route at once and looks
  // exactly like a clean containment until someone notices the box is offline.
  if (type === "block_ip" || type === "block_domain") {
    if (activeEndpoints().some((endpoint) => endpoint === target)) {
      return "target is the console's active VPN or remote endpoint — blocking it would cut every route";
    }
  }
  return null;
}

function appliedInLastHour(): number {
  const cutoff = Date.now() - 3_600_000;
  return listActions().filter(
    (action) =>
      action.status === "applied" &&
      action.origin !== "human" &&
      action.appliedAt !== null &&
      Date.parse(action.appliedAt) >= cutoff,
  ).length;
}

/**
 * Decides whether an action executes itself. Returns null to execute, or the
 * reason it is being held for a human.
 */
function autonomyHold(
  type: ResponseType,
  alert: Alert | null,
  autonomy: AutonomyMode,
): string | null {
  const rails = getSettings().response.guardrails;

  const originHold = automaticResponseOriginHold(alert);
  if (originHold) return originHold;
  if (rails.alwaysConfirm.includes(type)) {
    return `${ACTION_LABEL[type].toLowerCase()} always requires confirmation`;
  }
  if (autonomy === "manual") return "autonomy is set to manual confirmation";
  if (appliedInLastHour() >= rails.maxAutoActionsPerHour) {
    return `automatic action budget spent (${rails.maxAutoActionsPerHour}/hour)`;
  }
  if (autonomy === "full") return null;

  // Guarded: the deterministic layer must be confident on its own, and the
  // model must agree. Either one alone holds the action.
  const score = alert?.detection?.score ?? 0;
  if (score < rails.autoExecuteAtScore) {
    return `detection score ${score} is under the guarded threshold ${rails.autoExecuteAtScore}`;
  }
  if (alert && alert.verdict !== "BLOCK") {
    return `triage verdict is ${alert.verdict ?? "pending"}, not BLOCK`;
  }
  if (alert && alert.confidence < rails.autoExecuteAtConfidence) {
    return `verdict confidence ${alert.confidence.toFixed(2)} is under the guarded threshold ${rails.autoExecuteAtConfidence.toFixed(2)}`;
  }
  return null;
}

// --- Execution --------------------------------------------------------------

async function execute(action: ResponseAction): Promise<void> {
  const { response } = getSettings();

  if (response.execution === "simulate") {
    action.simulated = true;
  } else {
    action.simulated = false;
    try {
      if (action.type === "block_ip" || action.type === "isolate_host") {
        // Isolation is the same primitive as a block — drop both directions for
        // that address — so it goes through the agent too and inherits Guard.
        await agentBlock(action.target, action.id, action.requestedBy, action.reason);
      } else if (action.type === "kill_process") {
        await run("kill", ["-9", action.target]);
      } else {
        // The remaining actions need a privileged helper this console does not
        // ship; recording the command and holding the item is the honest result.
        action.simulated = true;
      }
    } catch (error) {
      action.status = "failed";
      action.error = error instanceof Error ? error.message : String(error);
      upsertAction(action);
      addAudit(action.requestedBy, `response.${action.type}`, action.target, action.error, false);
      return;
    }
  }

  // Side effects the console owns regardless of execution mode.
  if (action.type === "quarantine_file") {
    quarantineItem({
      kind: "file",
      value: action.target,
      alertId: action.alertId,
      assetId: action.assetId,
      actionId: action.id,
      reason: action.reason,
    });
  }
  if (action.type === "block_ip" || action.type === "block_domain") {
    quarantineItem({
      kind: action.type === "block_ip" ? "ip" : "domain",
      value: action.target,
      alertId: action.alertId,
      assetId: action.assetId,
      actionId: action.id,
      reason: action.reason,
    });
  }
  if (action.type === "isolate_host" && action.assetId) {
    setIsolation(action.assetId, true, action.requestedBy);
  }

  action.status = "applied";
  action.appliedAt = new Date().toISOString();
  action.error = null;
  upsertAction(action);
  recordActionOnIncident(action);

  addAudit(
    action.requestedBy,
    `response.${action.type}`,
    action.target,
    `${action.simulated ? "[simulated] " : ""}${action.command}`,
  );
  addNotification({
    kind: "response",
    level: "warning",
    title: `${ACTION_LABEL[action.type]} applied${action.simulated ? " (simulated)" : ""}`,
    body: `${action.target} — ${action.reason}`,
    linkView: "response",
    linkId: action.id,
  });
}

// --- Proposal ---------------------------------------------------------------

function targetFor(step: Playbook["steps"][number], alert: Alert): string | null {
  const event = alert.event;
  switch (step.targetFrom) {
    case "remote_ip": {
      const ip = remoteIp(event);
      return isLocal(ip) ? null : ip;
    }
    case "hostname":
      return event.sni ?? event.hostname ?? null;
    case "file_path":
      // Only files we can identify as a sample. During an encryptor run most
      // file events are the *victim's* data and the ransom note — quarantining
      // those takes the user's files away and preserves nothing useful. A hash
      // means the endpoint agent fingerprinted an artefact worth holding.
      return event.filePath && event.fileSha256 ? event.filePath : null;
    case "process":
      return event.processPid ? String(event.processPid) : null;
    case "asset":
      return assetForEvent(event)?.ip ?? null;
  }
}

function create(input: {
  alert: Alert | null;
  type: ResponseType;
  target: string;
  reason: string;
  origin: ResponseOrigin;
  requestedBy: string;
  playbookId: string | null;
}): ResponseAction {
  const { response } = getSettings();
  const asset = input.alert ? (assetForEvent(input.alert.event)?.id ?? null) : null;
  return {
    id: randomUUID(),
    alertId: input.alert?.id ?? null,
    incidentId: input.alert?.incidentId ?? null,
    assetId: asset,
    type: input.type,
    target: input.target,
    status: "pending_approval",
    origin: input.origin,
    requestedBy: input.requestedBy,
    reason: input.reason,
    autonomy: response.autonomy,
    guardrail: null,
    command: commandFor(input.type, input.target),
    simulated: response.execution === "simulate",
    playbookId: input.playbookId,
    createdAt: new Date().toISOString(),
    appliedAt: null,
    undoneAt: null,
    decidedBy: null,
    error: null,
  };
}

/**
 * An action already applied or already waiting for a human covers any later
 * proposal for the same target. Without this, a beacon checking in every 45
 * seconds files a fresh block for the same address every time, and the queue
 * becomes unreadable exactly when it matters.
 */
function supersededBy(type: ResponseType, target: string): ResponseAction | undefined {
  return listActions().find(
    (action) =>
      action.type === type &&
      action.target === target &&
      (action.status === "applied" || action.status === "pending_approval"),
  );
}

/** Records the action and either fires it or holds it, per guardrails then autonomy. */
async function submit(action: ResponseAction, alert: Alert | null): Promise<ResponseAction> {
  const existing = supersededBy(action.type, action.target);
  if (existing) return existing;

  const violation = guardrailViolation(action.type, action.target, alert);
  if (violation) {
    action.status = "blocked_by_guardrail";
    action.guardrail = violation;
    upsertAction(action);
    addAudit(
      action.requestedBy,
      `response.${action.type}.blocked`,
      action.target,
      violation,
      false,
    );
    return action;
  }

  const hold = autonomyHold(action.type, alert, getSettings().response.autonomy);
  if (hold) {
    action.status = "pending_approval";
    action.guardrail = hold;
    upsertAction(action);
    addNotification({
      kind: "response",
      level: "warning",
      title: `${ACTION_LABEL[action.type]} awaiting approval`,
      body: `${action.target} — ${hold}`,
      linkView: "response",
      linkId: action.id,
    });
    return action;
  }

  upsertAction(action);
  await execute(action);
  return action;
}

/**
 * Turns a settled alert into response proposals. Playbooks matched on detection
 * evidence come first; a lone BLOCK verdict with no matching playbook still
 * proposes the one obvious containment step.
 */
export async function proposeForAlert(alert: Alert): Promise<ResponseAction[]> {
  const settings = getSettings();
  if (!settings.response.enabled) return [];
  if (alert.verdict !== "BLOCK" && (alert.detection?.score ?? 0) < 60) return [];

  const hitIds = new Set((alert.detection?.hits ?? []).map((hit) => hit.ruleId));
  const tags = new Set(alert.event.tags);
  const score = alert.detection?.score ?? 0;

  const matched = listPlaybooks().filter(
    (playbook) =>
      playbook.enabled &&
      settings.response.enabledPlaybooks.includes(playbook.id) &&
      score >= playbook.minScore &&
      (playbook.triggerRuleIds.some((id) => hitIds.has(id)) ||
        playbook.triggerTags.some((tag) => tags.has(tag))),
  );

  const created: ResponseAction[] = [];
  const seen = new Set<string>();

  for (const playbook of matched) {
    for (const step of playbook.steps) {
      const target = targetFor(step, alert);
      if (!target) continue;
      const key = `${step.type}:${target}`;
      if (seen.has(key)) continue;
      seen.add(key);
      // An open action already covers this target. `submit` would hand the
      // existing one back, which the caller cannot tell apart from a new
      // proposal — and would then file it on the incident timeline a second time.
      if (supersededBy(step.type, target)) continue;
      created.push(
        await submit(
          create({
            alert,
            type: step.type,
            target,
            reason: `${playbook.name}: ${step.reason}`,
            origin: "playbook",
            requestedBy: `playbook:${playbook.id}`,
            playbookId: playbook.id,
          }),
          alert,
        ),
      );
    }
  }

  if (created.length === 0 && alert.verdict === "BLOCK") {
    const ip = remoteIp(alert.event);
    if (!isLocal(ip) && !supersededBy("block_ip", ip)) {
      const top = alert.detection?.hits[0];
      created.push(
        await submit(
          create({
            alert,
            type: "block_ip",
            target: ip,
            reason: top
              ? `${top.name} (${top.ruleId}) with a BLOCK verdict from ${alert.model ?? "triage"}.`
              : `BLOCK verdict from ${alert.model ?? "triage"}: ${alert.reason ?? "no reason recorded"}`,
            origin: top ? "engine" : "llm",
            requestedBy: top ? "detection-engine" : (alert.model ?? "triage"),
            playbookId: null,
          }),
          alert,
        ),
      );
    }
  }

  const fresh = created.filter((action) => !alert.responseIds.includes(action.id));
  if (fresh.length > 0) {
    alert.responseIds.push(...fresh.map((action) => action.id));
    upsertAlert(alert);
  }
  return fresh;
}

/** An analyst asking for an action directly. Guardrails still apply; autonomy does not. */
export async function requestManualAction(input: {
  alertId: string | null;
  type: ResponseType;
  target: string;
  reason: string;
  by: string;
}): Promise<ResponseAction> {
  const alert = input.alertId ? (getAlert(input.alertId) ?? null) : null;
  const action = create({
    alert,
    type: input.type,
    target: input.target,
    reason: input.reason || `Requested by ${input.by}.`,
    origin: "human",
    requestedBy: input.by,
    playbookId: null,
  });

  const violation = guardrailViolation(action.type, action.target, alert);
  if (violation) {
    action.status = "blocked_by_guardrail";
    action.guardrail = violation;
    upsertAction(action);
    addAudit(input.by, `response.${action.type}.blocked`, action.target, violation, false);
    return action;
  }

  upsertAction(action);
  await execute(action);
  if (alert) {
    alert.responseIds.push(action.id);
    upsertAlert(alert);
  }
  return action;
}

export async function approveAction(id: string, by: string): Promise<ResponseAction | null> {
  const action = getAction(id);
  if (action?.status !== "pending_approval") return null;
  action.decidedBy = by;
  action.guardrail = null;
  upsertAction(action);
  await execute(action);
  return action;
}

export function rejectAction(id: string, by: string): ResponseAction | null {
  const action = getAction(id);
  if (action?.status !== "pending_approval") return null;
  action.status = "rejected";
  action.decidedBy = by;
  upsertAction(action);
  recordActionOnIncident(action);
  addAudit(by, `response.${action.type}.reject`, action.target, action.reason);
  return action;
}

export async function undoAction(id: string, by: string): Promise<ResponseAction | null> {
  const action = getAction(id);
  if (action?.status !== "applied") return null;

  const undoCommand = commandFor(action.type, action.target, true);
  if (!action.simulated && undoCommand) {
    try {
      if (action.type === "block_ip" || action.type === "isolate_host") {
        await agentUnblock(action.target, randomUUID(), by, action.reason);
      }
    } catch (error) {
      action.error = error instanceof Error ? error.message : String(error);
      upsertAction(action);
      return action;
    }
  }

  if (action.type === "isolate_host" && action.assetId) setIsolation(action.assetId, false, by);
  for (const item of listQuarantine()) {
    if (item.actionId === action.id && item.status === "held") restoreItem(item.id, by);
  }

  action.status = "undone";
  action.undoneAt = new Date().toISOString();
  action.decidedBy = by;
  action.error = null;
  upsertAction(action);
  recordActionOnIncident(action);
  addAudit(
    by,
    `response.${action.type}.undo`,
    action.target,
    undoCommand || "reversed in the console",
  );
  addNotification({
    kind: "response",
    level: "info",
    title: `${ACTION_LABEL[action.type]} undone`,
    body: `${by} reversed the action on ${action.target}.`,
    linkView: "response",
    linkId: action.id,
  });
  return action;
}
