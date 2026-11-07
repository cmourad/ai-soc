import { randomUUID } from "node:crypto";
import type { Alert, NotifyAttempt, OncallIncident, Person } from "@aisoc/shared";
import { broadcast } from "../bus.js";
import { getSettings } from "../settings.js";
import {
  addNotification,
  getAlert,
  getPage,
  listPages,
  upsertAlert,
  upsertPage,
} from "../store.js";
import { sendEmail } from "./email.js";
import { escapeHtml, inQuietHours, sendTelegram } from "./telegram.js";

const timers = new Map<string, NodeJS.Timeout>();

/**
 * Rotation order: whoever is on shift right now, then every other active person
 * in roster order. Escalation walks this list, so a no-ack always has somewhere
 * to go even outside scheduled hours.
 */
export function rotationFor(now = new Date()): Person[] {
  const { people, shifts } = getSettings().oncall;
  const active = people.filter((person) => person.active);
  const day = now.getDay();
  const hour = now.getHours();

  const onShift = new Set(
    shifts
      .filter((shift) => {
        if (!shift.days.includes(day)) return false;
        return shift.startHour <= shift.endHour
          ? hour >= shift.startHour && hour < shift.endHour
          : hour >= shift.startHour || hour < shift.endHour;
      })
      .map((shift) => shift.personId),
  );

  const primary = active.filter((person) => onShift.has(person.id));
  const rest = active.filter((person) => !onShift.has(person.id));
  return [...primary, ...rest];
}

function personById(id: string): Person | undefined {
  return getSettings().oncall.people.find((person) => person.id === id);
}

function describe(alert: Alert): string {
  const event = alert.event;
  const detection = alert.detection;
  const topHits = (detection?.hits ?? [])
    .slice(0, 3)
    .map((hit) => `• ${escapeHtml(hit.ruleId)} ${escapeHtml(hit.name)} (${hit.kind})`);
  const mitre = (detection?.mitre ?? [])
    .slice(0, 4)
    .map((ref) => `${ref.techniqueId} ${ref.technique}`)
    .join(", ");
  const actions = alert.responseIds.length;

  return [
    `<b>AI SOC — ${alert.stage === "needs_human" ? "needs a human" : alert.stage}</b>`,
    `<b>${escapeHtml(event.signature)}</b>`,
    `severity ${event.severity} · ${escapeHtml(event.category)}`,
    `${escapeHtml(event.srcIp)}:${event.srcPort} → ${escapeHtml(event.destIp)}:${event.destPort} (${event.proto})`,
    detection
      ? `detection: <b>${detection.score}/100 ${detection.band}</b> · ${detection.hits.length} hit${detection.hits.length === 1 ? "" : "s"}`
      : "",
    ...topHits,
    mitre ? `ATT&amp;CK: ${escapeHtml(mitre)}` : "",
    alert.enrichment
      ? `intel: ${escapeHtml(alert.enrichment.indicator)} reputation ${alert.enrichment.reputation}/100${alert.enrichment.country ? ` · ${escapeHtml(alert.enrichment.country)}` : ""}${alert.enrichment.asn ? ` · ${escapeHtml(alert.enrichment.asn)}` : ""}`
      : "",
    `verdict: <b>${alert.verdict ?? "none"}</b> @ ${alert.confidence.toFixed(2)} via ${escapeHtml(alert.model ?? "n/a")}`,
    alert.reason ? escapeHtml(alert.reason) : "",
    alert.escalationReason ? `escalated: ${escapeHtml(alert.escalationReason)}` : "",
    actions > 0
      ? `response: ${actions} action${actions === 1 ? "" : "s"} filed — review in the console`
      : "",
    `\nAck in the console (alert ${alert.id.slice(0, 8)}) or it escalates to the next person on call.`,
  ]
    .filter(Boolean)
    .join("\n");
}

function plainText(html: string): string {
  return html.replace(/<[^>]+>/g, "");
}

async function notifyPerson(incident: OncallIncident, person: Person, alert: Alert): Promise<void> {
  const settings = getSettings();
  const message = describe(alert);
  const attempts: NotifyAttempt[] = [];
  let delivered = false;

  const quiet = inQuietHours(alert.event.severity);
  if (settings.telegram.enabled && person.telegramId && !quiet) {
    const result = await sendTelegram(person.telegramId, message);
    attempts.push({
      at: new Date().toISOString(),
      personId: person.id,
      personName: person.name,
      channel: "telegram",
      ok: result.ok,
      error: result.ok ? null : result.error,
    });
    delivered = result.ok;
  }

  // Email is the fallback when Telegram is off, muted, or failed — or always,
  // if the operator asked for both.
  if (settings.smtp.enabled && person.email && (!delivered || settings.smtp.alwaysSend)) {
    const result = await sendEmail(
      person.email,
      `[AI SOC] ${alert.event.signature} (sev ${alert.event.severity})`,
      `${plainText(message)}\n\n${quiet ? "Sent by email: Telegram is muted by quiet hours.\n" : ""}`,
    );
    attempts.push({
      at: new Date().toISOString(),
      personId: person.id,
      personName: person.name,
      channel: "email",
      ok: result.ok,
      error: result.ok ? null : result.error,
    });
    delivered = delivered || result.ok;
  }

  if (attempts.length === 0) {
    attempts.push({
      at: new Date().toISOString(),
      personId: person.id,
      personName: person.name,
      channel: "telegram",
      ok: false,
      error: quiet
        ? "muted by quiet hours, no email fallback configured"
        : "no enabled channel for this person",
    });
  }

  incident.attempts.push(...attempts);
  upsertPage(incident);
}

function scheduleEscalation(incidentId: string): void {
  const minutes = getSettings().oncall.ackTimeoutMinutes;
  const existing = timers.get(incidentId);
  if (existing) clearTimeout(existing);
  const timer = setTimeout(() => {
    timers.delete(incidentId);
    void escalate(incidentId);
  }, minutes * 60_000);
  timers.set(incidentId, timer);

  const incident = getPage(incidentId);
  if (incident) {
    incident.nextEscalationAt = new Date(Date.now() + minutes * 60_000).toISOString();
    upsertPage(incident);
  }
}

async function escalate(incidentId: string): Promise<void> {
  const incident = getPage(incidentId);
  if (!incident || incident.acked || incident.closedAt) return;
  const alert = getAlert(incident.alertId);
  if (!alert) return;

  const nextIndex = incident.currentIndex + 1;
  const nextId = incident.rotation[nextIndex];
  if (!nextId) {
    incident.exhausted = true;
    incident.nextEscalationAt = null;
    upsertPage(incident);
    broadcast({
      type: "toast",
      level: "error",
      message: `On-call rotation exhausted for "${alert.event.signature}" — nobody acknowledged.`,
    });
    return;
  }

  incident.currentIndex = nextIndex;
  upsertPage(incident);
  const person = personById(nextId);
  if (person) {
    broadcast({
      type: "toast",
      level: "info",
      message: `No ack after ${getSettings().oncall.ackTimeoutMinutes}m — escalating to ${person.name}.`,
    });
    await notifyPerson(incident, person, alert);
  }
  scheduleEscalation(incidentId);
}

/** Called by the pipeline whenever an alert reaches a terminal stage. */
export function onAlertSettled(alert: Alert): void {
  const { oncall } = getSettings();
  if (!oncall.enabled) return;
  if (!oncall.notifyOnStages.includes(alert.stage)) return;
  if (alert.event.severity > oncall.minSeverity) return;
  if (alert.pageId) return;

  const rotation = rotationFor().map((person) => person.id);
  if (rotation.length === 0) {
    broadcast({
      type: "toast",
      level: "error",
      message: "On-call is enabled but no active personnel are configured.",
    });
    return;
  }

  const incident: OncallIncident = {
    id: randomUUID(),
    alertId: alert.id,
    createdAt: new Date().toISOString(),
    rotation,
    currentIndex: 0,
    attempts: [],
    acked: false,
    ackedBy: null,
    ackedAt: null,
    exhausted: false,
    nextEscalationAt: null,
    closedAt: null,
  };
  upsertPage(incident);
  alert.pageId = incident.id;
  upsertAlert(alert);
  addNotification({
    kind: "oncall",
    level: alert.event.severity === 1 ? "critical" : "warning",
    title: `Paging on-call — ${alert.event.signature}`,
    body: `Rotation of ${rotation.length}; escalates in ${oncall.ackTimeoutMinutes} minutes without an ack.`,
    linkView: "triage",
    linkId: alert.id,
  });

  const first = personById(rotation[0]!);
  if (first) void notifyPerson(incident, first, alert);
  scheduleEscalation(incident.id);
}

export function ackIncident(incidentId: string, by: string): OncallIncident | null {
  const incident = getPage(incidentId);
  if (!incident) return null;
  const timer = timers.get(incidentId);
  if (timer) {
    clearTimeout(timer);
    timers.delete(incidentId);
  }
  incident.acked = true;
  incident.ackedBy = by;
  incident.ackedAt = new Date().toISOString();
  incident.nextEscalationAt = null;
  incident.closedAt = new Date().toISOString();
  upsertPage(incident);
  return incident;
}

/** Restart escalation timers for incidents that survived a restart. */
export function resumeIncidents(): void {
  for (const incident of listPages()) {
    if (incident.acked || incident.closedAt || incident.exhausted) continue;
    scheduleEscalation(incident.id);
  }
}
