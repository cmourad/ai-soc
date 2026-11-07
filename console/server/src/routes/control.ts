import { randomUUID } from "node:crypto";
import type { Alert, SecurityEvent } from "@aisoc/shared";
import type { FastifyInstance } from "fastify";
import { broadcast } from "../bus.js";
import { secretPresence } from "../crypto.js";
import { handleEvent } from "../ingest.js";
import { ackIncident, onAlertSettled } from "../notify/oncall.js";
import { controlService, getServiceStatus, isServiceAction } from "../services.js";
import { getSettings, updateSettings } from "../settings.js";
import { fireScenario } from "../sources/seed.js";
import { addAudit, addEvent, upsertAlert } from "../store.js";

/** Operator control surface: pause, services, drills, acks. */
export function registerControlRoutes(app: FastifyInstance): void {
  // --- Control ----------------------------------------------------------------

  app.post<{ Params: { id: string } }>("/api/incidents/:id/ack", async (request, reply) => {
    const incident = ackIncident(request.params.id, request.actor);
    if (!incident) return reply.code(404).send({ ok: false, error: "unknown page" });
    addAudit(request.actor, "oncall.ack", incident.id.slice(0, 8), "Acknowledged the page.");
    broadcast({
      type: "toast",
      level: "success",
      message: `${request.actor} acknowledged the page.`,
    });
    return { ok: true, incident };
  });

  app.post("/api/control/pause", async () => {
    const settings = updateSettings({ ingest: { paused: true } });
    broadcast({ type: "settings", settings, secrets: secretPresence() });
    return { ok: true };
  });

  app.post("/api/control/resume", async () => {
    const settings = updateSettings({ ingest: { paused: false } });
    broadcast({ type: "settings", settings, secrets: secretPresence() });
    return { ok: true };
  });

  app.get("/api/services", async () => {
    return { ok: true, groups: await getServiceStatus() };
  });

  app.post<{ Params: { name: string; action: string } }>(
    "/api/services/:name/:action",
    async (request, reply) => {
      const action = request.params.action;
      if (!isServiceAction(action)) {
        return reply.code(400).send({ ok: false, error: "invalid action" });
      }
      const result = await controlService(request.params.name, action);
      if (!result.ok) return reply.code(500).send(result);
      addAudit(
        request.actor,
        "service.control",
        request.params.name,
        `${action} ${request.params.name}`,
      );
      broadcast({ type: "toast", level: "success", message: `${action} ${request.params.name}` });
      return result;
    },
  );

  /** Runs one scripted attack immediately so any feature can be demonstrated on demand. */

  app.post<{ Params: { id: string } }>("/api/scenarios/:id/fire", async (request, reply) => {
    const scenario = fireScenario(request.params.id, handleEvent);
    if (!scenario) return reply.code(404).send({ ok: false, error: "unknown scenario" });
    addAudit(
      request.actor,
      "scenario.fire",
      scenario.name,
      `${scenario.steps.length} events queued.`,
    );
    broadcast({
      type: "toast",
      level: "info",
      message: `Running "${scenario.name}" — ${scenario.steps.length} events over the next few seconds.`,
    });
    return { ok: true, scenario: scenario.id };
  });

  /**

   * Fires a synthetic critical alert straight into on-call routing so the

   * rotation and no-ack escalation can be demonstrated without waiting for the

   * seeded stream to produce one.

   */

  app.post("/api/oncall/drill", async (_request, reply) => {
    const settings = getSettings();
    if (!settings.oncall.enabled) {
      return reply.code(400).send({ ok: false, error: "on-call routing is disabled" });
    }
    const event: SecurityEvent = {
      id: randomUUID(),
      ts: new Date().toISOString(),
      srcIp: "203.0.113.66",
      srcPort: 51_820,
      destIp: "192.0.2.9",
      destPort: 8080,
      proto: "TCP",
      appProto: "http",
      signature: "AISOC DRILL Synthetic on-call routing test",
      signatureId: 9_000_001,
      category: "Attempted Administrator Privilege Gain",
      severity: 1,
      tags: ["drill", "oncall"],
      direction: "to_server",
      bytesToServer: 1_024,
      bytesToClient: 3_200,
      source: "seed",
    };
    addEvent(event);

    const alert: Alert = {
      id: randomUUID(),
      origin: "event",
      event,
      stage: "needs_human",
      verdict: "WATCH",
      confidence: 0.5,
      model: "drill",
      reason: "Synthetic drill alert — routed to on-call to exercise ack and escalation.",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      resolvedAt: null,
      escalationReason: "on-call drill",
      humanOverride: null,
      notes: [],
      llmCallIds: [],
      incidentId: null,
      pageId: null,
      detection: null,
      enrichment: null,
      assetId: null,
      responseIds: [],
    };
    upsertAlert(alert);
    onAlertSettled(alert);
    return { ok: true, alertId: alert.id };
  });
}
