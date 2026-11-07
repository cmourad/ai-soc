import type { FastifyInstance } from "fastify";
import {
  addIncidentNote,
  assignIncident,
  narrate,
  setIncidentStatus,
} from "../incidents/correlate.js";
import { getIncident } from "../store.js";

/** Correlated incident lifecycle. */
export function registerIncidentRoutes(app: FastifyInstance): void {
  // --- Incidents --------------------------------------------------------------

  app.post<{ Params: { id: string } }>("/api/incidents/:id/status", async (request, reply) => {
    const body = request.body as { status?: string };
    const status = body.status ?? "";
    if (!["open", "investigating", "contained", "closed"].includes(status)) {
      return reply.code(400).send({ ok: false, error: "unknown status" });
    }
    const incident = setIncidentStatus(
      request.params.id,
      status as "open" | "investigating" | "contained" | "closed",
      request.actor,
    );
    if (!incident) return reply.code(404).send({ ok: false, error: "unknown incident" });
    return { ok: true, incident };
  });

  app.post<{ Params: { id: string } }>("/api/incidents/:id/assign", async (request, reply) => {
    const body = request.body as { assignee?: string };
    const incident = assignIncident(
      request.params.id,
      (body.assignee ?? "").slice(0, 100),
      request.actor,
    );
    if (!incident) return reply.code(404).send({ ok: false, error: "unknown incident" });
    return { ok: true, incident };
  });

  app.post<{ Params: { id: string } }>("/api/incidents/:id/note", async (request, reply) => {
    const body = request.body as { body?: string };
    const incident = addIncidentNote(
      request.params.id,
      request.actor,
      (body.body ?? "").slice(0, 2_000),
    );
    if (!incident) return reply.code(404).send({ ok: false, error: "unknown incident" });
    return { ok: true, incident };
  });

  app.post<{ Params: { id: string } }>("/api/incidents/:id/narrate", async (request, reply) => {
    if (!getIncident(request.params.id)) {
      return reply.code(404).send({ ok: false, error: "unknown incident" });
    }
    void narrate(request.params.id);
    return { ok: true };
  });
}
