import type { Verdict } from "@aisoc/shared";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { addComment, applyHumanOverride, requeue } from "../triage/pipeline.js";

/** Human interaction with a triaged alert: override, comment, requeue. */
export function registerAlertRoutes(app: FastifyInstance): void {
  // --- Alerts -----------------------------------------------------------------

  const overrideBody = z.object({
    verdict: z.enum(["BLOCK", "WATCH", "IGNORE"]),
    note: z.string().max(2_000).default(""),
  });

  app.post<{ Params: { id: string } }>("/api/alerts/:id/override", async (request, reply) => {
    const parsed = overrideBody.safeParse(request.body);
    if (!parsed.success)
      return reply.code(400).send({ ok: false, error: "invalid override payload" });
    const alert = applyHumanOverride(
      request.params.id,
      parsed.data.verdict,
      request.actor,
      parsed.data.note,
    );
    if (!alert) return reply.code(404).send({ ok: false, error: "unknown alert" });
    return { ok: true, alert };
  });

  app.post<{ Params: { id: string } }>("/api/alerts/:id/comment", async (request, reply) => {
    const body = request.body as { author?: string; body?: string };
    const alert = addComment(request.params.id, request.actor, (body.body ?? "").slice(0, 2_000));
    if (!alert) return reply.code(404).send({ ok: false, error: "unknown alert" });
    return { ok: true, alert };
  });

  app.post<{ Params: { id: string } }>("/api/alerts/:id/requeue", async (request, reply) => {
    if (!requeue(request.params.id))
      return reply.code(404).send({ ok: false, error: "unknown alert" });
    return { ok: true };
  });
}
