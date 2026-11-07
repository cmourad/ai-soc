import { randomUUID } from "node:crypto";
import type { ResponseType } from "@aisoc/shared";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { broadcast } from "../bus.js";
import { describeError } from "../http.js";
import {
  approveAction,
  rejectAction,
  requestManualAction,
  undoAction,
} from "../response/actions.js";
import { agentFirewall, agentUnblock } from "../response/agent.js";
import { addAudit } from "../store.js";

/** Proposing, approving and undoing containment actions. */
export function registerResponseRoutes(app: FastifyInstance): void {
  // --- Response ---------------------------------------------------------------

  const actionBody = z.object({
    alertId: z.string().max(100).nullable().default(null),
    type: z.enum(["block_ip", "block_domain", "quarantine_file", "isolate_host", "kill_process"]),
    target: z.string().min(1).max(300),
    reason: z.string().max(1_000).default(""),
  });

  app.post("/api/actions", async (request, reply) => {
    const parsed = actionBody.safeParse(request.body);
    if (!parsed.success)
      return reply.code(400).send({ ok: false, error: describeError(parsed.error) });
    const action = await requestManualAction({
      alertId: parsed.data.alertId,
      type: parsed.data.type,
      target: parsed.data.target,
      reason: parsed.data.reason,
      by: request.actor,
    });
    if (action.status === "blocked_by_guardrail") {
      broadcast({
        type: "toast",
        level: "error",
        message: `Guardrail refused the action: ${action.guardrail}`,
      });
    }
    return { ok: true, action };
  });

  app.post<{ Params: { id: string } }>("/api/actions/:id/approve", async (request, reply) => {
    const action = await approveAction(request.params.id, request.actor);
    if (!action) return reply.code(404).send({ ok: false, error: "no action awaiting approval" });
    return { ok: true, action };
  });

  app.post<{ Params: { id: string } }>("/api/actions/:id/reject", async (request, reply) => {
    const action = rejectAction(request.params.id, request.actor);
    if (!action) return reply.code(404).send({ ok: false, error: "no action awaiting approval" });
    return { ok: true, action };
  });

  app.post<{ Params: { id: string } }>("/api/actions/:id/undo", async (request, reply) => {
    const action = await undoAction(request.params.id, request.actor);
    if (!action) return reply.code(404).send({ ok: false, error: "action is not undoable" });
    return { ok: true, action };
  });

  // The firewall views read straight from the agent's nft table rather than
  // from console state: what is actually enforced is the agent's answer, and a
  // cached copy here would drift every time an element expires on its own.
  app.get("/api/firewall", async () => {
    try {
      return { ok: true, ...(await agentFirewall()) };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  });

  app.post<{ Body: { ip?: string } }>("/api/firewall/unblock", async (request, reply) => {
    const ip = String(request.body?.ip ?? "");
    if (!ip) return reply.code(400).send({ ok: false, error: "ip is required" });
    try {
      await agentUnblock(ip, randomUUID(), request.actor, "Lifted from the console firewall view.");
      addAudit(request.actor, "firewall.unblock", ip, "Asked the agent to lift the block.");
      return { ok: true };
    } catch (error) {
      return reply
        .code(502)
        .send({ ok: false, error: error instanceof Error ? error.message : String(error) });
    }
  });
}
