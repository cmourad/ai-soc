import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { setIsolation } from "../assets.js";
import { describeError } from "../http.js";
import { addListEntry, removeListEntry } from "../lists.js";
import { deleteItem, restoreItem } from "../quarantine.js";

/** Assets, quarantine and the allow/block lists. */
export function registerAssetRoutes(app: FastifyInstance): void {
  // --- Assets -----------------------------------------------------------------

  app.post<{ Params: { id: string } }>("/api/assets/:id/isolate", async (request, reply) => {
    const body = request.body as { isolated?: boolean };
    const asset = setIsolation(request.params.id, body.isolated !== false, request.actor);
    if (!asset) return reply.code(404).send({ ok: false, error: "unknown asset" });
    return { ok: true, asset };
  });

  // --- Quarantine and lists ---------------------------------------------------

  app.post<{ Params: { id: string } }>("/api/quarantine/:id/restore", async (request, reply) => {
    const item = restoreItem(request.params.id, request.actor);
    if (!item) return reply.code(404).send({ ok: false, error: "nothing held under that id" });
    return { ok: true, item };
  });

  app.post<{ Params: { id: string } }>("/api/quarantine/:id/delete", async (request, reply) => {
    const item = deleteItem(request.params.id, request.actor);
    if (!item) return reply.code(404).send({ ok: false, error: "nothing held under that id" });
    return { ok: true, item };
  });

  const listBody = z.object({
    list: z.enum(["allow", "block"]),
    kind: z.enum(["ip", "domain", "hash", "url", "signature"]),
    value: z.string().min(1).max(300),
    note: z.string().max(500).default(""),
    expiresAt: z.string().max(40).nullable().default(null),
  });

  app.post("/api/lists", async (request, reply) => {
    const parsed = listBody.safeParse(request.body);
    if (!parsed.success)
      return reply.code(400).send({ ok: false, error: describeError(parsed.error) });
    const entry = addListEntry({
      list: parsed.data.list,
      kind: parsed.data.kind,
      value: parsed.data.value.trim(),
      note: parsed.data.note,
      addedBy: request.actor,
      expiresAt: parsed.data.expiresAt,
    });
    return { ok: true, entry };
  });

  app.post<{ Params: { id: string } }>("/api/lists/:id/remove", async (request, reply) => {
    if (!removeListEntry(request.params.id, request.actor)) {
      return reply.code(404).send({ ok: false, error: "unknown list entry" });
    }
    return { ok: true };
  });
}
