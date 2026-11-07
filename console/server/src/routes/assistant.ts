import type { AssistanceSubjectKind } from "@aisoc/shared";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import {
  deleteAssistanceChat,
  getAssistanceChat,
  listAllAssistanceChats,
  listAssistanceChats,
  sendAssistanceMessage,
} from "../assistant/chat.js";
import { listAnalystModels } from "../assistant/models.js";
import { describeError } from "../http.js";
import { getSettings } from "../settings.js";
import { addAudit } from "../store.js";

/** Analyst chat over an immutable investigation snapshot. */
export function registerAssistantRoutes(app: FastifyInstance, remote: boolean): void {
  const assistanceSubject = z.object({
    subjectKind: z.enum(["alert", "incident", "dns", "compass"]),
    // The resolver snapshot and the traffic review are singletons, not stored
    // rows with an id.
    subjectId: z.union([z.string().uuid(), z.literal("current")]),
  });

  // Both of these subjects carry browsing metadata that /api/dns and
  // /api/compass already keep off the tailnet.
  const localOnlySubject = (kind: AssistanceSubjectKind) => kind === "dns" || kind === "compass";

  const SUBJECT_NOUN: Record<AssistanceSubjectKind, string> = {
    alert: "alert",
    incident: "incident",
    dns: "resolver snapshot",
    compass: "traffic review",
  };

  const assistanceBody = assistanceSubject.extend({
    message: z.string().trim().min(1).max(2_000),
    model: z.string().max(205).optional(),
  });

  const assistanceHandler = async (
    request: FastifyRequest<{ Params: { id?: string } }>,
    reply: FastifyReply,
  ) => {
    const parsed = assistanceBody.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, error: "invalid assistant message" });
    }
    if (remote && localOnlySubject(parsed.data.subjectKind)) {
      return reply.code(403).send({ ok: false, error: "That evidence is local-only" });
    }
    if (parsed.data.subjectKind === "compass") {
      const compass = getSettings().networkCompass;
      if (!compass.enabled || !compass.aiReviewEnabled) {
        return reply.code(403).send({ ok: false, error: "AI review is turned off for Compass" });
      }
    }
    try {
      const chat = await sendAssistanceMessage({
        chatId: request.params.id ?? null,
        subjectKind: parsed.data.subjectKind,
        subjectId: parsed.data.subjectId,
        question: parsed.data.message,
        model: parsed.data.model ?? "secondTriage",
      });
      addAudit(
        request.actor,
        "assistant.chat",
        `${chat.subjectKind}:${chat.subjectId}`,
        `Asked ${chat.model} a follow-up question about this ${SUBJECT_NOUN[chat.subjectKind]}.`,
      );
      return { ok: true, chat };
    } catch (error) {
      return reply.code(400).send({ ok: false, error: describeError(error) });
    }
  };

  app.get<{
    Querystring: { subjectKind?: string; subjectId?: string };
  }>("/api/assistant/chat", async (request, reply) => {
    if (request.query.subjectKind === undefined && request.query.subjectId === undefined) {
      const chats = listAllAssistanceChats();
      return {
        ok: true,
        chats: remote ? chats.filter((chat) => !localOnlySubject(chat.subjectKind)) : chats,
      };
    }
    const parsed = assistanceSubject.safeParse(request.query);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, error: "invalid assistant subject" });
    }
    if (remote && localOnlySubject(parsed.data.subjectKind)) {
      return reply.code(403).send({ ok: false, error: "That evidence is local-only" });
    }
    return {
      ok: true,
      chats: listAssistanceChats(parsed.data.subjectKind, parsed.data.subjectId),
    };
  });

  app.get("/api/assistant/chat/models", async () => ({
    ok: true,
    models: await listAnalystModels(),
  }));

  app.post("/api/assistant/chat", assistanceHandler);

  app.post<{ Params: { id: string } }>("/api/assistant/chat/:id", assistanceHandler);

  app.delete<{ Params: { id: string } }>("/api/assistant/chat/:id", async (request, reply) => {
    const existing = getAssistanceChat(request.params.id);
    if (!existing) {
      return reply.code(404).send({ ok: false, error: "no such conversation" });
    }
    if (remote && localOnlySubject(existing.subjectKind)) {
      return reply.code(403).send({ ok: false, error: "That evidence is local-only" });
    }
    deleteAssistanceChat(request.params.id);
    addAudit(
      request.actor,
      "assistant.chat.delete",
      request.params.id,
      "Deleted an assistant conversation.",
    );
    return { ok: true };
  });
}
