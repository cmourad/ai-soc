import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { clearAssistanceChats } from "../assistant/chat.js";
import { describeError } from "../http.js";
import { dnsSummary, setBlockingEnabled } from "../network/dns.js";
import { reviewCompass } from "../network/review.js";
import {
  clearCompassData,
  compassSummary,
  getCompassReview,
  setCompassReview,
  setInsightFeedback,
} from "../network/state.js";
import { getSettings } from "../settings.js";
import { addAudit, clearCompassLlmCalls } from "../store.js";

/** Network Compass and resolver routes. */
export function registerCompassRoutes(app: FastifyInstance, remote: boolean): void {
  // Network Compass contains browsing metadata and is intentionally local-only,
  // even for an otherwise authenticated tailnet operator.
  app.get("/api/compass", async (_request, reply) => {
    if (remote) return reply.code(403).send({ ok: false, error: "Network Compass is local-only" });
    return { ok: true, summary: compassSummary() };
  });

  // The resolver ledger names every site this host visited, so it carries the
  // same browsing metadata as Compass and gets the same local-only guard.
  app.get("/api/dns", async (_request, reply) => {
    if (remote) return reply.code(403).send({ ok: false, error: "DNS activity is local-only" });
    return { ok: true, summary: await dnsSummary() };
  });

  // Pausing blocking is a network-wide change, so it gets the same local-only
  // guard as reading the resolver ledger.
  app.post("/api/dns/blocking", async (request, reply) => {
    if (remote) return reply.code(403).send({ ok: false, error: "DNS activity is local-only" });
    const parsed = z.object({ enabled: z.boolean() }).safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ ok: false, error: "expected { enabled: boolean }" });
    }
    const { enabled } = parsed.data;
    try {
      await setBlockingEnabled(enabled);
      addAudit(
        request.actor,
        enabled ? "dns.blocking.resume" : "dns.blocking.pause",
        "resolver",
        enabled
          ? "Resumed DNS blocking for every client."
          : "Paused DNS blocking for every client.",
      );
      return { ok: true };
    } catch (error) {
      const detail = describeError(error);
      addAudit(
        request.actor,
        enabled ? "dns.blocking.resume" : "dns.blocking.pause",
        "resolver",
        detail,
        false,
      );
      return reply.code(502).send({ ok: false, error: detail });
    }
  });

  app.post("/api/compass/forget", async (request, reply) => {
    if (remote) return reply.code(403).send({ ok: false, error: "Network Compass is local-only" });
    clearCompassData();
    clearAssistanceChats("compass");
    clearCompassLlmCalls();
    addAudit(
      request.actor,
      "compass.forget",
      "network-compass",
      "Deleted retained flows, recommendation feedback and conversations.",
    );
    return { ok: true, summary: compassSummary() };
  });

  // The one Compass path that sends anything off the machine, so it is gated
  // twice: local-only like the rest, and behind an explicit setting that is off
  // by default. It never runs on a timer — only when the operator asks.
  let reviewInFlight: Promise<void> | null = null;

  app.post("/api/compass/review", async (request, reply) => {
    if (remote) return reply.code(403).send({ ok: false, error: "Network Compass is local-only" });
    const compass = getSettings().networkCompass;
    if (!compass.enabled || !compass.aiReviewEnabled) {
      return reply.code(403).send({ ok: false, error: "AI review is turned off for Compass" });
    }
    if (reviewInFlight) return reply.code(409).send({ ok: false, error: "a review is running" });

    addAudit(
      request.actor,
      "compass.review",
      "network-compass",
      "Sent the aggregate site table to the first-tier model.",
    );
    reviewInFlight = (async () => {
      setCompassReview(await reviewCompass(compassSummary()));
    })().finally(() => {
      reviewInFlight = null;
    });
    await reviewInFlight;
    return { ok: true, review: getCompassReview() };
  });

  const compassFeedbackBody = z.object({
    id: z
      .string()
      .max(120)
      .regex(/^[a-z-]+:[a-z0-9.:_-]+$/),
    status: z.enum(["dismissed", "snoozed"]),
  });

  app.post("/api/compass/feedback", async (request, reply) => {
    if (remote) return reply.code(403).send({ ok: false, error: "Network Compass is local-only" });
    const parsed = compassFeedbackBody.safeParse(request.body);
    if (!parsed.success)
      return reply.code(400).send({ ok: false, error: "invalid Compass feedback" });
    const snoozedUntil =
      parsed.data.status === "snoozed" ? new Date(Date.now() + 7 * 86_400_000).toISOString() : null;
    setInsightFeedback(parsed.data.id, parsed.data.status, snoozedUntil);
    addAudit(
      request.actor,
      `compass.${parsed.data.status}`,
      parsed.data.id,
      "Insight feedback recorded locally.",
    );
    return { ok: true, summary: compassSummary() };
  });
}
