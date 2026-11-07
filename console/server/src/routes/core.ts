import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { broadcast } from "../bus.js";
import { REMOTE_PORT } from "../config.js";
import { secretPresence, setSecret } from "../crypto.js";
import { RULES } from "../detect/rules.js";
import { describeError } from "../http.js";
import { publishLocalNetworks } from "../ingest.js";
import { compassSummary, invalidateCompassSummary } from "../network/state.js";
import { sendEmail } from "../notify/email.js";
import { rotationFor } from "../notify/oncall.js";
import { sendTelegram } from "../notify/telegram.js";
import { computeStats, snapshot } from "../projection.js";
import { configureRemoteAccess } from "../remoteaccess/manager.js";
import { getSettings, updateSettings } from "../settings.js";
import { SCENARIOS } from "../sources/scenarios.js";
import { addAudit } from "../store.js";

/** Health, snapshot, settings and secrets. */
export function registerCoreRoutes(app: FastifyInstance, remote: boolean): void {
  // Deliberately does no work. aisoc-console-health.timer restarts the backend
  // after two failed probes, and computeStats() walks every collection — under
  // load the probe was capable of causing the outage it exists to detect.
  app.get("/api/health", async () => ({ ok: true, uptime: Math.floor(process.uptime()) }));

  app.get("/api/snapshot", async () => snapshot(!remote));

  app.get("/api/oncall/rotation", async () => rotationFor());

  /** The rule catalogue, so the UI can show what the engine is capable of matching. */

  app.get("/api/detection/rules", async () =>
    RULES.map((rule) => ({
      id: rule.id,
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      score: rule.score,
      confidence: rule.confidence,
      origin: rule.origin,
      mitre: rule.mitre,
    })),
  );

  app.get("/api/scenarios", async () =>
    SCENARIOS.map((scenario) => ({
      id: scenario.id,
      name: scenario.name,
      description: scenario.description,
      steps: scenario.steps.length,
    })),
  );

  app.post("/api/settings", async (request, reply) => {
    if (
      remote &&
      request.body &&
      typeof request.body === "object" &&
      "networkCompass" in request.body
    ) {
      return reply.code(403).send({ ok: false, error: "Network Compass settings are local-only" });
    }
    try {
      const settings = updateSettings(request.body);
      publishLocalNetworks();
      addAudit(request.actor, "settings.update", "console", "Settings saved.");
      broadcast({ type: "settings", settings, secrets: secretPresence() });
      // Retention, history and exclusions all change what the summary means.
      invalidateCompassSummary();
      broadcast({ type: "compass", summary: compassSummary() });
      broadcast({ type: "stats", stats: computeStats() });
      void configureRemoteAccess(REMOTE_PORT);
      return { ok: true, settings };
    } catch (error) {
      return reply.code(400).send({ ok: false, error: describeError(error) });
    }
  });

  const secretBody = z.object({ name: z.string().min(1).max(100), value: z.string().max(5_000) });

  app.post("/api/secrets", async (request, reply) => {
    const parsed = secretBody.safeParse(request.body);
    if (!parsed.success)
      return reply.code(400).send({ ok: false, error: "invalid secret payload" });
    setSecret(parsed.data.name, parsed.data.value);
    addAudit(
      request.actor,
      parsed.data.value ? "secret.store" : "secret.clear",
      parsed.data.name,
      "Secret updated; the value never leaves the server.",
    );
    broadcast({ type: "settings", settings: getSettings(), secrets: secretPresence() });
    return { ok: true };
  });

  app.post("/api/telegram/test", async () => {
    const { telegram } = getSettings();
    const result = await sendTelegram(
      telegram.chatId,
      "<b>AI SOC console</b>\nTest message — Telegram alerting is wired up correctly.",
    );
    broadcast({
      type: "toast",
      level: result.ok ? "success" : "error",
      message: result.ok ? "Telegram test message sent." : `Telegram test failed: ${result.error}`,
    });
    return result;
  });

  app.post("/api/smtp/test", async (request) => {
    const to = (request.body as { to?: string })?.to ?? getSettings().smtp.from;
    const result = await sendEmail(
      to,
      "[AI SOC] SMTP test",
      "Test message — the AI SOC console can reach this SMTP server.",
    );
    broadcast({
      type: "toast",
      level: result.ok ? "success" : "error",
      message: result.ok ? `Test email sent to ${to}.` : `SMTP test failed: ${result.error}`,
    });
    return result;
  });
}
