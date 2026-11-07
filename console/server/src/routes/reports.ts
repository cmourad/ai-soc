import { EXPORT_KINDS, isExportKind } from "@aisoc/shared";
import type { FastifyInstance } from "fastify";
import { buildReport, exportData } from "../reports.js";
import { addAudit, markNotificationsRead } from "../store.js";

/** Reporting, data export and notification state. */
export function registerReportRoutes(app: FastifyInstance): void {
  // --- Notifications ----------------------------------------------------------

  app.post("/api/notifications/read", async (request) => {
    const body = request.body as { ids?: string[] } | undefined;
    return { ok: true, ids: markNotificationsRead(body?.ids ?? null) };
  });

  // --- Reports and export -----------------------------------------------------

  app.get<{ Querystring: { period?: string } }>("/api/reports", async (request) =>
    buildReport(request.query.period === "weekly" ? "weekly" : "daily"),
  );

  app.get<{ Params: { kind: string }; Querystring: { format?: string } }>(
    "/api/export/:kind",
    async (request, reply) => {
      const kind = request.params.kind;
      if (!isExportKind(kind)) {
        return reply.code(404).send({ ok: false, error: "unknown export" });
      }
      const format = request.query.format === "json" ? "json" : "csv";
      const body = exportData(kind, format);
      addAudit(request.actor, "export", kind, `Exported ${kind} as ${format}.`);
      return reply
        .header("content-type", format === "json" ? "application/json" : "text/csv")
        .header(
          "content-disposition",
          `attachment; filename="aisoc-${kind}-${new Date().toISOString().slice(0, 10)}.${format}"`,
        )
        .send(body);
    },
  );
}
