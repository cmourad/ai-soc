import { randomUUID } from "node:crypto";
import type { ExportKind, IocType, Report, ResponseType, Severity } from "@aisoc/shared";
import {
  listActions,
  listAlerts,
  listAssets,
  listAudit,
  listIncidents,
  listQuarantine,
} from "./store.js";

/**
 * Reporting reads the live store rather than a separate rollup table. At this
 * scale that is exact rather than approximate, and it removes a whole class of
 * "the dashboard disagrees with the queue" bug.
 */

function windowFor(period: "daily" | "weekly"): { from: Date; to: Date; previousFrom: Date } {
  const to = new Date();
  const days = period === "daily" ? 1 : 7;
  const from = new Date(to.getTime() - days * 86_400_000);
  const previousFrom = new Date(from.getTime() - days * 86_400_000);
  return { from, to, previousFrom };
}

const within = (iso: string, from: Date, to: Date): boolean => {
  const at = Date.parse(iso);
  return at >= from.getTime() && at <= to.getTime();
};

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? Math.round((sorted[middle - 1]! + sorted[middle]!) / 2)
    : sorted[middle]!;
}

function delta(current: number, previous: number): number | null {
  if (previous === 0) return current === 0 ? 0 : null;
  return Math.round(((current - previous) / previous) * 100);
}

export function buildReport(period: "daily" | "weekly"): Report {
  const { from, to, previousFrom } = windowFor(period);
  const alerts = listAlerts();
  const current = alerts.filter((alert) => within(alert.createdAt, from, to));
  const previous = alerts.filter((alert) => within(alert.createdAt, previousFrom, from));

  const resolved = current.filter((alert) => alert.resolvedAt);
  const dwellSeconds = resolved.map(
    (alert) => (Date.parse(alert.resolvedAt!) - Date.parse(alert.createdAt)) / 1000,
  );
  const autoResolved = resolved.filter((alert) => !alert.humanOverride).length;

  const actions = listActions().filter((action) => within(action.createdAt, from, to));
  const incidents = listIncidents().filter((incident) => within(incident.createdAt, from, to));

  const metrics = [
    {
      label: "Alerts opened",
      value: current.length,
      delta: delta(current.length, previous.length),
      unit: "",
    },
    {
      label: "Malicious",
      value: current.filter((alert) => alert.detection?.band === "malicious").length,
      delta: delta(
        current.filter((alert) => alert.detection?.band === "malicious").length,
        previous.filter((alert) => alert.detection?.band === "malicious").length,
      ),
      unit: "",
    },
    { label: "Incidents", value: incidents.length, delta: null, unit: "" },
    {
      label: "Median time to verdict",
      value: median(dwellSeconds),
      delta: null,
      unit: "s",
    },
    {
      label: "Auto-resolved",
      value: resolved.length > 0 ? Math.round((autoResolved / resolved.length) * 100) : 0,
      delta: null,
      unit: "%",
    },
    {
      label: "Response actions applied",
      value: actions.filter((action) => action.status === "applied").length,
      delta: null,
      unit: "",
    },
    {
      label: "Awaiting approval",
      value: actions.filter((action) => action.status === "pending_approval").length,
      delta: null,
      unit: "",
    },
    {
      label: "Held in quarantine",
      value: listQuarantine().filter((item) => item.status === "held").length,
      delta: null,
      unit: "",
    },
  ];

  const vectors = new Map<string, { count: number; severity: Severity }>();
  for (const alert of current) {
    const top = alert.detection?.hits[0];
    const name = top ? top.name : alert.event.category;
    const existing = vectors.get(name);
    vectors.set(name, {
      count: (existing?.count ?? 0) + 1,
      severity: Math.min(existing?.severity ?? 4, alert.event.severity) as Severity,
    });
  }

  const targets = new Map<string, { hostname: string; alerts: number; risk: number }>();
  for (const asset of listAssets()) {
    const count = current.filter((alert) => alert.assetId === asset.id).length;
    if (count === 0 && asset.riskScore === 0) continue;
    targets.set(asset.id, { hostname: asset.hostname, alerts: count, risk: asset.riskScore });
  }

  const indicators = new Map<string, { type: IocType; hits: number; reputation: number }>();
  for (const alert of current) {
    if (!alert.enrichment) continue;
    const key = alert.enrichment.indicator;
    const existing = indicators.get(key);
    indicators.set(key, {
      type: alert.enrichment.type,
      hits: (existing?.hits ?? 0) + 1,
      reputation: Math.max(existing?.reputation ?? 0, alert.enrichment.reputation),
    });
  }

  const mitreCount = new Map<string, { technique: string; tactic: string; count: number }>();
  for (const alert of current) {
    for (const ref of alert.detection?.mitre ?? []) {
      const existing = mitreCount.get(ref.techniqueId);
      mitreCount.set(ref.techniqueId, {
        technique: ref.technique,
        tactic: ref.tactic,
        count: (existing?.count ?? 0) + 1,
      });
    }
  }

  const responseTypes: ResponseType[] = [
    "block_ip",
    "block_domain",
    "quarantine_file",
    "isolate_host",
    "kill_process",
  ];

  return {
    id: randomUUID(),
    period,
    generatedAt: new Date().toISOString(),
    from: from.toISOString(),
    to: to.toISOString(),
    metrics,
    topVectors: [...vectors.entries()]
      .map(([name, value]) => ({ name, ...value }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8),
    topTargets: [...targets.entries()]
      .map(([assetId, value]) => ({ assetId, ...value }))
      .sort((a, b) => b.risk - a.risk || b.alerts - a.alerts)
      .slice(0, 8),
    topIndicators: [...indicators.entries()]
      .map(([value, rest]) => ({ value, ...rest }))
      .sort((a, b) => b.reputation - a.reputation || b.hits - a.hits)
      .slice(0, 8),
    mitreCoverage: [...mitreCount.entries()]
      .map(([techniqueId, value]) => ({ techniqueId, ...value }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 12),
    responseSummary: responseTypes.map((type) => ({
      type,
      applied: actions.filter((a) => a.type === type && a.status === "applied").length,
      pending: actions.filter((a) => a.type === type && a.status === "pending_approval").length,
      undone: actions.filter((a) => a.type === type && a.status === "undone").length,
    })),
    narrative: null,
  };
}

// --- Export -----------------------------------------------------------------

function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function toCsv(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) return "";
  const columns = [...new Set(rows.flatMap((row) => Object.keys(row)))];
  const lines = [columns.join(",")];
  for (const row of rows) lines.push(columns.map((column) => csvCell(row[column])).join(","));
  return `${lines.join("\n")}\n`;
}

function rowsFor(kind: ExportKind): Record<string, unknown>[] {
  switch (kind) {
    case "alerts":
      return listAlerts().map((alert) => ({
        id: alert.id,
        createdAt: alert.createdAt,
        resolvedAt: alert.resolvedAt,
        stage: alert.stage,
        verdict: alert.verdict,
        confidence: alert.confidence,
        model: alert.model,
        severity: alert.event.severity,
        signature: alert.event.signature,
        category: alert.event.category,
        srcIp: alert.event.srcIp,
        destIp: alert.event.destIp,
        destPort: alert.event.destPort,
        detectionScore: alert.detection?.score ?? "",
        detectionBand: alert.detection?.band ?? "",
        detectionHits: alert.detection?.hits.map((hit) => hit.ruleId).join(" ") ?? "",
        mitre: alert.detection?.mitre.map((ref) => ref.techniqueId).join(" ") ?? "",
        reputation: alert.enrichment?.reputation ?? "",
        country: alert.enrichment?.country ?? "",
        assetId: alert.assetId ?? "",
        incidentId: alert.incidentId ?? "",
        overriddenBy: alert.humanOverride?.by ?? "",
        reason: alert.reason ?? "",
      }));
    case "incidents":
      return listIncidents().map((incident) => ({
        ref: incident.ref,
        title: incident.title,
        status: incident.status,
        severity: incident.severity,
        score: incident.score,
        correlatedOn: incident.correlationBasis,
        alerts: incident.alertIds.length,
        assets: incident.assetIds.join(" "),
        mitre: incident.mitre.map((ref) => ref.techniqueId).join(" "),
        assignee: incident.assignee ?? "",
        createdAt: incident.createdAt,
        closedAt: incident.closedAt ?? "",
        narrative: incident.narrative ?? "",
      }));
    case "actions":
      return listActions().map((action) => ({
        id: action.id,
        createdAt: action.createdAt,
        type: action.type,
        target: action.target,
        status: action.status,
        origin: action.origin,
        requestedBy: action.requestedBy,
        autonomy: action.autonomy,
        guardrail: action.guardrail ?? "",
        simulated: action.simulated,
        command: action.command,
        appliedAt: action.appliedAt ?? "",
        undoneAt: action.undoneAt ?? "",
        decidedBy: action.decidedBy ?? "",
        reason: action.reason,
      }));
    case "audit":
      return listAudit().map((entry) => ({ ...entry }));
    case "quarantine":
      return listQuarantine().map((item) => ({ ...item }));
    case "assets":
      return listAssets().map((asset) => ({
        id: asset.id,
        hostname: asset.hostname,
        ip: asset.ip,
        os: asset.os,
        kind: asset.kind,
        owner: asset.owner,
        online: asset.online,
        isolated: asset.isolated,
        riskScore: asset.riskScore,
        openAlerts: asset.openAlerts,
        criticalAlerts: asset.criticalAlerts,
        realtime: asset.protection.realtime,
        firewall: asset.protection.firewall,
        rulesVersion: asset.protection.rulesVersion,
        agentVersion: asset.protection.agentVersion,
        lastScan: asset.protection.lastScan ?? "",
        lastSeen: asset.lastSeen,
      }));
  }
}

export function exportData(kind: ExportKind, format: "csv" | "json"): string {
  const rows = rowsFor(kind);
  return format === "csv" ? toCsv(rows) : JSON.stringify(rows, null, 2);
}
