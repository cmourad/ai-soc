import type { Report } from "@aisoc/shared";
import { EXPORT_KINDS } from "@aisoc/shared";
import { Download, Package, RefreshCw, TrendingDown, TrendingUp } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Stat } from "@/components/security";
import { Badge, Button, Input, SectionTitle } from "@/components/ui/primitives";
import { api, exportUrl } from "@/lib/api";
import { cn, riskBg, severityBg, timeOf, titleCase } from "@/lib/utils";
import { useStore } from "@/store";

function Bars({ rows }: { rows: { label: string; value: number; tone?: string }[] }) {
  const max = Math.max(1, ...rows.map((row) => row.value));
  return (
    <div className="flex flex-col gap-1">
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-[1fr_90px_36px] items-center gap-2">
          <span className="truncate text-[11px] text-ink" title={row.label}>
            {row.label}
          </span>
          <span className="h-1.5 overflow-hidden rounded-full bg-edge">
            <span
              className={cn("block h-full", row.tone ?? "bg-status")}
              style={{ width: `${(row.value / max) * 100}%` }}
            />
          </span>
          <span className="text-right font-mono text-[11px] text-ink-dim tabular-nums">
            {row.value}
          </span>
        </div>
      ))}
      {rows.length === 0 ? (
        <p className="text-[11px] text-ink-dim">Nothing in this window.</p>
      ) : null}
    </div>
  );
}

function ReportBody({ report }: { report: Report }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-8">
        {report.metrics.map((metric) => (
          <Stat
            key={metric.label}
            label={metric.label}
            value={`${metric.value}${metric.unit}`}
            hint={
              metric.delta === null ? undefined : (
                <span
                  className={cn(
                    "flex items-center gap-1",
                    metric.delta > 0 ? "text-sev2" : metric.delta < 0 ? "text-ignore" : "",
                  )}
                >
                  {metric.delta > 0 ? (
                    <TrendingUp className="h-2.5 w-2.5" />
                  ) : metric.delta < 0 ? (
                    <TrendingDown className="h-2.5 w-2.5" />
                  ) : null}
                  {metric.delta > 0 ? "+" : ""}
                  {metric.delta}% vs previous
                </span>
              )
            }
          />
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <SectionTitle>Top attack vectors</SectionTitle>
          <Bars
            rows={report.topVectors.map((vector) => ({
              label: vector.name,
              value: vector.count,
              tone: severityBg(vector.severity),
            }))}
          />
        </div>

        <div>
          <SectionTitle>Most targeted hosts</SectionTitle>
          <Bars
            rows={report.topTargets.map((target) => ({
              label: `${target.hostname} · risk ${target.risk}`,
              value: target.alerts,
              tone: riskBg(target.risk),
            }))}
          />
        </div>

        <div>
          <SectionTitle>Top indicators</SectionTitle>
          <Bars
            rows={report.topIndicators.map((indicator) => ({
              label: `${indicator.value} · reputation ${indicator.reputation}`,
              value: indicator.hits,
              tone: riskBg(indicator.reputation),
            }))}
          />
        </div>

        <div>
          <SectionTitle>ATT&amp;CK techniques observed</SectionTitle>
          <Bars
            rows={report.mitreCoverage.map((entry) => ({
              label: `${entry.techniqueId} ${entry.technique} · ${entry.tactic}`,
              value: entry.count,
              tone: "bg-[#7a7ab4]",
            }))}
          />
        </div>
      </div>

      <div>
        <SectionTitle>Response metrics</SectionTitle>
        <div className="grid gap-1 md:grid-cols-5">
          {report.responseSummary.map((row) => (
            <div key={row.type} className="rounded-sm border border-edge bg-panel p-2">
              <div className="truncate text-[10px] uppercase tracking-wide text-ink-dim">
                {titleCase(row.type)}
              </div>
              <div className="mt-1 flex items-baseline gap-2 font-mono text-[11px]">
                <span className="text-ignore">{row.applied} applied</span>
                <span className="text-sev2">{row.pending} pending</span>
              </div>
              <div className="font-mono text-[10px] text-ink-dim">{row.undone} undone</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function RulePacks() {
  const rulePacks = useStore((s) => s.rulePacks);
  const pushToast = useStore((s) => s.pushToast);
  const [busy, setBusy] = useState(false);

  return (
    <div>
      <div className="flex items-center gap-2">
        <SectionTitle>Rule and indicator packs</SectionTitle>
        <Button
          size="sm"
          variant="outline"
          className="mb-2 ml-auto"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            api
              .updateRulePacks()
              .catch((error: Error) => pushToast("error", error.message))
              .finally(() => setBusy(false));
          }}
        >
          <RefreshCw className={cn("h-3 w-3", busy && "animate-spin")} />
          check for updates
        </Button>
      </div>
      <div className="grid gap-1 md:grid-cols-2">
        {rulePacks.map((pack) => (
          <div key={pack.id} className="rounded-sm border border-edge bg-panel p-2">
            <div className="flex items-center gap-2">
              <Package className="h-3 w-3 shrink-0 text-ink-dim" />
              <span className="truncate text-[11px] text-ink">{pack.name}</span>
              <Badge className="ml-auto shrink-0 font-mono text-ink-dim">{pack.version}</Badge>
              <Button
                size="sm"
                variant="ghost"
                className="shrink-0"
                onClick={() =>
                  api
                    .toggleRulePack(pack.id)
                    .catch((error: Error) => pushToast("error", error.message))
                }
              >
                {pack.enabled ? "disable" : "enable"}
              </Button>
            </div>
            <div className="mt-1 flex flex-wrap gap-x-4 text-[10px] text-ink-dim">
              <span>{pack.entries} entries</span>
              <span>{pack.kind}</span>
              <span className="truncate">{pack.origin}</span>
              <span>updated {new Date(pack.updatedAt).toLocaleDateString()}</span>
              {!pack.enabled ? <span className="text-block">disabled</span> : null}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function AuditLog() {
  const audit = useStore((s) => s.audit);
  const [query, setQuery] = useState("");

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const list = needle
      ? audit.filter((entry) =>
          `${entry.actor} ${entry.action} ${entry.target} ${entry.detail}`
            .toLowerCase()
            .includes(needle),
        )
      : audit;
    return [...list].reverse().slice(0, 300);
  }, [audit, query]);

  return (
    <div>
      <div className="flex items-center gap-2">
        <SectionTitle>Audit log</SectionTitle>
        <Input
          className="mb-2 ml-auto w-64"
          value={query}
          placeholder="filter by actor, action, target…"
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>
      <div className="max-h-[420px] overflow-y-auto rounded-sm border border-edge">
        {visible.map((entry) => (
          <div
            key={entry.id}
            className="grid grid-cols-[54px_90px_150px_1fr] items-center gap-2 border-b border-edge/60 bg-panel px-2 py-1 text-[11px] last:border-b-0"
          >
            <span className="font-mono text-[10px] text-ink-dim tabular-nums">
              {timeOf(entry.at)}
            </span>
            <span className="truncate font-mono text-ink">{entry.actor}</span>
            <span className={cn("truncate font-mono", entry.ok ? "text-[#8ab4d8]" : "text-block")}>
              {entry.action}
            </span>
            <span className="min-w-0">
              <span className="block truncate text-ink">{entry.target}</span>
              <span className="block truncate text-[10px] text-ink-dim">{entry.detail}</span>
            </span>
          </div>
        ))}
        {visible.length === 0 ? (
          <p className="bg-panel p-4 text-center text-xs text-ink-dim">
            Nothing recorded yet. Overrides, response decisions, list edits, exports, and settings
            changes all land here.
          </p>
        ) : null}
      </div>
    </div>
  );
}

export function ReportsView() {
  const pushToast = useStore((s) => s.pushToast);
  const [period, setPeriod] = useState<"daily" | "weekly">("daily");
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    api
      .report(period)
      .then(setReport)
      .catch((error: Error) => pushToast("error", error.message))
      .finally(() => setLoading(false));
  }, [period, pushToast]);

  return (
    <div className="h-full overflow-y-auto">
      <div className="flex flex-col gap-5 p-4">
        <div className="flex flex-wrap items-center gap-2">
          {(["daily", "weekly"] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => setPeriod(value)}
              className={cn(
                "rounded-sm px-2 py-0.5 text-[11px] transition-colors",
                period === value ? "bg-active text-ink" : "text-ink-dim hover:text-ink",
              )}
            >
              {value} summary
            </button>
          ))}
          {report ? (
            <span className="text-[10px] text-ink-dim">
              {new Date(report.from).toLocaleString()} → {new Date(report.to).toLocaleString()}
            </span>
          ) : null}

          <span className="ml-auto flex flex-wrap items-center gap-1.5">
            <span className="text-[10px] uppercase tracking-wide text-ink-dim">Export</span>
            {EXPORT_KINDS.map((kind) => (
              <span key={kind} className="flex items-center">
                <a
                  href={exportUrl(kind, "csv")}
                  download
                  className="flex h-6 items-center gap-1 rounded-l-sm border border-edge px-2 text-[11px] text-ink hover:bg-hover"
                >
                  <Download className="h-3 w-3" />
                  {kind}
                </a>
                <a
                  href={exportUrl(kind, "json")}
                  download
                  className="flex h-6 items-center rounded-r-sm border border-l-0 border-edge px-1.5 text-[10px] text-ink-dim hover:bg-hover hover:text-ink"
                  title={`${kind} as JSON`}
                >
                  json
                </a>
              </span>
            ))}
          </span>
        </div>

        {report ? (
          <ReportBody report={report} />
        ) : (
          <p className="p-6 text-center text-xs text-ink-dim">
            {loading ? "Building the report…" : "No report."}
          </p>
        )}

        <RulePacks />
        <AuditLog />
      </div>
    </div>
  );
}
