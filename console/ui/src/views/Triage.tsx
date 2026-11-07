import type { Alert, TriageStage } from "@aisoc/shared";
import { useEffect, useMemo, useState } from "react";
import { ScoreBar } from "@/components/security";
import { Badge, Button } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import {
  bandColor,
  cn,
  severityBg,
  severityLabel,
  shortAge,
  timeOf,
  verdictColor,
} from "@/lib/utils";
import { useStore } from "@/store";

const STAGES: { id: TriageStage | "all"; label: string }[] = [
  { id: "all", label: "all" },
  { id: "pending", label: "pending" },
  { id: "first_triage", label: "first triage" },
  { id: "second_triage", label: "second triage" },
  { id: "needs_human", label: "needs a human" },
  { id: "resolved", label: "resolved" },
];

const STAGE_STYLE: Record<TriageStage, string> = {
  pending: "border-edge text-ink-dim",
  first_triage: "border-[#3f5f7a] text-[#8ab4d8]",
  second_triage: "border-[#6a4f7a] text-[#c99ce0]",
  needs_human: "border-[#7a5a2d] text-sev2",
  resolved: "border-[#2d5a3d] text-ignore",
};

function StageBadge({ stage }: { stage: TriageStage }) {
  return <Badge className={cn("font-mono", STAGE_STYLE[stage])}>{stage.replace(/_/g, " ")}</Badge>;
}

function ConfidenceBar({ value }: { value: number }) {
  const tone = value >= 0.8 ? "bg-ignore" : value >= 0.6 ? "bg-watch" : "bg-block";
  return (
    <div className="flex items-center gap-1.5">
      <div className="h-1 w-12 overflow-hidden rounded-full bg-edge">
        <div className={cn("h-full", tone)} style={{ width: `${Math.round(value * 100)}%` }} />
      </div>
      <span className="font-mono text-[10px] text-ink-dim tabular-nums">{value.toFixed(2)}</span>
    </div>
  );
}

function AlertRow({ alert, selected, now }: { alert: Alert; selected: boolean; now: number }) {
  const selectAlert = useStore((s) => s.selectAlert);
  const incident = useStore((s) => s.pages.find((page) => page.id === alert.pageId));

  return (
    <button
      type="button"
      onClick={() => selectAlert(alert.id)}
      className={cn(
        "row-in grid w-full grid-cols-[62px_10px_1fr_96px_120px_100px_130px_70px_80px] items-center gap-2 px-3 py-1 text-left text-[11px]",
        selected ? "bg-active" : "hover:bg-hover",
      )}
    >
      <span className="font-mono text-ink-dim tabular-nums">{timeOf(alert.createdAt)}</span>
      <span
        className={cn("h-2 w-2 rounded-full", severityBg(alert.event.severity))}
        title={severityLabel(alert.event.severity)}
      />
      <span className="min-w-0">
        <span className="block truncate font-mono text-ink" title={alert.event.signature}>
          {alert.event.signature}
        </span>
        {alert.detection && alert.detection.hits.length > 0 ? (
          <span className="block truncate text-[10px] text-ink-dim">
            {alert.detection.hits
              .slice(0, 3)
              .map((hit) => hit.ruleId)
              .join(" · ")}
          </span>
        ) : null}
      </span>
      <span className="flex items-center gap-1.5">
        <ScoreBar score={alert.detection?.score ?? 0} width="w-8" />
        {alert.detection ? (
          <span className={cn("text-[9px] uppercase", bandColor(alert.detection.band))}>
            {alert.detection.band.slice(0, 4)}
          </span>
        ) : null}
      </span>
      <StageBadge stage={alert.stage} />
      <span className={cn("font-mono font-semibold", verdictColor(alert.verdict))}>
        {alert.verdict ?? "—"}
      </span>
      <ConfidenceBar value={alert.confidence} />
      <span className="truncate font-mono text-[10px] text-ink-dim" title={alert.model ?? ""}>
        {alert.model ?? "—"}
      </span>
      <span className="flex items-center gap-1 font-mono text-[10px] text-ink-dim tabular-nums">
        {shortAge(alert.createdAt, now)}
        {incident && !incident.acked && !incident.exhausted ? (
          <span className="pulse h-1.5 w-1.5 rounded-full bg-sev2" title="Paging on-call" />
        ) : null}
        {incident?.exhausted ? (
          <span className="h-1.5 w-1.5 rounded-full bg-sev1" title="Rotation exhausted" />
        ) : null}
      </span>
    </button>
  );
}

export function TriageView() {
  const alerts = useStore((s) => s.alerts);
  const stageFilter = useStore((s) => s.stageFilter);
  const setStageFilter = useStore((s) => s.setStageFilter);
  const selectedAlertId = useStore((s) => s.selectedAlertId);
  const stats = useStore((s) => s.stats);
  const pushToast = useStore((s) => s.pushToast);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1_000);
    return () => clearInterval(timer);
  }, []);

  const visible = useMemo(() => {
    const filtered =
      stageFilter === "all" ? alerts : alerts.filter((alert) => alert.stage === stageFilter);
    return [...filtered].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }, [alerts, stageFilter]);

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-center gap-2 border-b border-edge bg-panel px-3 py-1.5">
        {STAGES.map((stage) => {
          const count =
            stage.id === "all" ? alerts.length : (stats?.byStage[stage.id as TriageStage] ?? 0);
          return (
            <button
              key={stage.id}
              type="button"
              onClick={() => setStageFilter(stage.id)}
              className={cn(
                "rounded-sm px-2 py-0.5 text-[11px] transition-colors",
                stageFilter === stage.id ? "bg-active text-ink" : "text-ink-dim hover:text-ink",
              )}
            >
              {stage.label}
              <span className="ml-1.5 font-mono text-[10px] tabular-nums opacity-70">{count}</span>
            </button>
          );
        })}

        <Button
          size="sm"
          variant="outline"
          className="ml-auto"
          onClick={() => {
            api
              .oncallDrill()
              .then(() => pushToast("info", "On-call drill fired — watch the rotation escalate."))
              .catch((error: Error) => pushToast("error", error.message));
          }}
          title="Fire a synthetic critical alert into on-call routing"
        >
          on-call drill
        </Button>
      </div>

      <div className="grid shrink-0 grid-cols-[62px_10px_1fr_96px_120px_100px_130px_70px_80px] gap-2 border-b border-edge bg-panel px-3 py-1 text-[10px] uppercase tracking-wide text-ink-dim">
        <span>opened</span>
        <span />
        <span>signature · engine hits</span>
        <span>detection</span>
        <span>stage</span>
        <span>verdict</span>
        <span>confidence</span>
        <span>model</span>
        <span>elapsed</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {visible.length === 0 ? (
          <p className="p-6 text-center text-xs text-ink-dim">
            Nothing in this stage yet. Alerts enter the queue when an event's severity is at or
            below the configured triage threshold.
          </p>
        ) : (
          visible.map((alert) => (
            <AlertRow
              key={alert.id}
              alert={alert}
              selected={alert.id === selectedAlertId}
              now={now}
            />
          ))
        )}
      </div>
    </div>
  );
}
