import type { DetectionRun, LlmCall, Verdict } from "@aisoc/shared";
import { ChevronDown, ChevronRight, Loader2 } from "lucide-react";
import { useMemo, useState } from "react";
import { HitRow, MitreChips, ScoreBar } from "@/components/security";
import { Badge, Button } from "@/components/ui/primitives";
import { bandColor, cn, timeOf, verdictColor } from "@/lib/utils";
import { useStore } from "@/store";

const STATUS_STYLE: Record<LlmCall["status"], string> = {
  running: "border-[#3f5f7a] text-[#8ab4d8]",
  ok: "border-[#2d5a3d] text-ignore",
  error: "border-[#5a2d2d] text-block",
  timeout: "border-[#7a5a2d] text-sev2",
};

function Block({ title, body, mono = true }: { title: string; body: string; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="text-[10px] uppercase tracking-wide text-ink-dim">{title}</div>
      <pre
        className={cn(
          "max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-sm border border-edge bg-shell p-2 text-[11px] leading-relaxed text-ink",
          mono && "font-mono",
        )}
      >
        {body}
      </pre>
    </div>
  );
}

function CallRow({ call }: { call: LlmCall }) {
  const [open, setOpen] = useState(false);
  const selectAlert = useStore((s) => s.selectAlert);
  const setView = useStore((s) => s.setView);

  return (
    <div className="border-b border-edge/60">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className={cn(
          "row-in grid w-full grid-cols-[16px_62px_110px_1fr_90px_80px_80px_90px] items-center gap-2 px-3 py-1 text-left text-[11px]",
          open ? "bg-active" : "hover:bg-hover",
        )}
      >
        {open ? (
          <ChevronDown className="h-3 w-3 text-ink-dim" />
        ) : (
          <ChevronRight className="h-3 w-3 text-ink-dim" />
        )}
        <span className="font-mono text-ink-dim tabular-nums">{timeOf(call.startedAt)}</span>
        <Badge className="font-mono text-ink-dim">{call.stage.replace(/_/g, " ")}</Badge>
        <span className="flex min-w-0 items-center gap-1.5">
          <span className="truncate font-mono text-ink" title={call.model}>
            {call.model}
          </span>
          {call.batchAlertIds ? (
            <Badge
              className="shrink-0 border-[#3f5f7a] text-[#8ab4d8]"
              title={`One model call covering ${call.batchAlertIds.length} alerts`}
            >
              batch ×{call.batchAlertIds.length}
            </Badge>
          ) : null}
        </span>
        <Badge className={cn("font-mono", STATUS_STYLE[call.status])}>
          {call.status === "running" ? <Loader2 className="mr-1 h-2.5 w-2.5 animate-spin" /> : null}
          {call.status}
        </Badge>
        <span className={cn("font-mono font-semibold", verdictColor(verdictOf(call)))}>
          {verdictOf(call) ??
            (call.stage === "compass_review"
              ? "review"
              : call.stage === "compass_chat" || call.stage === "assistant_chat"
                ? "reply"
                : call.stage === "incident_narrative"
                  ? "narrative"
                  : "—")}
        </span>
        <span className="font-mono text-[10px] text-ink-dim tabular-nums">
          {call.latencyMs !== null ? `${(call.latencyMs / 1000).toFixed(1)}s` : "…"}
        </span>
        <span className="font-mono text-[10px] text-ink-dim tabular-nums">
          {call.tokens ? `${call.tokens.total} tok` : "—"}
        </span>
      </button>

      {open ? (
        <div className="flex flex-col gap-3 border-t border-edge bg-panel px-3 py-3">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-[10px] text-ink-dim">
            <span>
              provider <span className="font-mono text-ink">{call.provider}</span>
            </span>
            <span>
              endpoint <span className="font-mono text-ink">{call.endpoint}</span>
            </span>
            <span>
              max tokens <span className="font-mono text-ink">{call.maxTokens}</span>
            </span>
            {call.provider === "openai-compatible" ? (
              <span>
                temperature <span className="font-mono text-ink">{call.temperature}</span>
              </span>
            ) : null}
            {call.schemaEnforced !== null ? (
              <span
                title={
                  call.schemaEnforced
                    ? "The verdict shape was constrained at the sampler, not just requested in the prompt."
                    : "The schema was only asked for in the prompt and checked afterwards."
                }
              >
                schema{" "}
                <span
                  className={call.schemaEnforced ? "font-mono text-ignore" : "font-mono text-sev2"}
                >
                  {call.schemaEnforced ? "sampler-enforced" : "prompt-only"}
                </span>
              </span>
            ) : null}
            {call.tokens === null && call.status === "ok" ? (
              <span className="text-ink-dim">tokens not reported by this provider</span>
            ) : null}
            {call.tokens ? (
              <span>
                tokens{" "}
                <span className="font-mono text-ink">
                  {call.tokens.prompt} in / {call.tokens.completion} out
                </span>
              </span>
            ) : null}
            {call.batchAlertIds ? (
              <span>
                covers{" "}
                <span className="font-mono text-ink">{call.batchAlertIds.length} alerts</span> in
                one call
              </span>
            ) : null}
            {call.alertId ? (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  selectAlert(call.alertId!);
                  setView("triage");
                }}
              >
                open alert
              </Button>
            ) : null}
          </div>

          {call.decisionApplied ? (
            <div className="rounded-sm border border-[#3f5f7a] bg-[#182430] px-2 py-1.5 text-[11px] text-[#a8cbe8]">
              <span className="font-semibold">
                {call.batchAlertIds ? "Decisions applied" : "Decision applied"}:{" "}
              </span>
              <span className="whitespace-pre-line">{call.decisionApplied}</span>
            </div>
          ) : null}

          {call.error ? (
            <div className="rounded-sm border border-[#5a2d2d] bg-[#321e1e] px-2 py-1.5 text-[11px] text-[#f5b8b8]">
              <span className="font-semibold">Error: </span>
              {call.error}
            </div>
          ) : null}

          <div className="grid gap-3 lg:grid-cols-2">
            <Block title="System prompt" body={call.systemPrompt} mono={false} />
            <Block title="Input sent to the model" body={call.userPrompt} />
          </div>

          {call.reasoning ? (
            <Block title="Model reasoning" body={call.reasoning} mono={false} />
          ) : null}
          {call.rawResponse ? <Block title="Raw model output" body={call.rawResponse} /> : null}
          {call.parsed ? (
            <Block
              title={
                call.stage === "compass_review"
                  ? "Parsed review"
                  : call.stage === "compass_chat" || call.stage === "assistant_chat"
                    ? "Parsed reply"
                    : call.stage === "incident_narrative"
                      ? "Parsed narrative"
                      : "Parsed verdict"
              }
              body={JSON.stringify(call.parsed, null, 2)}
            />
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function DetectionRunRow({ run }: { run: DetectionRun }) {
  const [open, setOpen] = useState(false);
  const selectAlert = useStore((s) => s.selectAlert);
  const setView = useStore((s) => s.setView);

  return (
    <div className="border-b border-edge/60">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className={cn(
          "row-in grid w-full grid-cols-[16px_62px_110px_1fr_90px_80px_80px_90px] items-center gap-2 px-3 py-1 text-left text-[11px]",
          open ? "bg-active" : "hover:bg-hover",
        )}
      >
        {open ? (
          <ChevronDown className="h-3 w-3 text-ink-dim" />
        ) : (
          <ChevronRight className="h-3 w-3 text-ink-dim" />
        )}
        <span className="font-mono text-ink-dim tabular-nums">{timeOf(run.ranAt)}</span>
        <Badge className="border-[#7a3d5a] font-mono text-[#e08ab4]">detection</Badge>
        <span className="min-w-0">
          <span className="block truncate font-mono text-ink" title={run.signature}>
            {run.hits[0]?.name ?? run.signature}
          </span>
          <span className="block truncate text-[10px] text-ink-dim">
            {run.hits.length > 0
              ? run.hits.map((hit) => hit.ruleId).join(" · ")
              : "no first-party match"}
          </span>
        </span>
        <Badge className={cn("font-mono", bandColor(run.band))}>{run.band}</Badge>
        <ScoreBar score={run.score} width="w-10" />
        <span className="font-mono text-[10px] text-ink-dim tabular-nums">{run.durationMs}ms</span>
        <span className="font-mono text-[10px] text-ink-dim tabular-nums">
          {run.hits.length} hit{run.hits.length === 1 ? "" : "s"}
        </span>
      </button>

      {open ? (
        <div className="flex flex-col gap-2 border-t border-edge bg-panel px-3 py-3">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-[10px] text-ink-dim">
            <span>
              engine <span className="font-mono text-ink">{run.engineVersion}</span>
            </span>
            <span>
              remote <span className="font-mono text-ink">{run.remoteIp}</span>
            </span>
            <span>
              event <span className="font-mono text-ink">{run.eventId.slice(0, 8)}</span>
            </span>
            {run.alertId ? (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  selectAlert(run.alertId!);
                  setView("triage");
                }}
              >
                open alert
              </Button>
            ) : (
              <span>scored below the alerting threshold — no alert opened</span>
            )}
          </div>

          {run.mitre.length > 0 ? <MitreChips refs={run.mitre} /> : null}

          <div className="flex flex-col gap-1">
            {run.hits.map((hit) => (
              <HitRow key={hit.id} hit={hit} />
            ))}
            {run.hits.length === 0 ? (
              <p className="text-[11px] text-ink-dim">
                The engine ran and matched nothing. Recorded anyway — a rule that never fires is a
                fact about the ruleset, not an absence of evidence.
              </p>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

type Entry =
  | { kind: "llm"; at: string; call: LlmCall }
  | { kind: "detection"; at: string; run: DetectionRun };

/** Only triage stages carry a verdict; a Compass review parses to a summary. */
function verdictOf(call: LlmCall): Verdict | null {
  const parsed = call.parsed;
  return parsed && "verdict" in parsed ? parsed.verdict : null;
}

export function LlmActivityView() {
  const llmCalls = useStore((s) => s.llmCalls);
  const detections = useStore((s) => s.detections);
  const stats = useStore((s) => s.stats);
  const [layer, setLayer] = useState<"all" | "detection" | "llm">("all");
  const [stageFilter, setStageFilter] = useState<"all" | "first_triage" | "second_triage">("all");
  const [interestingOnly, setInterestingOnly] = useState(true);
  const [failedOnly, setFailedOnly] = useState(false);

  const visible = useMemo<Entry[]>(() => {
    const entries: Entry[] = [];

    if (layer !== "detection") {
      for (const call of llmCalls) {
        if (stageFilter !== "all" && call.stage !== stageFilter) continue;
        if (failedOnly && call.status !== "error" && call.status !== "timeout") continue;
        entries.push({ kind: "llm", at: call.startedAt, call });
      }
    }
    if (layer !== "llm" && !failedOnly) {
      for (const run of detections) {
        if (interestingOnly && run.hits.length === 0) continue;
        entries.push({ kind: "detection", at: run.ranAt, run });
      }
    }
    return entries.sort((a, b) => b.at.localeCompare(a.at)).slice(0, 400);
  }, [llmCalls, detections, layer, stageFilter, failedOnly, interestingOnly]);

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-edge bg-panel px-3 py-1.5">
        {(["all", "detection", "llm"] as const).map((value) => (
          <button
            key={value}
            type="button"
            onClick={() => setLayer(value)}
            className={cn(
              "rounded-sm px-2 py-0.5 text-[11px] transition-colors",
              layer === value ? "bg-active text-ink" : "text-ink-dim hover:text-ink",
            )}
          >
            {value === "llm"
              ? "model calls"
              : value === "detection"
                ? "engine runs"
                : "both layers"}
          </button>
        ))}

        <div className="mx-1 h-4 w-px bg-edge" />

        {(["all", "first_triage", "second_triage"] as const).map((stage) => (
          <button
            key={stage}
            type="button"
            onClick={() => setStageFilter(stage)}
            disabled={layer === "detection"}
            className={cn(
              "rounded-sm px-2 py-0.5 text-[11px] transition-colors disabled:opacity-40",
              stageFilter === stage ? "bg-active text-ink" : "text-ink-dim hover:text-ink",
            )}
          >
            {stage.replace(/_/g, " ")}
          </button>
        ))}

        <div className="mx-1 h-4 w-px bg-edge" />

        <button
          type="button"
          onClick={() => setInterestingOnly(!interestingOnly)}
          className={cn(
            "rounded-sm px-2 py-0.5 text-[11px] transition-colors",
            interestingOnly ? "bg-active text-ink" : "text-ink-dim hover:text-ink",
          )}
          title="Hide engine runs that matched nothing"
        >
          hits only
        </button>
        <button
          type="button"
          onClick={() => setFailedOnly(!failedOnly)}
          className={cn(
            "rounded-sm px-2 py-0.5 text-[11px] transition-colors",
            failedOnly ? "bg-active text-block" : "text-ink-dim hover:text-ink",
          )}
        >
          failures only
        </button>

        <div className="ml-auto flex gap-4 text-[10px] text-ink-dim">
          <span>
            engine: {stats?.detectionRuns.toLocaleString() ?? 0} runs · {stats?.detectionHits ?? 0}{" "}
            hits
          </span>
          <span>
            model: {stats?.llmInFlight ?? 0} in flight · {stats?.llmTotal ?? 0} calls ·{" "}
            {stats?.llmErrors ?? 0} failed
          </span>
          <span>{(stats?.tokensUsed ?? 0).toLocaleString()} tokens</span>
        </div>
      </div>

      <div className="grid shrink-0 grid-cols-[16px_62px_110px_1fr_90px_80px_80px_90px] gap-2 border-b border-edge bg-panel px-3 py-1 text-[10px] uppercase tracking-wide text-ink-dim">
        <span />
        <span>started</span>
        <span>layer</span>
        <span>what ran</span>
        <span>status</span>
        <span>result</span>
        <span>took</span>
        <span>cost</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {visible.length === 0 ? (
          <p className="p-6 text-center text-xs text-ink-dim">
            Nothing yet. The detection engine logs a run for every event it scores; model calls
            appear once an alert enters triage.
          </p>
        ) : (
          visible.map((entry) =>
            entry.kind === "llm" ? (
              <CallRow key={entry.call.id} call={entry.call} />
            ) : (
              <DetectionRunRow key={entry.run.id} run={entry.run} />
            ),
          )
        )}
      </div>
    </div>
  );
}
