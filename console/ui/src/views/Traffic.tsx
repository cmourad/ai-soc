import type { SecurityEvent } from "@aisoc/shared";
import { Play, Snowflake } from "lucide-react";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Sparkline } from "@/components/Sparkline";
import { Badge, Button, Input } from "@/components/ui/primitives";
import { cn, severityBg, severityLabel, timeOf, verdictColor } from "@/lib/utils";
import { useStore } from "@/store";

const SEVERITIES = [1, 2, 3, 4];
const MAX_ROWS = 300;

function TelemetryStrip() {
  const stats = useStore((s) => s.stats);
  const [history, setHistory] = useState<number[]>([]);

  useEffect(() => {
    if (!stats) return;
    setHistory((prev) => [...prev, stats.eventsPerSecond].slice(-60));
  }, [stats]);

  const bySeverity = stats?.bySeverity ?? {};
  const total = Math.max(
    1,
    SEVERITIES.reduce((sum, s) => sum + (bySeverity[String(s)] ?? 0), 0),
  );

  return (
    <div className="flex shrink-0 items-stretch gap-px border-b border-edge bg-edge">
      <div className="flex flex-1 items-center gap-4 bg-shell px-4 py-3">
        <div>
          <div className="text-[10px] uppercase tracking-wide text-ink-dim">Throughput</div>
          <div className="font-mono text-3xl leading-none text-ink-bright tabular-nums">
            {stats?.eventsPerSecond.toFixed(1) ?? "0.0"}
            <span className="ml-1 text-sm text-ink-dim">ev/s</span>
          </div>
          <div className="mt-1 text-[10px] text-ink-dim">
            {stats?.totalEvents.toLocaleString() ?? 0} seen this session
          </div>
        </div>
        <Sparkline points={history} className="ml-auto" />
      </div>

      <div className="flex min-w-[260px] flex-col justify-center bg-shell px-4 py-3">
        <div className="mb-1.5 text-[10px] uppercase tracking-wide text-ink-dim">
          Severity mix (last {stats?.totalEvents ? Math.min(2000, stats.totalEvents) : 0} events)
        </div>
        <div className="flex h-2 overflow-hidden rounded-sm">
          {SEVERITIES.map((severity) => {
            const count = bySeverity[String(severity)] ?? 0;
            return (
              <div
                key={severity}
                className={severityBg(severity)}
                style={{ width: `${(count / total) * 100}%` }}
                title={`${severityLabel(severity)}: ${count}`}
              />
            );
          })}
        </div>
        <div className="mt-1.5 flex gap-3 text-[10px] text-ink-dim">
          {SEVERITIES.map((severity) => (
            <span key={severity} className="flex items-center gap-1">
              <span className={cn("h-1.5 w-1.5 rounded-full", severityBg(severity))} />
              {severityLabel(severity)} {bySeverity[String(severity)] ?? 0}
            </span>
          ))}
        </div>
      </div>

      <div className="flex min-w-[160px] flex-col justify-center bg-shell px-4 py-3">
        <div className="text-[10px] uppercase tracking-wide text-ink-dim">In triage</div>
        <div className="font-mono text-2xl leading-tight text-ink-bright tabular-nums">
          {stats?.openAlerts ?? 0}
        </div>
        <div className="text-[10px] text-ink-dim">
          {stats?.needsHuman ?? 0} awaiting a human · {stats?.llmInFlight ?? 0} model calls live
        </div>
      </div>
    </div>
  );
}

function FilterBar() {
  const severityFilter = useStore((s) => s.severityFilter);
  const toggleSeverity = useStore((s) => s.toggleSeverity);
  const sourceFilter = useStore((s) => s.sourceFilter);
  const setSourceFilter = useStore((s) => s.setSourceFilter);
  const textFilter = useStore((s) => s.textFilter);
  const setTextFilter = useStore((s) => s.setTextFilter);
  const paused = useStore((s) => s.paused);
  const setFrozen = useStore((s) => s.setFrozen);

  return (
    <div className="flex shrink-0 items-center gap-2 border-b border-edge bg-panel px-3 py-1.5">
      <span className="text-[10px] uppercase tracking-wide text-ink-dim">Severity</span>
      {SEVERITIES.map((severity) => {
        const on = severityFilter.includes(severity);
        return (
          <button
            key={severity}
            type="button"
            onClick={() => toggleSeverity(severity)}
            className={cn(
              "flex items-center gap-1 rounded-sm border px-1.5 py-0.5 text-[10px] uppercase transition-colors",
              on
                ? "border-edge bg-active text-ink"
                : "border-transparent text-ink-dim hover:text-ink",
            )}
          >
            <span className={cn("h-1.5 w-1.5 rounded-full", severityBg(severity))} />
            {severityLabel(severity)}
          </button>
        );
      })}

      <div className="mx-1 h-4 w-px bg-edge" />

      <Input
        value={sourceFilter}
        onChange={(event) => setSourceFilter(event.target.value)}
        placeholder="source or dest IP"
        className="h-6 w-40"
      />
      <Input
        value={textFilter}
        onChange={(event) => setTextFilter(event.target.value)}
        placeholder="signature, port, tag, SNI…"
        className="h-6 w-64"
      />

      <Button
        variant={paused ? "primary" : "ghost"}
        size="sm"
        onClick={() => setFrozen(!paused)}
        className="ml-auto"
        title="Freeze the view without pausing ingest"
      >
        {paused ? <Play className="h-3 w-3" /> : <Snowflake className="h-3 w-3" />}
        {paused ? "resume view" : "freeze view"}
      </Button>
    </div>
  );
}

function matches(
  event: SecurityEvent,
  severities: number[],
  source: string,
  text: string,
): boolean {
  if (!severities.includes(event.severity)) return false;
  if (source && !event.srcIp.includes(source) && !event.destIp.includes(source)) return false;
  if (text) {
    const haystack = [
      event.signature,
      event.category,
      event.tags.join(" "),
      event.sni ?? "",
      event.hostname ?? "",
      event.url ?? "",
      String(event.destPort),
      String(event.srcPort),
      event.proto,
    ]
      .join(" ")
      .toLowerCase();
    if (!haystack.includes(text.toLowerCase())) return false;
  }
  return true;
}

function EventRow({
  event,
  selected,
  onClick,
}: {
  event: SecurityEvent;
  selected: boolean;
  onClick: () => void;
}) {
  const alert = useStore((s) => s.alerts.find((a) => a.event.id === event.id));

  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "row-in grid w-full grid-cols-[62px_10px_1fr_150px_150px_58px_120px] items-center gap-2 px-3 py-[3px] text-left font-mono text-[11px] leading-5",
        selected ? "bg-active" : "hover:bg-hover",
      )}
    >
      <span className="text-ink-dim tabular-nums">{timeOf(event.ts)}</span>
      <span
        className={cn("h-2 w-2 rounded-full", severityBg(event.severity))}
        title={severityLabel(event.severity)}
      />
      <span className="truncate text-ink" title={event.signature}>
        {event.signature}
      </span>
      <span className="truncate text-ink-dim tabular-nums">
        {event.srcIp}:{event.srcPort}
      </span>
      <span className="truncate text-ink-dim tabular-nums">
        {event.destIp}:{event.destPort}
      </span>
      <span className="text-ink-dim">{event.proto}</span>
      <span className={cn("truncate text-[10px]", verdictColor(alert?.verdict ?? null))}>
        {alert ? `${alert.verdict ?? alert.stage.replace("_", " ")}` : ""}
      </span>
    </button>
  );
}

export function TrafficView() {
  const events = useStore((s) => s.events);
  const severityFilter = useStore((s) => s.severityFilter);
  const sourceFilter = useStore((s) => s.sourceFilter);
  const textFilter = useStore((s) => s.textFilter);
  const paused = useStore((s) => s.paused);
  const selectedEventId = useStore((s) => s.selectedEventId);
  const selectEvent = useStore((s) => s.selectEvent);
  const downSensors = (useStore((s) => s.stats)?.sensors ?? []).filter((sensor) => !sensor.ok);

  const listRef = useRef<HTMLDivElement>(null);
  const stickToBottom = useRef(true);

  const visible = useMemo(
    () =>
      events
        .filter((event) => matches(event, severityFilter, sourceFilter, textFilter))
        .slice(-MAX_ROWS),
    [events, severityFilter, sourceFilter, textFilter],
  );

  useLayoutEffect(() => {
    const node = listRef.current;
    if (!node || paused || !stickToBottom.current) return;
    node.scrollTop = node.scrollHeight;
  }, [paused]);

  // Re-pin after each render that added rows.
  useLayoutEffect(() => {
    const node = listRef.current;
    if (!node || paused || !stickToBottom.current) return;
    node.scrollTop = node.scrollHeight;
  });

  return (
    <div className="flex h-full flex-col">
      <TelemetryStrip />
      <FilterBar />

      <div className="grid shrink-0 grid-cols-[62px_10px_1fr_150px_150px_58px_120px] gap-2 border-b border-edge bg-panel px-3 py-1 text-[10px] uppercase tracking-wide text-ink-dim">
        <span>time</span>
        <span />
        <span>signature</span>
        <span>source</span>
        <span>destination</span>
        <span>proto</span>
        <span>verdict</span>
      </div>

      <div
        ref={listRef}
        onScroll={(scrollEvent) => {
          const node = scrollEvent.currentTarget;
          stickToBottom.current = node.scrollHeight - node.scrollTop - node.clientHeight < 24;
        }}
        className="flex-1 overflow-y-auto"
      >
        {visible.length === 0 ? (
          downSensors.length > 0 ? (
            <div className="p-6 text-center text-xs">
              <p className="text-ink">
                {downSensors.map((sensor) => sensor.label).join(" and ")}{" "}
                {downSensors.length === 1 ? "has" : "have"} stopped writing — no events are
                arriving.
              </p>
              <p className="mt-1 text-ink-dim">
                {downSensors.map((sensor) => `${sensor.label}: ${sensor.detail}`).join(" · ")}
              </p>
            </div>
          ) : (
            <p className="p-6 text-center text-xs text-ink-dim">
              No events match the current filters.
            </p>
          )
        ) : (
          visible.map((event) => (
            <EventRow
              key={event.id}
              event={event}
              selected={event.id === selectedEventId}
              onClick={() => selectEvent(event.id)}
            />
          ))
        )}
      </div>

      <div className="flex shrink-0 items-center gap-3 border-t border-edge bg-panel px-3 py-1 text-[10px] text-ink-dim">
        <Badge className="text-ink-dim">{visible.length} shown</Badge>
        <span>{events.length} buffered</span>
        {paused ? <span className="text-watch">view frozen — ingest still running</span> : null}
      </div>
    </div>
  );
}
