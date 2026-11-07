import type { Alert, Incident, ResponseAction, SecurityEvent } from "@aisoc/shared";
import {
  formatBytes,
  inboundBytes,
  inboundPackets,
  localIp,
  meanPacketBytes,
  outboundBytes,
  outboundPackets,
  remoteIp,
} from "@aisoc/shared";
import {
  ArrowDown,
  ArrowUp,
  BrainCircuit,
  CornerDownRight,
  Radio,
  ScanSearch,
  Siren,
  UserCheck,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/primitives";
import { cn, scoreColor, verdictColor } from "@/lib/utils";

/**
 * One connection, and the chain of decisions taken about it.
 *
 * The direction and the mean packet size lead deliberately: they are what
 * separates a transfer from the ack stream acknowledging someone else's, and
 * reading them off the incident used to mean opening eve.json by hand.
 */

type Wire = {
  key: string;
  local: string;
  remote: string;
  remotePort: number;
  proto: string;
  appProto: string | null;
  peer: string | null;
  out: number;
  in: number;
  outMean: number | undefined;
  inMean: number | undefined;
};

function wireOf(event: SecurityEvent): Wire {
  const ends = [`${event.srcIp}:${event.srcPort}`, `${event.destIp}:${event.destPort}`].sort();
  const remote = remoteIp(event);
  const out = outboundBytes(event);
  const incoming = inboundBytes(event);
  return {
    key: ends.join(" "),
    local: localIp(event),
    remote,
    remotePort: remote === event.destIp ? event.destPort : event.srcPort,
    proto: event.proto,
    appProto: event.appProto ?? null,
    peer: event.sni ?? event.hostname ?? null,
    out,
    in: incoming,
    outMean: meanPacketBytes(out, outboundPackets(event)),
    inMean: meanPacketBytes(incoming, inboundPackets(event)),
  };
}

/**
 * Suricata's counters are cumulative for the life of a flow, so several alerts
 * on one connection each carry the whole total. The high-water mark is the
 * transfer; summing them would report it once per alert.
 */
function wiresOf(alerts: Alert[]): Wire[] {
  const byFlow = new Map<string, Wire>();
  for (const alert of alerts) {
    const wire = wireOf(alert.event);
    // Endpoint telemetry carries no flow: both ends are the host itself.
    if (wire.local === wire.remote) continue;
    const seen = byFlow.get(wire.key);
    if (!seen || wire.out + wire.in > seen.out + seen.in) byFlow.set(wire.key, wire);
  }
  return [...byFlow.values()].sort((a, b) => b.out + b.in - (a.out + a.in));
}

function Direction({
  label,
  icon: Icon,
  value,
  mean,
  scale,
  tone,
}: {
  label: string;
  icon: typeof ArrowUp;
  value: number;
  mean: number | undefined;
  scale: number;
  tone: string;
}) {
  const ackOnly = mean !== undefined && mean < 200 && value > 0;
  return (
    <div className="flex items-center gap-1.5 text-[10px]">
      <Icon className={cn("h-3 w-3 shrink-0", tone)} />
      <span className="w-6 shrink-0 text-ink-dim">{label}</span>
      <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-shell">
        <span
          className={cn(
            "block h-full rounded-full",
            ackOnly ? "bg-edge" : tone.replace("text-", "bg-"),
          )}
          style={{ width: `${scale > 0 ? Math.max(1, (value / scale) * 100) : 0}%` }}
        />
      </span>
      <span className="w-16 shrink-0 text-right font-mono tabular-nums text-ink">
        {formatBytes(value)}
      </span>
      <span className="w-20 shrink-0 text-right font-mono tabular-nums text-ink-dim">
        {mean === undefined ? "—" : `${Math.round(mean)} B/pkt`}
      </span>
    </div>
  );
}

function WireRow({ wire, index }: { wire: Wire; index: number }) {
  const scale = Math.max(wire.out, wire.in);
  const ackOnly = wire.outMean !== undefined && wire.outMean < 200 && wire.out > 0;
  return (
    <div
      className="stage-in rounded-sm border border-edge bg-shell px-2 py-1.5"
      style={{ "--stage": index } as React.CSSProperties}
    >
      <div className="flex items-baseline gap-1.5 text-[10px]">
        <span className="font-mono text-ink">{wire.local}</span>
        <span className="text-ink-dim">⇄</span>
        <span className="font-mono text-ink">
          {wire.remote}:{wire.remotePort}
        </span>
        <span className="ml-auto shrink-0 font-mono text-ink-dim">
          {wire.proto}
          {wire.appProto ? ` · ${wire.appProto}` : ""}
        </span>
      </div>
      {wire.peer ? (
        <p className="truncate font-mono text-[10px] text-[#8ab4d8]" title={wire.peer}>
          {wire.peer}
        </p>
      ) : null}
      <div className="mt-1 flex flex-col gap-1">
        <Direction
          label="out"
          icon={ArrowUp}
          value={wire.out}
          mean={wire.outMean}
          scale={scale}
          tone="text-block"
        />
        <Direction
          label="in"
          icon={ArrowDown}
          value={wire.in}
          mean={wire.inMean}
          scale={scale}
          tone="text-[#8ab4d8]"
        />
      </div>
      {ackOnly ? (
        <p className="mt-1 text-[10px] leading-snug text-ink-dim">
          Outbound packets average bare-header size — this end acknowledged a download rather than
          sending anything.
        </p>
      ) : null}
    </div>
  );
}

type Stage = {
  key: string;
  icon: typeof Radio;
  label: string;
  value: string;
  tone: string;
  detail: string | null;
};

function stagesOf(alert: Alert, incident: Incident, actions: ResponseAction[]): Stage[] {
  const stages: Stage[] = [
    {
      key: "sensor",
      icon: Radio,
      label: "sensor",
      value: `sid ${alert.event.signatureId}`,
      tone: "text-sev2",
      detail: alert.event.signature,
    },
  ];

  if (alert.detection) {
    const { score, band, hits } = alert.detection;
    stages.push({
      key: "engine",
      icon: ScanSearch,
      label: "engine",
      value: `${score}/100 ${band}`,
      tone: scoreColor(score),
      detail:
        hits.length === 0
          ? "No first-party rule, indicator, or heuristic matched."
          : hits.map((hit) => `${hit.ruleId} +${hit.score}`).join(" · "),
    });
  }

  if (alert.escalationReason) {
    stages.push({
      key: "escalation",
      icon: CornerDownRight,
      label: "escalated",
      value: "second triage",
      tone: "text-ink-dim",
      detail: alert.escalationReason,
    });
  }

  if (alert.verdict) {
    stages.push({
      key: "verdict",
      icon: BrainCircuit,
      label: "triage",
      value: `${alert.verdict} @ ${alert.confidence.toFixed(2)}`,
      tone: verdictColor(alert.verdict),
      detail: alert.reason,
    });
  } else {
    stages.push({
      key: "verdict",
      icon: BrainCircuit,
      label: "triage",
      value: alert.stage.replace(/_/g, " "),
      tone: "text-ink-dim",
      detail: "No verdict yet.",
    });
  }

  if (alert.humanOverride) {
    stages.push({
      key: "override",
      icon: UserCheck,
      label: "override",
      value: `${alert.humanOverride.verdict} by ${alert.humanOverride.by}`,
      tone: verdictColor(alert.humanOverride.verdict),
      detail: alert.humanOverride.note,
    });
  }

  if (actions.length > 0) {
    stages.push({
      key: "response",
      icon: Zap,
      label: "response",
      value: `${actions.length} action${actions.length === 1 ? "" : "s"}`,
      tone: "text-ignore",
      detail: actions
        .map((a) => `${a.type.replace(/_/g, " ")} ${a.target} · ${a.status}`)
        .join(" · "),
    });
  }

  stages.push({
    key: "incident",
    icon: Siren,
    label: "incident",
    value: `${incident.ref} ${incident.status}`,
    tone: "text-status",
    detail: incident.correlationBasis,
  });

  return stages;
}

function StageRow({ stage, index }: { stage: Stage; index: number }) {
  const Icon = stage.icon;
  return (
    <div
      className="stage-in flex gap-2 border-l border-edge pl-3"
      style={{ "--stage": index } as React.CSSProperties}
    >
      <span className="relative -ml-[19px] mt-0.5 flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-full bg-panel">
        <Icon className={cn("h-2.5 w-2.5", stage.tone)} />
      </span>
      <div className="min-w-0 flex-1 pb-2">
        <div className="flex items-baseline gap-2">
          <span className="shrink-0 text-[10px] uppercase tracking-wide text-ink-dim">
            {stage.label}
          </span>
          <span className={cn("truncate font-mono text-[11px]", stage.tone)}>{stage.value}</span>
        </div>
        {stage.detail ? (
          <p className="text-[10px] leading-snug text-ink-dim">{stage.detail}</p>
        ) : null}
      </div>
    </div>
  );
}

export function FlowPath({
  incident,
  alerts,
  actions,
  onSelectAlert,
}: {
  incident: Incident;
  alerts: Alert[];
  actions: ResponseAction[];
  onSelectAlert: (alertId: string) => void;
}) {
  if (alerts.length === 0) return null;

  const wires = wiresOf(alerts);
  const dominant = [...alerts].sort(
    (a, b) => (b.detection?.score ?? 0) - (a.detection?.score ?? 0),
  )[0]!;
  const stages = stagesOf(dominant, incident, actions);

  return (
    <div className="flex flex-col gap-2">
      {wires.map((wire, index) => (
        <WireRow key={wire.key} wire={wire} index={index} />
      ))}

      <div className="mt-0.5 flex flex-col">
        {stages.map((stage, index) => (
          <StageRow key={stage.key} stage={stage} index={wires.length + index} />
        ))}
      </div>

      {alerts.length > 1 ? (
        <button
          type="button"
          onClick={() => onSelectAlert(dominant.id)}
          className="self-start text-[10px] text-ink-dim underline-offset-2 hover:text-ink hover:underline"
        >
          decision chain shown for the highest-scoring of {alerts.length} alerts — open it
        </button>
      ) : null}

      {dominant.enrichment ? (
        <Badge className="self-start gap-1.5 text-ink-dim">
          <span className="font-mono normal-case">{dominant.enrichment.indicator}</span>
          <span>reputation {dominant.enrichment.reputation}/100</span>
          {dominant.enrichment.asn ? <span>{dominant.enrichment.asn}</span> : null}
        </Badge>
      ) : null}
    </div>
  );
}
