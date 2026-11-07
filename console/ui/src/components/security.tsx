import type { Detection, DetectionHit, Enrichment, MitreRef } from "@aisoc/shared";
import { Fingerprint, Radar, ScanSearch } from "lucide-react";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/primitives";
import { bandColor, cn, hitKindStyle, riskBg, scoreColor } from "@/lib/utils";

const KIND_ICON = {
  ioc: Fingerprint,
  rule: ScanSearch,
  heuristic: Radar,
} as const;

export function ScoreBar({
  score,
  className,
  width = "w-16",
}: {
  score: number;
  className?: string;
  width?: string;
}) {
  return (
    <span className={cn("flex items-center gap-1.5", className)}>
      <span className={cn("h-1 overflow-hidden rounded-full bg-edge", width)}>
        <span
          className={cn("block h-full", riskBg(score))}
          style={{ width: `${Math.min(100, score)}%` }}
        />
      </span>
      <span className={cn("font-mono text-[10px] tabular-nums", scoreColor(score))}>{score}</span>
    </span>
  );
}

/**
 * A span rather than a div: these chips are rendered inside clickable rows, and
 * a div is not valid content for a button.
 */
export function MitreChips({ refs, max = 6 }: { refs: MitreRef[]; max?: number }) {
  if (refs.length === 0) return null;
  const shown = refs.slice(0, max);
  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((ref) => (
        <Badge
          key={ref.techniqueId}
          className="border-[#4a4a6a] font-mono normal-case text-[#a8a8d8]"
          title={`${ref.tactic} · ${ref.technique}`}
        >
          {ref.techniqueId}
        </Badge>
      ))}
      {refs.length > max ? <Badge className="text-ink-dim">+{refs.length - max}</Badge> : null}
    </span>
  );
}

export function HitRow({ hit }: { hit: DetectionHit }) {
  const Icon = KIND_ICON[hit.kind];
  return (
    <div className="rounded-sm border border-edge bg-shell p-2">
      <div className="flex items-center gap-2">
        <Icon className="h-3 w-3 shrink-0 text-ink-dim" />
        <Badge className={cn("shrink-0 font-mono", hitKindStyle(hit.kind))}>{hit.kind}</Badge>
        <span className="truncate font-mono text-[11px] text-ink" title={hit.name}>
          {hit.name}
        </span>
        <ScoreBar score={hit.score} className="ml-auto shrink-0" width="w-10" />
      </div>
      <p className="mt-1 text-[10px] leading-snug text-ink-dim">{hit.description}</p>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-ink-dim">
        <span className="font-mono text-ink">{hit.ruleId}</span>
        <span>
          {hit.field} = <span className="font-mono text-ink">{hit.value}</span>
        </span>
        <span>confidence {(hit.confidence * 100).toFixed(0)}%</span>
        <span className="truncate">{hit.origin}</span>
      </div>
      {hit.mitre.length > 0 ? (
        <div className="mt-1.5">
          <MitreChips refs={hit.mitre} max={4} />
        </div>
      ) : null}
    </div>
  );
}

/**
 * The deterministic layer's report, shown above the model's opinion everywhere
 * an alert is inspected — the ordering is the point: evidence first, narration
 * second.
 */
export function DetectionPanel({ detection }: { detection: Detection | null }) {
  if (!detection) {
    return (
      <p className="rounded-sm border border-edge bg-shell p-2 text-[11px] text-ink-dim">
        The detection engine did not run on this alert.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2 rounded-sm border border-edge bg-shell p-2">
        <span
          className={cn(
            "font-mono text-2xl font-semibold leading-none",
            scoreColor(detection.score),
          )}
        >
          {detection.score}
        </span>
        <span className="text-[10px] text-ink-dim">/100</span>
        <Badge className={cn("ml-1 font-mono", bandColor(detection.band))}>{detection.band}</Badge>
        <span className="ml-auto text-right text-[10px] leading-tight text-ink-dim">
          {detection.hits.length} hit{detection.hits.length === 1 ? "" : "s"}
          <br />
          {detection.durationMs}ms · {detection.engineVersion}
        </span>
      </div>

      {detection.mitre.length > 0 ? <MitreChips refs={detection.mitre} /> : null}

      {detection.hits.length === 0 ? (
        <p className="text-[10px] leading-snug text-ink-dim">
          Nothing first-party matched. The alert exists because the sensor rated it severe, not
          because our own rules or indicators fired — worth weighing when reading the verdict.
        </p>
      ) : (
        detection.hits.map((hit) => <HitRow key={hit.id} hit={hit} />)
      )}
    </div>
  );
}

export function IntelPanel({ enrichment }: { enrichment: Enrichment | null }) {
  if (!enrichment) {
    return (
      <p className="rounded-sm border border-edge bg-shell p-2 text-[11px] text-ink-dim">
        No indicator to enrich, or enrichment is disabled in settings.
      </p>
    );
  }

  return (
    <div className="rounded-sm border border-edge bg-shell p-2">
      <div className="flex items-center gap-2">
        <span className="truncate font-mono text-[11px] text-ink">{enrichment.indicator}</span>
        <Badge className="shrink-0 text-ink-dim">{enrichment.type}</Badge>
        <ScoreBar score={enrichment.reputation} className="ml-auto shrink-0" />
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-ink-dim">
        {enrichment.country ? <span>{enrichment.country}</span> : null}
        {enrichment.asn ? <span className="font-mono">{enrichment.asn}</span> : null}
        {enrichment.firstSeen ? (
          <span>first seen {new Date(enrichment.firstSeen).toLocaleDateString()}</span>
        ) : null}
        <span>{enrichment.cached ? "cached" : "fresh"}</span>
      </div>
      <div className="mt-1.5 flex flex-col gap-1">
        {enrichment.sources.map((source) => (
          <div key={source.provider} className="flex items-start gap-2 text-[10px]">
            <span
              className={cn(
                "mt-1 h-1.5 w-1.5 shrink-0 rounded-full",
                source.ok ? "bg-ignore" : "bg-block",
              )}
            />
            <span className="w-20 shrink-0 font-mono text-ink">{source.provider}</span>
            <span className="text-ink-dim">{source.error ?? source.detail}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone,
  onClick,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: string;
  onClick?: () => void;
}) {
  const Tag = onClick ? "button" : "div";
  return (
    <Tag
      {...(onClick ? { type: "button" as const, onClick } : {})}
      className={cn(
        "flex flex-col justify-center rounded-sm border border-edge bg-panel px-3 py-2 text-left",
        onClick && "transition-colors hover:border-status hover:bg-hover",
      )}
    >
      <span className="text-[10px] uppercase tracking-wide text-ink-dim">{label}</span>
      <span
        className={cn("font-mono text-2xl leading-tight tabular-nums", tone ?? "text-ink-bright")}
      >
        {value}
      </span>
      {hint ? <span className="text-[10px] leading-snug text-ink-dim">{hint}</span> : null}
    </Tag>
  );
}
