import type {
  CompassDestination,
  CompassInsight,
  NetworkFlow,
  ReviewAssessment,
  TrafficClass,
} from "@aisoc/shared";
import { formatBytes, windowLabel } from "@aisoc/shared";
import {
  ArrowDownLeft,
  ArrowUpRight,
  Bot,
  Compass,
  EyeOff,
  Globe,
  Info,
  Loader2,
  Lock,
  MessageSquare,
  Pause,
  Play,
  Radio,
  ShieldCheck,
  Sparkles,
  Trash2,
  TriangleAlert,
  Unlock,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Badge, Button, Field, Input, Select, Switch, Tooltip } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { cn, relativeTime } from "@/lib/utils";
import { useStore } from "@/store";

type Tab = "sites" | "connections";

const CONFIDENCE_HELP: Record<string, string> = {
  asserted: "The app named this site while connecting. Not verified, but it is what was requested.",
  inferred: "Matched from a recent DNS lookup. Shared CDN addresses can be mislabelled.",
  unknown: "No name was seen. Encrypted DNS or a direct-to-IP connection hides it.",
};

const ASSESSMENT_STYLE: Record<ReviewAssessment, string> = {
  expected: "border-[#2d5a3d] text-ignore",
  worth_checking: "border-watch/60 text-watch",
  unexpected: "border-[#5a2d2d] text-block",
};

const CLASS_HELP: Record<TrafficClass, string> = {
  web: "Ordinary web traffic.",
  infrastructure: "Machine chatter — name lookups, clock sync, device discovery.",
  local: "Stayed inside your own network.",
  other: "A non-web service.",
};

function InsightCard({
  insight,
  onMute,
  onDismiss,
}: {
  insight: CompassInsight;
  onMute: (domain: string) => void;
  onDismiss: (id: string) => void;
}) {
  const Icon = insight.tone === "watch" ? TriangleAlert : Sparkles;
  return (
    <article className="rounded-sm border border-edge bg-panel p-3">
      <div className="flex items-start gap-2">
        <Icon
          className={cn(
            "mt-px h-4 w-4 shrink-0",
            insight.tone === "watch" ? "text-watch" : "text-accent",
          )}
        />
        <h3 className="text-xs font-semibold leading-5 text-ink-bright">{insight.title}</h3>
      </div>
      <p className="mt-2 text-[11px] leading-5 text-ink-dim">{insight.detail}</p>
      <div className="mt-3 flex gap-1.5">
        {insight.domain ? (
          <Button size="sm" variant="outline" onClick={() => onMute(insight.domain!)}>
            mute {insight.domain}
          </Button>
        ) : null}
        <Button size="sm" variant="ghost" onClick={() => onDismiss(insight.id)}>
          hide for a week
        </Button>
      </div>
    </article>
  );
}

function SiteRow({
  destination,
  share,
  onMute,
  onSuppressBeacon,
  beaconSuppressed,
}: {
  destination: CompassDestination;
  share: number;
  onMute: (domain: string) => void;
  onSuppressBeacon: (destinationKey: string) => void;
  beaconSuppressed: boolean;
}) {
  const [open, setOpen] = useState(false);
  const total = destination.bytesUp + destination.bytesDown;
  const isNamed = !destination.key.startsWith("ip:");
  const namedProcesses = destination.processes.filter((process) => process.name);
  const primaryProcess = namedProcesses[0]?.name ?? "unknown";
  return (
    <div className="border-b border-edge/60">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="grid w-full grid-cols-[1fr_120px_92px_92px_120px_64px] items-center gap-3 px-4 py-2 text-left hover:bg-hover"
      >
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="truncate text-xs text-ink-bright">{destination.label}</span>
            {destination.knownDays === 1 ? (
              <Badge className="border-watch/60 text-watch">new</Badge>
            ) : null}
            {destination.plaintextFlows > 0 ? (
              <Tooltip label={`${destination.plaintextFlows} connections sent in the clear`}>
                <Unlock className="h-3 w-3 text-watch" />
              </Tooltip>
            ) : null}
          </div>
          <div className="mt-1 h-1 w-full max-w-md overflow-hidden rounded-full bg-edge">
            <div className="h-full bg-accent" style={{ width: `${Math.max(1, share * 100)}%` }} />
          </div>
        </div>
        <span className="truncate font-mono text-[11px] text-ink" title={primaryProcess}>
          {primaryProcess}
        </span>
        <span className="text-right font-mono text-[11px] text-ink-dim tabular-nums">
          {formatBytes(destination.bytesUp)}
        </span>
        <span className="text-right font-mono text-[11px] text-ink tabular-nums">
          {formatBytes(destination.bytesDown)}
        </span>
        <span className="truncate text-[11px] text-ink-dim">
          {destination.categoryLabel ?? CLASS_HELP[destination.trafficClass].split(" —")[0]}
        </span>
        <span className="text-right text-[10px] text-ink-dim">
          {relativeTime(destination.lastSeen)}
        </span>
      </button>
      {open ? (
        <div className="grid grid-cols-2 gap-x-8 gap-y-1 border-t border-edge/40 bg-shell px-4 py-3 text-[11px] text-ink-dim">
          <span>
            Connections: <span className="font-mono text-ink">{destination.flows}</span> · total{" "}
            <span className="font-mono text-ink">{formatBytes(total)}</span>
          </span>
          <span>
            Known for:{" "}
            <span className="font-mono text-ink">
              {destination.knownDays === 1 ? "today only" : `${destination.knownDays} days`}
            </span>
            {destination.firstSeenDay ? ` (since ${destination.firstSeenDay})` : ""}
          </span>
          <span>
            How we know the name:{" "}
            <Tooltip label={CONFIDENCE_HELP[destination.confidence] ?? ""}>
              <span className="underline decoration-dotted">{destination.confidence}</span>
            </Tooltip>
          </span>
          <span>
            Kind:{" "}
            <Tooltip label={CLASS_HELP[destination.trafficClass]}>
              <span className="underline decoration-dotted">{destination.trafficClass}</span>
            </Tooltip>
            {destination.country ? ` · ${destination.country}` : ""}
          </span>
          {destination.asn ? (
            <span className="col-span-2">
              Network: <span className="font-mono text-ink">{destination.asn}</span>
              {destination.key.startsWith("ip:") ? (
                <>
                  {" "}
                  · address <span className="font-mono text-ink">{destination.key.slice(3)}</span>
                </>
              ) : null}
            </span>
          ) : null}
          <span className="col-span-2 break-words">
            Applications:{" "}
            <span className="font-mono text-ink">
              {destination.processes
                .map(
                  (process) =>
                    `${process.name ?? "unknown"} (${process.flows} · ${formatBytes(process.bytesUp + process.bytesDown)})`,
                )
                .join(", ")}
            </span>
          </span>
          {destination.hostnames.length > 0 ? (
            <span className="col-span-2 break-words">
              Hosts seen:{" "}
              <span className="font-mono text-ink">{destination.hostnames.join(", ")}</span>
            </span>
          ) : null}
          <div className="col-span-2 mt-1 flex gap-2">
            <Button size="sm" variant="outline" onClick={() => onSuppressBeacon(destination.key)}>
              {beaconSuppressed ? "resume beacon alerts" : "suppress beacon alerts"}
            </Button>
            {isNamed ? (
              <Button size="sm" variant="outline" onClick={() => onMute(destination.label)}>
                stop recording {destination.label}
              </Button>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function ConnectionRow({ flow }: { flow: NetworkFlow }) {
  return (
    <div className="grid grid-cols-[70px_1fr_120px_120px_78px_78px] items-center gap-2 border-b border-edge/60 px-4 py-1.5 font-mono text-[11px] hover:bg-hover">
      <span className="text-ink-dim">
        {new Date(flow.endedAt).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        })}
      </span>
      <div className="min-w-0">
        <div className="truncate text-ink" title={flow.hostname ?? flow.remoteIp}>
          {flow.hostname ?? flow.domain ?? flow.remoteIp}
        </div>
        <div className="truncate text-[9px] text-ink-dim">
          {flow.remoteIp}:{flow.remotePort} · {flow.direction} · {flow.domainConfidence}
        </div>
      </div>
      <span className="truncate text-ink" title={flow.processName ?? "unknown"}>
        {flow.processName ?? "unknown"}
      </span>
      <span className="truncate text-ink-dim">{flow.appProto ?? flow.proto.toLowerCase()}</span>
      <span className="text-right text-ink-dim tabular-nums">{formatBytes(flow.bytesUp)}</span>
      <span className="text-right text-ink-dim tabular-nums">{formatBytes(flow.bytesDown)}</span>
    </div>
  );
}

export function NetworkCompassView() {
  const settings = useStore((state) => state.settings.networkCompass);
  const flows = useStore((state) => state.networkFlows);
  const summary = useStore((state) => state.compass);
  const review = useStore((state) => state.compassReview);
  const pushToast = useStore((state) => state.pushToast);
  const openAssistant = useStore((state) => state.openAssistant);
  const [tab, setTab] = useState<Tab>("sites");
  const [showBackground, setShowBackground] = useState(false);
  const [query, setQuery] = useState("");
  const [excludedDomain, setExcludedDomain] = useState("");
  const [saving, setSaving] = useState(false);
  const [reviewing, setReviewing] = useState(false);

  const update = async (patch: Partial<typeof settings>, message: string) => {
    setSaving(true);
    try {
      await api.saveSettings({ networkCompass: patch });
      pushToast("success", message);
    } catch (error) {
      pushToast("error", error instanceof Error ? error.message : String(error));
    } finally {
      setSaving(false);
    }
  };

  const mute = (domain: string) => {
    const clean = domain
      .trim()
      .toLowerCase()
      .replace(/^\.+|\.+$/g, "");
    if (!/^[a-z0-9.-]+$/.test(clean) || clean.includes("..")) {
      pushToast("error", "Enter a valid site name, like example.com.");
      return;
    }
    void update(
      { excludedDomains: [...new Set([...settings.excludedDomains, clean])] },
      `${clean} will no longer be recorded.`,
    );
  };

  const toggleBeaconSuppression = (destinationKey: string) => {
    const suppressed = settings.beaconSuppressions.includes(destinationKey);
    void update(
      {
        beaconSuppressions: suppressed
          ? settings.beaconSuppressions.filter((entry) => entry !== destinationKey)
          : [...settings.beaconSuppressions, destinationKey],
      },
      suppressed
        ? `Beacon alerts resumed for ${destinationKey}.`
        : `Beacon alerts suppressed for ${destinationKey}; recording continues.`,
    );
  };

  const askAnalyst = async () => {
    setReviewing(true);
    try {
      await api.reviewCompass();
    } catch (error) {
      pushToast("error", error instanceof Error ? error.message : String(error));
    } finally {
      setReviewing(false);
    }
  };

  const dismissInsight = async (id: string) => {
    try {
      await api.compassFeedback(id, "snoozed");
      pushToast("success", "Hidden for a week.");
    } catch (error) {
      pushToast("error", error instanceof Error ? error.message : String(error));
    }
  };

  const destinations = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (summary?.destinations ?? []).filter((entry) => {
      if (!showBackground && entry.trafficClass === "infrastructure") return false;
      if (!needle) return true;
      return (
        entry.label.toLowerCase().includes(needle) ||
        entry.categoryLabel?.toLowerCase().includes(needle) ||
        entry.hostnames.some((host) => host.includes(needle))
      );
    });
  }, [query, showBackground, summary]);

  const connections = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return flows
      .filter((flow) => showBackground || flow.trafficClass !== "infrastructure")
      .filter((flow) => {
        if (!needle) return true;
        return [flow.hostname, flow.domain, flow.remoteIp, flow.appProto, flow.processName]
          .filter(Boolean)
          .some((value) => value!.toLowerCase().includes(needle));
      })
      .sort((a, b) => Date.parse(b.endedAt) - Date.parse(a.endedAt))
      .slice(0, 300);
  }, [flows, query, showBackground]);

  const biggest = destinations[0] ? destinations[0].bytesUp + destinations[0].bytesDown : 1;
  const windowText = windowLabel(summary?.windowHours ?? settings.rawRetentionHours);

  if (!settings.enabled) {
    return (
      <div className="h-full overflow-y-auto bg-shell">
        <section className="mx-auto mt-16 max-w-xl rounded-sm border border-edge bg-panel p-8 text-center">
          <ShieldCheck className="mx-auto h-8 w-8 text-accent" />
          <h2 className="mt-3 text-sm font-semibold text-ink-bright">
            See where your internet traffic goes
          </h2>
          <p className="mt-2 text-xs leading-5 text-ink-dim">
            Compass lists the sites this machine talked to and how much data each one used. It never
            records what you typed, searched, or read — only which site, how much, and when.
          </p>
          <p className="mt-2 text-xs leading-5 text-ink-dim">
            Everything stays on this machine and is deleted after {settings.rawRetentionHours}{" "}
            hours. Security alerting is unaffected either way.
          </p>
          <Button
            className="mt-5"
            variant="primary"
            disabled={saving}
            onClick={() => update({ enabled: true }, "Compass is now recording on this machine.")}
          >
            <Compass className="h-3.5 w-3.5" /> Start watching my traffic
          </Button>
        </section>
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto bg-shell">
      <section className="border-b border-edge bg-panel px-5 py-4">
        <div className="flex items-start gap-4">
          <span className="rounded-sm border border-edge bg-active p-2 text-accent">
            <Compass className="h-5 w-5" />
          </span>
          <div className="max-w-3xl">
            <h1 className="text-base font-semibold text-ink-bright">Where your traffic went</h1>
            <p className="mt-1 text-xs leading-5 text-ink-dim">
              Every site this machine contacted in {windowText}, biggest first. Page contents, full
              addresses and search terms are never recorded.{" "}
              {settings.aiReviewEnabled
                ? "AI review is on: when you press it, the site names and totals below are sent to your first-tier model."
                : "Nothing here is sent to a model."}
            </p>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              disabled={saving}
              onClick={() =>
                update(
                  { paused: !settings.paused },
                  settings.paused ? "Recording resumed." : "Recording paused.",
                )
              }
            >
              {settings.paused ? (
                <Play className="h-3.5 w-3.5" />
              ) : (
                <Pause className="h-3.5 w-3.5" />
              )}
              {settings.paused ? "resume" : "pause"}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={saving}
              onClick={() => update({ enabled: false }, "Compass stopped recording.")}
            >
              <EyeOff className="h-3.5 w-3.5" /> stop
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={async () => {
                if (!confirmErase()) return;
                try {
                  await api.forgetCompass();
                  pushToast("success", "Everything Compass recorded has been erased.");
                } catch (error) {
                  pushToast("error", error instanceof Error ? error.message : String(error));
                }
              }}
            >
              <Trash2 className="h-3.5 w-3.5" /> erase everything
            </Button>
          </div>
        </div>
        {settings.paused ? (
          <p className="mt-3 flex items-center gap-2 rounded-sm border border-watch/40 bg-watch/10 px-3 py-1.5 text-[11px] text-watch">
            <Pause className="h-3 w-3" /> Recording is paused. Figures below stop updating until you
            resume.
          </p>
        ) : null}
      </section>

      <section className="grid grid-cols-5 gap-px border-b border-edge bg-edge">
        {[
          {
            label: "Downloaded",
            value: formatBytes(summary?.bytesDown ?? 0),
            hint: `Received by this machine in ${windowText}.`,
            icon: <ArrowDownLeft className="h-4 w-4 text-accent" />,
          },
          {
            label: "Uploaded",
            value: formatBytes(summary?.bytesUp ?? 0),
            hint: `Sent from this machine in ${windowText}.`,
            icon: <ArrowUpRight className="h-4 w-4 text-watch" />,
          },
          {
            label: "Sites contacted",
            value: String(
              (summary?.destinations ?? []).filter(
                (entry) => entry.trafficClass !== "infrastructure",
              ).length,
            ),
            hint: "Distinct destinations, excluding background machine chatter.",
            icon: <Globe className="h-4 w-4 text-ink-dim" />,
          },
          {
            label: "Background chatter",
            value: String(summary?.backgroundFlows ?? 0),
            hint: "Name lookups, clock sync and device discovery. Hidden unless you ask for it.",
            icon: <Radio className="h-4 w-4 text-ink-dim" />,
          },
          {
            label: "Process coverage",
            value: `${Math.round((summary?.attributionCoverage ?? 0) * 100)}%`,
            hint: `${summary?.attributedFlows ?? 0} of ${summary?.retainedFlows ?? 0} flows matched an exact live socket. Short-lived connections can be missed and remain unknown.`,
            icon: <ShieldCheck className="h-4 w-4 text-ink-dim" />,
          },
        ].map((tile) => (
          <div key={tile.label} className="flex items-center gap-3 bg-shell px-5 py-4">
            {tile.icon}
            <div className="min-w-0">
              <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-ink-dim">
                {tile.label}
                <Tooltip label={tile.hint}>
                  <Info className="h-2.5 w-2.5" />
                </Tooltip>
              </div>
              <div className="font-mono text-xl text-ink-bright tabular-nums">{tile.value}</div>
            </div>
          </div>
        ))}
      </section>

      {settings.aiReviewEnabled ? (
        <section className="border-b border-edge px-5 py-4">
          <div className="flex items-center gap-3">
            <Bot className="h-4 w-4 text-accent" />
            <h2 className="text-[11px] font-semibold uppercase tracking-wide text-ink-dim">
              First-tier analyst
            </h2>
            {review ? (
              <span className="text-[10px] text-ink-dim">
                {review.model} · {review.sitesReviewed} sites · {relativeTime(review.createdAt)}
              </span>
            ) : null}
            <Button
              className="ml-auto"
              size="sm"
              variant="primary"
              disabled={reviewing}
              onClick={askAnalyst}
            >
              {reviewing ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Bot className="h-3.5 w-3.5" />
              )}
              {reviewing ? "reviewing traffic…" : review ? "review again" : "review traffic"}
            </Button>
          </div>

          {review?.error ? (
            <p className="mt-3 rounded-sm border border-block/40 bg-block/10 px-3 py-2 text-[11px] text-block">
              The model could not complete the review: {review.error}
            </p>
          ) : null}

          {review && !review.error ? (
            <>
              <p className="mt-3 max-w-4xl text-xs leading-6 text-ink">{review.summary}</p>
              {review.findings.length > 0 ? (
                <div className="mt-3 space-y-1.5">
                  {review.findings.map((finding) => (
                    <div
                      key={finding.site}
                      className="grid grid-cols-[150px_110px_1fr] items-start gap-3 rounded-sm border border-edge bg-panel px-3 py-2"
                    >
                      <span className="truncate font-mono text-[11px] text-ink-bright">
                        {finding.site}
                      </span>
                      <Badge className={ASSESSMENT_STYLE[finding.assessment]}>
                        {finding.assessment.replace(/_/g, " ")}
                      </Badge>
                      <span className="text-[11px] leading-5 text-ink-dim">{finding.reason}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="mt-2 text-[11px] text-ink-dim">
                  The model flagged nothing in particular.
                </p>
              )}
              {review.invented.length > 0 ? (
                <p className="mt-3 flex items-start gap-2 rounded-sm border border-watch/40 bg-watch/10 px-3 py-2 text-[11px] text-watch">
                  <TriangleAlert className="mt-px h-3 w-3 shrink-0" />
                  <span>
                    Dropped {review.invented.length} finding
                    {review.invented.length === 1 ? "" : "s"} about{" "}
                    <span className="font-mono">{review.invented.join(", ")}</span> — the model
                    named sites that were never in your traffic. Treat the rest with more suspicion
                    than usual.
                  </span>
                </p>
              ) : null}
              <div className="mt-3 flex items-center gap-3 border-t border-edge/60 pt-3">
                <p className="max-w-3xl text-[10px] leading-4 text-ink-dim">
                  A second opinion, not a verdict. It saw only the site names and totals on this
                  page — never a URL, a page, or a search — and it cannot block anything.
                </p>
                <Button
                  className="ml-auto shrink-0"
                  size="sm"
                  variant="outline"
                  onClick={() => openAssistant({ kind: "compass", id: "current" })}
                >
                  <MessageSquare className="h-3.5 w-3.5" /> Ask assistant
                </Button>
              </div>
            </>
          ) : null}

          {!review && !reviewing ? (
            <p className="mt-2 text-[11px] text-ink-dim">
              Sends the site names and byte totals from the table below to {""}
              your first-tier model and asks whether anything looks off.
            </p>
          ) : null}
        </section>
      ) : null}

      {settings.insightsEnabled && (summary?.insights.length ?? 0) > 0 ? (
        <section className="border-b border-edge px-5 py-4">
          <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-wide text-ink-dim">
            Worth knowing
          </h2>
          <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
            {summary?.insights.map((insight) => (
              <InsightCard
                key={insight.id}
                insight={insight}
                onMute={mute}
                onDismiss={dismissInsight}
              />
            ))}
          </div>
        </section>
      ) : null}

      <section className="grid grid-cols-[1fr_320px]">
        <div className="min-w-0 border-r border-edge">
          <div className="flex items-center gap-2 border-b border-edge bg-panel px-4 py-2">
            {(
              [
                ["sites", "By site"],
                ["connections", "Every connection"],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                onClick={() => setTab(id)}
                className={cn(
                  "rounded-sm border px-2 py-1 text-[11px]",
                  tab === id
                    ? "border-edge bg-active text-ink"
                    : "border-transparent text-ink-dim hover:text-ink",
                )}
              >
                {label}
              </button>
            ))}
            <label className="ml-3 flex items-center gap-1.5 text-[11px] text-ink-dim">
              <input
                type="checkbox"
                checked={showBackground}
                onChange={(event) => setShowBackground(event.target.checked)}
                className="h-3 w-3 accent-[var(--accent,#0a84ff)]"
              />
              show background chatter
            </label>
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="search a site or address…"
              className="ml-auto h-7 w-56"
            />
          </div>

          {tab === "sites" ? (
            <>
              <div className="grid grid-cols-[1fr_120px_92px_92px_120px_64px] gap-3 border-b border-edge px-4 py-1 text-[10px] uppercase text-ink-dim">
                <span>site</span>
                <span>application</span>
                <span className="text-right">sent</span>
                <span className="text-right">received</span>
                <span>kind</span>
                <span className="text-right">last</span>
              </div>
              {destinations.length === 0 ? (
                <p className="p-10 text-center text-xs text-ink-dim">
                  Nothing recorded yet in {windowText}. Browse for a minute and this fills in.
                </p>
              ) : (
                destinations
                  .slice(0, 200)
                  .map((entry) => (
                    <SiteRow
                      key={entry.key}
                      destination={entry}
                      share={(entry.bytesUp + entry.bytesDown) / biggest}
                      onMute={mute}
                      onSuppressBeacon={toggleBeaconSuppression}
                      beaconSuppressed={settings.beaconSuppressions.includes(entry.key)}
                    />
                  ))
              )}
            </>
          ) : (
            <>
              <div className="grid grid-cols-[70px_1fr_120px_120px_78px_78px] gap-2 border-b border-edge px-4 py-1 text-[10px] uppercase text-ink-dim">
                <span>time</span>
                <span>destination</span>
                <span>application</span>
                <span>service</span>
                <span className="text-right">sent</span>
                <span className="text-right">received</span>
              </div>
              {connections.length === 0 ? (
                <p className="p-10 text-center text-xs text-ink-dim">
                  No connections match this view.
                </p>
              ) : (
                connections.map((flow) => <ConnectionRow key={flow.id} flow={flow} />)
              )}
            </>
          )}
        </div>

        <aside className="bg-panel p-4">
          <h2 className="text-[11px] font-semibold uppercase tracking-wide text-ink">
            What is kept
          </h2>
          <p className="mt-2 text-[11px] leading-5 text-ink-dim">
            Two things, both on this machine only.
          </p>
          <p className="mt-2 text-[11px] leading-5 text-ink-dim">
            Application names are exact live socket matches. Short connections can be missed and
            stay unknown; Compass never guesses from a site or port.
          </p>

          <div className="mt-4 space-y-3">
            <Field
              label="Connection list"
              hint="Which site, process name, how much, when. Erased for good after this."
            >
              <Select
                value={String(settings.rawRetentionHours)}
                onValueChange={(value) =>
                  update({ rawRetentionHours: Number(value) }, "Retention updated.")
                }
                options={[
                  { value: "6", label: "6 hours" },
                  { value: "24", label: "24 hours" },
                  { value: "72", label: "3 days" },
                  { value: "168", label: "7 days" },
                ]}
              />
            </Field>

            <Field
              label="Daily totals per destination"
              hint="One row per site or unresolved address per day. This is the only reason Compass can measure novelty."
            >
              <Select
                value={String(settings.historyDays)}
                onValueChange={(value) =>
                  update({ historyDays: Number(value) }, "History window updated.")
                }
                options={[
                  { value: "0", label: "Do not keep" },
                  { value: "7", label: "7 days" },
                  { value: "30", label: "30 days" },
                  { value: "90", label: "90 days" },
                ]}
              />
            </Field>
          </div>

          <div className="mt-5 border-t border-edge pt-4">
            <Switch
              checked={settings.insightsEnabled}
              onCheckedChange={(value) =>
                update({ insightsEnabled: value }, value ? "Insights on." : "Insights off.")
              }
              label="Show insights"
              hint="Plain-language notes about your own traffic. Computed here; no model involved."
            />
          </div>

          <div className="mt-4 border-t border-edge pt-4">
            <Switch
              checked={settings.aiReviewEnabled}
              onCheckedChange={(value) =>
                update(
                  { aiReviewEnabled: value },
                  value ? "AI review enabled." : "AI review disabled.",
                )
              }
              label="Let the AI analyst review this"
              hint="Adds a button that sends the site names and totals — never URLs or page contents — to your first-tier model. This is the only part of Compass that leaves the machine."
            />
          </div>

          <div className="mt-5 border-t border-edge pt-4">
            <Switch
              checked={settings.beaconDetectionEnabled}
              onCheckedChange={(value) =>
                update(
                  { beaconDetectionEnabled: value },
                  value ? "Beacon detection enabled." : "Beacon detection disabled.",
                )
              }
              label="Detect repeated callbacks"
              hint="May open a security alert from a scored aggregate. Automatic response is always prohibited."
            />
          </div>

          {settings.beaconSuppressions.length > 0 ? (
            <div className="mt-4 border-t border-edge pt-4">
              <h3 className="text-[11px] font-semibold text-ink">Beacon alert suppressions</h3>
              <p className="mt-1 text-[10px] leading-snug text-ink-dim">
                Recording continues. Only beacon alerts are suppressed.
              </p>
              <div className="mt-2 flex flex-wrap gap-1">
                {settings.beaconSuppressions.map((destinationKey) => (
                  <button
                    type="button"
                    key={destinationKey}
                    className="rounded-sm border border-edge px-1.5 py-0.5 font-mono text-[9px] text-ink-dim hover:text-ink"
                    title="Resume beacon alerts"
                    onClick={() => toggleBeaconSuppression(destinationKey)}
                  >
                    {destinationKey} ×
                  </button>
                ))}
              </div>
            </div>
          ) : null}

          <div className="mt-5 border-t border-edge pt-4">
            <h3 className="text-[11px] font-semibold text-ink">Muted sites</h3>
            <p className="mt-1 text-[10px] leading-snug text-ink-dim">
              Never recorded from now on. Works on a single host like
              <span className="font-mono"> detectportal.firefox.com</span> or a whole site.
            </p>
            <div className="mt-2 flex gap-1.5">
              <Input
                value={excludedDomain}
                onChange={(event) => setExcludedDomain(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key !== "Enter" || !excludedDomain.trim()) return;
                  mute(excludedDomain);
                  setExcludedDomain("");
                }}
                placeholder="example.com"
                className="h-7 flex-1"
              />
              <Button
                size="sm"
                variant="ghost"
                disabled={!excludedDomain.trim() || saving}
                onClick={() => {
                  mute(excludedDomain);
                  setExcludedDomain("");
                }}
              >
                mute
              </Button>
            </div>
            {settings.excludedDomains.length > 0 ? (
              <div className="mt-2 flex flex-wrap gap-1">
                {settings.excludedDomains.map((domain) => (
                  <button
                    type="button"
                    key={domain}
                    className="rounded-sm border border-edge px-1.5 py-0.5 font-mono text-[9px] text-ink-dim hover:text-ink"
                    title="Unmute"
                    onClick={() =>
                      update(
                        {
                          excludedDomains: settings.excludedDomains.filter(
                            (entry) => entry !== domain,
                          ),
                        },
                        `${domain} unmuted.`,
                      )
                    }
                  >
                    {domain} ×
                  </button>
                ))}
              </div>
            ) : null}
            <p className="mt-2 text-[9px] leading-4 text-ink-dim">
              Muting stops future recording. Use erase everything to remove what is already stored.
            </p>
          </div>

          <div className="mt-5 flex items-start gap-2 border-t border-edge pt-4 text-[10px] leading-4 text-ink-dim">
            <Lock className="mt-px h-3 w-3 shrink-0" />
            <span>
              This page is never served over remote access, even to you. It exists only on the
              machine doing the browsing.
            </span>
          </div>
        </aside>
      </section>
    </div>
  );
}

function confirmErase(): boolean {
  return window.confirm(
    "Erase every recorded connection, daily total and hidden insight? This cannot be undone.",
  );
}
