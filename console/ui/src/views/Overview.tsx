import { TACTIC_ORDER } from "@aisoc/shared";
import {
  Activity,
  CheckCircle2,
  Play,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  TriangleAlert,
} from "lucide-react";
import { useMemo, useState } from "react";
import { MitreChips, ScoreBar, Stat } from "@/components/security";
import { type MapExit, ThreatMap, type ThreatOrigin } from "@/components/ThreatMap";
import { Badge, Button, SectionTitle } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { cn, riskBg, shortAge, timeOf } from "@/lib/utils";
import { useStore } from "@/store";

const AUTONOMY_LABEL = {
  manual: "manual confirmation",
  guarded: "auto with guardrails",
  full: "full autonomy",
} as const;

function ProtectionBanner() {
  const stats = useStore((s) => s.stats);
  const settings = useStore((s) => s.settings);
  const setView = useStore((s) => s.setView);

  const detectionOn = settings.detection.enabled;
  const responseOn = settings.response.enabled;
  const paused = settings.ingest.paused;
  const degraded = !detectionOn || paused || (stats?.assetsIsolated ?? 0) > 0;

  const Icon = paused || !detectionOn ? ShieldX : degraded ? ShieldAlert : ShieldCheck;
  const tone = paused || !detectionOn ? "text-block" : degraded ? "text-watch" : "text-ignore";

  return (
    <div className="flex items-center gap-4 rounded-sm border border-edge bg-panel px-4 py-3">
      <Icon className={cn("h-8 w-8 shrink-0", tone)} strokeWidth={1.5} />
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className={cn("text-sm font-semibold", tone)}>
            {paused
              ? "Ingest paused"
              : !detectionOn
                ? "Detection engine disabled"
                : degraded
                  ? "Protected — attention needed"
                  : "Protected"}
          </span>
          <Badge className="font-mono text-ink-dim">{stats?.engineVersion ?? "engine —"}</Badge>
        </div>
        <p className="mt-0.5 text-[11px] leading-snug text-ink-dim">
          {stats?.detectionRuns.toLocaleString() ?? 0} events scored · {stats?.detectionHits ?? 0}{" "}
          rule and indicator hits · response is set to{" "}
          <span className="text-ink">{AUTONOMY_LABEL[stats?.autonomy ?? "manual"]}</span>
          {responseOn ? "" : " (response disabled)"}
        </p>
      </div>
      <Button
        variant="outline"
        size="sm"
        className="ml-auto shrink-0"
        onClick={() => setView("settings")}
      >
        tune protection
      </Button>
    </div>
  );
}

function AttackChainStrip() {
  const alerts = useStore((s) => s.alerts);

  const counts = useMemo(() => {
    const map = new Map<string, number>();
    for (const alert of alerts) {
      for (const ref of alert.detection?.mitre ?? []) {
        map.set(ref.tacticId, (map.get(ref.tacticId) ?? 0) + 1);
      }
    }
    return map;
  }, [alerts]);

  const max = Math.max(1, ...counts.values());

  return (
    <div>
      <SectionTitle>ATT&amp;CK coverage observed</SectionTitle>
      <div className="flex gap-px overflow-x-auto rounded-sm border border-edge">
        {TACTIC_ORDER.map((tactic) => {
          const count = counts.get(tactic.id) ?? 0;
          return (
            <div
              key={tactic.id}
              className="flex min-w-[86px] flex-1 flex-col gap-1 bg-panel px-2 py-1.5"
              title={`${tactic.id} · ${tactic.name}`}
            >
              <span className="truncate text-[9px] uppercase tracking-wide text-ink-dim">
                {tactic.name}
              </span>
              <div className="h-1 overflow-hidden rounded-full bg-edge">
                <div
                  className={cn(
                    "h-full",
                    count === 0 ? "bg-transparent" : riskBg((count / max) * 100),
                  )}
                  style={{ width: `${count === 0 ? 0 : Math.max(12, (count / max) * 100)}%` }}
                />
              </div>
              <span
                className={cn(
                  "font-mono text-[11px] tabular-nums",
                  count === 0 ? "text-ink-dim" : "text-ink",
                )}
              >
                {count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function HostHealth() {
  const assets = useStore((s) => s.assets);
  const setView = useStore((s) => s.setView);
  const selectAsset = useStore((s) => s.selectAsset);

  const sorted = [...assets].sort((a, b) => b.riskScore - a.riskScore);

  return (
    <div>
      <SectionTitle>Host health</SectionTitle>
      <div className="flex flex-col gap-1">
        {sorted.map((asset) => (
          <button
            key={asset.id}
            type="button"
            onClick={() => {
              selectAsset(asset.id);
              setView("assets");
            }}
            className="grid grid-cols-[10px_1fr_auto_auto] items-center gap-2 rounded-sm border border-edge bg-panel px-2 py-1.5 text-left hover:border-status"
          >
            <span
              className={cn(
                "h-2 w-2 rounded-full",
                asset.isolated ? "bg-block" : asset.online ? "bg-ignore" : "bg-ink-dim",
              )}
              title={asset.isolated ? "isolated" : asset.online ? "online" : "offline"}
            />
            <span className="min-w-0">
              <span className="block truncate font-mono text-[11px] text-ink">
                {asset.hostname}
                {asset.isolated ? (
                  <span className="ml-1.5 text-[10px] text-block">isolated</span>
                ) : null}
              </span>
              <span className="block truncate text-[10px] text-ink-dim">
                {asset.ip} · {asset.protection.realtime ? "realtime on" : "realtime OFF"} ·{" "}
                {asset.protection.firewall ? "firewall on" : "firewall OFF"}
              </span>
            </span>
            <span className="text-right text-[10px] text-ink-dim">
              {asset.openAlerts} alert{asset.openAlerts === 1 ? "" : "s"}
            </span>
            <ScoreBar score={asset.riskScore} />
          </button>
        ))}
        {assets.length === 0 ? (
          <p className="p-3 text-center text-xs text-ink-dim">No managed hosts registered.</p>
        ) : null}
      </div>
    </div>
  );
}

function LiveIncidents() {
  const incidents = useStore((s) => s.incidents);
  const setView = useStore((s) => s.setView);
  const selectIncident = useStore((s) => s.selectIncident);

  const open = [...incidents]
    .filter((incident) => incident.status !== "closed")
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
    .slice(0, 6);

  return (
    <div>
      <SectionTitle>Open incidents</SectionTitle>
      <div className="flex flex-col gap-1">
        {open.map((incident) => (
          <button
            key={incident.id}
            type="button"
            onClick={() => {
              selectIncident(incident.id);
              setView("incidents");
            }}
            className="rounded-sm border border-edge bg-panel px-2 py-1.5 text-left hover:border-status"
          >
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11px] text-status">{incident.ref}</span>
              <span className="truncate text-[11px] text-ink">{incident.title}</span>
              <ScoreBar score={incident.score} className="ml-auto shrink-0" width="w-10" />
            </div>
            <div className="mt-1 flex items-center gap-2 text-[10px] text-ink-dim">
              <span>{incident.alertIds.length} alerts</span>
              <span>·</span>
              <span>{incident.status}</span>
              <span>·</span>
              <span>{shortAge(incident.createdAt)} old</span>
              <span className="ml-auto">
                <MitreChips refs={incident.mitre} max={3} />
              </span>
            </div>
          </button>
        ))}
        {open.length === 0 ? (
          <p className="rounded-sm border border-edge bg-panel p-3 text-center text-xs text-ink-dim">
            No open incidents. Correlated alerts appear here as they group.
          </p>
        ) : null}
      </div>
    </div>
  );
}

function PendingApprovals() {
  const actions = useStore((s) => s.actions);
  const analyst = useStore((s) => s.analyst);
  const pushToast = useStore((s) => s.pushToast);
  const setView = useStore((s) => s.setView);
  const [busy, setBusy] = useState<string | null>(null);

  const pending = actions
    .filter((action) => action.status === "pending_approval")
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .slice(0, 5);

  if (pending.length === 0) return null;

  const decide = (id: string, approve: boolean) => {
    setBusy(id);
    const call = approve ? api.approveAction(id, analyst) : api.rejectAction(id, analyst);
    call
      .then(() => pushToast("success", approve ? "Action applied." : "Action rejected."))
      .catch((error: Error) => pushToast("error", error.message))
      .finally(() => setBusy(null));
  };

  return (
    <div>
      <SectionTitle>Waiting on you</SectionTitle>
      <div className="flex flex-col gap-1">
        {pending.map((action) => (
          <div
            key={action.id}
            className="flex items-center gap-2 rounded-sm border border-[#7a5a2d] bg-[#2a2113] px-2 py-1.5"
          >
            <TriangleAlert className="h-3.5 w-3.5 shrink-0 text-sev2" />
            <span className="min-w-0">
              <span className="block truncate font-mono text-[11px] text-ink">
                {action.type.replace(/_/g, " ")} {action.target}
              </span>
              <span className="block truncate text-[10px] text-ink-dim">{action.guardrail}</span>
            </span>
            <Button
              size="sm"
              variant="primary"
              className="ml-auto shrink-0"
              disabled={busy === action.id}
              onClick={() => decide(action.id, true)}
            >
              apply
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="shrink-0"
              disabled={busy === action.id}
              onClick={() => decide(action.id, false)}
            >
              reject
            </Button>
          </div>
        ))}
        <Button variant="ghost" size="sm" onClick={() => setView("response")}>
          open the response queue
        </Button>
      </div>
    </div>
  );
}

function RecentDetections() {
  const detections = useStore((s) => s.detections);
  const selectAlert = useStore((s) => s.selectAlert);
  const setView = useStore((s) => s.setView);

  const recent = [...detections]
    .filter((run) => run.hits.length > 0)
    .sort((a, b) => b.ranAt.localeCompare(a.ranAt))
    .slice(0, 8);

  return (
    <div>
      <SectionTitle>Latest engine hits</SectionTitle>
      <div className="flex flex-col gap-1">
        {recent.map((run) => (
          <button
            key={run.id}
            type="button"
            disabled={!run.alertId}
            onClick={() => {
              if (!run.alertId) return;
              selectAlert(run.alertId);
              setView("triage");
            }}
            className="grid grid-cols-[52px_1fr_auto] items-center gap-2 rounded-sm border border-edge bg-panel px-2 py-1.5 text-left enabled:hover:border-status disabled:opacity-70"
          >
            <span className="font-mono text-[10px] text-ink-dim tabular-nums">
              {timeOf(run.ranAt)}
            </span>
            <span className="min-w-0">
              <span className="block truncate font-mono text-[11px] text-ink">
                {run.hits[0]?.name ?? run.signature}
              </span>
              <span className="block truncate text-[10px] text-ink-dim">
                {run.hits.map((hit) => hit.ruleId).join(" · ")}
              </span>
            </span>
            <ScoreBar score={run.score} width="w-10" />
          </button>
        ))}
        {recent.length === 0 ? (
          <p className="rounded-sm border border-edge bg-panel p-3 text-center text-xs text-ink-dim">
            No engine hits yet.
          </p>
        ) : null}
      </div>
    </div>
  );
}

function ScenarioLauncher() {
  const pushToast = useStore((s) => s.pushToast);
  const [busy, setBusy] = useState(false);

  const scenarios = [
    { id: "c2-beacon", label: "C2 beaconing" },
    { id: "ransomware", label: "Ransomware" },
    { id: "credential-stuffing", label: "Credential stuffing" },
    { id: "exfiltration", label: "Exfiltration" },
    { id: "web-exploit", label: "Web exploit → shell" },
  ];

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="mr-1 text-[10px] uppercase tracking-wide text-ink-dim">Run a scenario</span>
      {scenarios.map((scenario) => (
        <Button
          key={scenario.id}
          size="sm"
          variant="outline"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            api
              .fireScenario(scenario.id)
              .catch((error: Error) => pushToast("error", error.message))
              .finally(() => setBusy(false));
          }}
        >
          <Play className="h-2.5 w-2.5" />
          {scenario.label}
        </Button>
      ))}
    </div>
  );
}

export function OverviewView() {
  const stats = useStore((s) => s.stats);
  const alerts = useStore((s) => s.alerts);
  const settings = useStore((s) => s.settings);
  const setView = useStore((s) => s.setView);

  const vpn = useStore((s) => s.vpn);
  const vpnServers = useStore((s) => s.vpnServers);
  const vpnProfiles = useStore((s) => s.vpnProfiles);

  const exit = useMemo<MapExit | null>(() => {
    if (!vpn || vpn.status === "disconnected") return null;
    const server = vpnServers.find((entry) => entry.id === vpn.serverId);
    if (server) {
      return {
        coords: [server.lat, server.lon],
        label: `${server.city}, ${server.country}`,
        status: vpn.status,
        approximate: false,
      };
    }
    const profile = vpnProfiles.find((entry) => entry.id === vpn.profileId);
    if (!profile) {
      return {
        coords: null,
        label: vpn.exitIp ?? "unknown exit",
        status: vpn.status,
        approximate: false,
      };
    }
    // Provider configs name their country ("ProtonVPN US-FREE#3"), which is the
    // only position an imported profile carries. Borrowing a catalogue server in
    // that country places it to within a country — flagged, never sold as exact.
    const codes = new Set(
      `${profile.name} ${profile.source}`.match(/\b[A-Z]{2}\b/g) ?? ([] as string[]),
    );
    const inCountry = vpnServers.find((entry) => codes.has(entry.countryCode));
    return {
      coords: inCountry ? [inCountry.lat, inCountry.lon] : null,
      label: inCountry ? `${profile.name} · ${inCountry.country}` : profile.name,
      status: vpn.status,
      approximate: true,
    };
  }, [vpn, vpnServers, vpnProfiles]);

  const origins = useMemo<ThreatOrigin[]>(() => {
    const map = new Map<string, ThreatOrigin>();
    for (const alert of alerts) {
      const intel = alert.enrichment;
      if (!intel?.lat || !intel.lon) continue;
      const existing = map.get(intel.indicator);
      map.set(intel.indicator, {
        id: intel.indicator,
        lat: intel.lat,
        lon: intel.lon,
        label: intel.indicator,
        country: intel.country,
        asn: intel.asn,
        reputation: Math.max(existing?.reputation ?? 0, intel.reputation),
        count: (existing?.count ?? 0) + 1,
      });
    }
    return [...map.values()].sort((a, b) => b.count - a.count);
  }, [alerts]);

  return (
    <div className="h-full overflow-y-auto">
      <div className="flex flex-col gap-4 p-4">
        <ProtectionBanner />

        <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-7">
          <Stat
            label="Malicious"
            value={stats?.malicious ?? 0}
            tone="text-block"
            hint={`${stats?.suspicious ?? 0} suspicious`}
            onClick={() => setView("triage")}
          />
          <Stat
            label="Needs a human"
            value={stats?.needsHuman ?? 0}
            tone={(stats?.needsHuman ?? 0) > 0 ? "text-sev2" : undefined}
            hint={`${stats?.openAlerts ?? 0} open alerts`}
            onClick={() => setView("triage")}
          />
          <Stat
            label="Incidents"
            value={stats?.openSecurityIncidents ?? 0}
            hint="open and correlated"
            onClick={() => setView("incidents")}
          />
          <Stat
            label="Pending actions"
            value={stats?.pendingActions ?? 0}
            tone={(stats?.pendingActions ?? 0) > 0 ? "text-sev2" : undefined}
            hint={`${stats?.appliedActions ?? 0} applied`}
            onClick={() => setView("response")}
          />
          <Stat
            label="Quarantined"
            value={stats?.quarantined ?? 0}
            hint="held in the vault"
            onClick={() => setView("quarantine")}
          />
          <Stat
            label="Hosts at risk"
            value={stats?.atRiskAssets ?? 0}
            tone={(stats?.atRiskAssets ?? 0) > 0 ? "text-sev2" : undefined}
            hint={`${stats?.assetsOnline ?? 0}/${stats?.assetsTotal ?? 0} online · ${stats?.assetsIsolated ?? 0} isolated`}
            onClick={() => setView("assets")}
          />
          <Stat
            label="Throughput"
            value={stats?.eventsPerSecond.toFixed(1) ?? "0.0"}
            hint={`${stats?.totalEvents.toLocaleString() ?? 0} events scored`}
            onClick={() => setView("traffic")}
          />
        </div>

        <ScenarioLauncher />

        <div className="grid gap-4 xl:grid-cols-[1fr_380px]">
          <div className="flex flex-col gap-4">
            <div>
              <SectionTitle>Egress and attack origins</SectionTitle>
              <ThreatMap
                origins={origins}
                home={{ lat: settings.site.lat, lon: settings.site.lon, name: settings.site.name }}
                exit={exit}
                egressHeld={vpn?.killSwitchEngaged ?? false}
                className="h-[340px]"
              />
            </div>
            <AttackChainStrip />
            <RecentDetections />
          </div>

          <div className="flex flex-col gap-4">
            <PendingApprovals />
            <LiveIncidents />
            <HostHealth />
            <PipelineHealth />
          </div>
        </div>
      </div>
    </div>
  );
}

function PipelineHealth() {
  const stats = useStore((s) => s.stats);
  const setView = useStore((s) => s.setView);

  const rows = [
    {
      icon: Activity,
      label: "Detection engine",
      value: `${stats?.detectionRuns.toLocaleString() ?? 0} runs · ${stats?.detectionHits ?? 0} hits`,
      ok: true,
    },
    {
      icon: CheckCircle2,
      label: "Model triage",
      value: `${stats?.llmInFlight ?? 0} in flight · ${stats?.llmTotal ?? 0} calls · ${stats?.llmErrors ?? 0} failed`,
      ok: (stats?.llmErrors ?? 0) === 0,
    },
    {
      icon: Activity,
      label: "Triage backlog",
      value: `${stats?.queueDepth ?? 0}/${stats?.queueCapacity ?? 0} queued`,
      ok: (stats?.queueDepth ?? 0) < (stats?.queueCapacity ?? 1),
    },
  ];

  return (
    <div>
      <SectionTitle>Pipeline</SectionTitle>
      <div className="flex flex-col gap-1">
        {rows.map((row) => (
          <button
            key={row.label}
            type="button"
            onClick={() => setView("llm")}
            className="flex items-center gap-2 rounded-sm border border-edge bg-panel px-2 py-1.5 text-left hover:border-status"
          >
            <row.icon className={cn("h-3 w-3", row.ok ? "text-ignore" : "text-sev2")} />
            <span className="text-[11px] text-ink">{row.label}</span>
            <span className="ml-auto font-mono text-[10px] text-ink-dim">{row.value}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
