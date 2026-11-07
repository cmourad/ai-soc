import type { Asset } from "@aisoc/shared";
import { Container, HardDrive, Laptop, Server, ShieldOff } from "lucide-react";
import { useState } from "react";
import { ScoreBar } from "@/components/security";
import { Badge, Button, SectionTitle } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { cn, riskColor, severityBg, shortAge, timeOf } from "@/lib/utils";
import { useStore } from "@/store";

const KIND_ICON = {
  workstation: HardDrive,
  laptop: Laptop,
  server: Server,
  container: Container,
} as const;

function ProtectionPill({ on, label }: { on: boolean; label: string }) {
  return (
    <Badge className={cn(on ? "border-[#2d5a3d] text-ignore" : "border-[#7a2d2d] text-block")}>
      {label} {on ? "on" : "off"}
    </Badge>
  );
}

function AssetCard({ asset, selected }: { asset: Asset; selected: boolean }) {
  const selectAsset = useStore((s) => s.selectAsset);
  const Icon = KIND_ICON[asset.kind];

  return (
    <button
      type="button"
      onClick={() => selectAsset(asset.id)}
      className={cn(
        "flex w-full items-center gap-3 border-b border-edge/60 px-3 py-2 text-left",
        selected ? "bg-active" : "hover:bg-hover",
      )}
    >
      <Icon className="h-4 w-4 shrink-0 text-ink-dim" strokeWidth={1.6} />
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2">
          <span className="truncate font-mono text-[12px] text-ink">{asset.hostname}</span>
          {asset.isolated ? <Badge className="border-[#7a2d2d] text-block">isolated</Badge> : null}
          <span
            className={cn("h-1.5 w-1.5 rounded-full", asset.online ? "bg-ignore" : "bg-ink-dim")}
            title={asset.online ? "online" : "offline"}
          />
        </span>
        <span className="block truncate text-[10px] text-ink-dim">
          {asset.ip} · {asset.os} · {asset.owner}
        </span>
      </span>
      <span className="shrink-0 text-right text-[10px] text-ink-dim">
        {asset.openAlerts} open
        <br />
        {asset.criticalAlerts} critical
      </span>
      <ScoreBar score={asset.riskScore} className="shrink-0" />
    </button>
  );
}

function AssetDetail({ asset }: { asset: Asset }) {
  const analyst = useStore((s) => s.analyst);
  const alerts = useStore((s) => s.alerts);
  const incidents = useStore((s) => s.incidents);
  const actions = useStore((s) => s.actions);
  const quarantine = useStore((s) => s.quarantine);
  const pushToast = useStore((s) => s.pushToast);
  const selectAlert = useStore((s) => s.selectAlert);
  const selectIncident = useStore((s) => s.selectIncident);
  const setView = useStore((s) => s.setView);
  const [busy, setBusy] = useState(false);

  const hostAlerts = alerts
    .filter((alert) => alert.assetId === asset.id)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const hostIncidents = incidents.filter((incident) => incident.assetIds.includes(asset.id));
  const hostActions = actions.filter((action) => action.assetId === asset.id);
  const hostQuarantine = quarantine.filter((item) => item.assetId === asset.id);

  // Every process, file, and hash this host has been seen touching — the pivot
  // an analyst actually needs when they land on a host from an alert.
  const processes = new Map<string, { pid: number | null; parent: string | null; count: number }>();
  const files = new Map<string, string | null>();
  for (const alert of hostAlerts) {
    const event = alert.event;
    if (event.processName) {
      const existing = processes.get(event.processName);
      processes.set(event.processName, {
        pid: event.processPid ?? existing?.pid ?? null,
        parent: event.parentProcess ?? existing?.parent ?? null,
        count: (existing?.count ?? 0) + 1,
      });
    }
    if (event.filePath) files.set(event.filePath, event.fileSha256 ?? null);
  }

  const isolate = (isolated: boolean) => {
    setBusy(true);
    api
      .isolateAsset(asset.id, isolated, analyst)
      .then(() =>
        pushToast(
          isolated ? "success" : "info",
          isolated ? `${asset.hostname} isolated.` : `${asset.hostname} back on the network.`,
        ),
      )
      .catch((error: Error) => pushToast("error", error.message))
      .finally(() => setBusy(false));
  };

  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <div className="border-b border-edge bg-panel px-3 py-2">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm text-ink-bright">{asset.hostname}</span>
          <ScoreBar score={asset.riskScore} className="ml-auto" />
        </div>
        <p className="mt-0.5 text-[10px] text-ink-dim">
          {asset.ip} · {asset.mac} · {asset.os}
        </p>
        <div className="mt-2 flex flex-wrap gap-1">
          <ProtectionPill on={asset.protection.realtime} label="realtime" />
          <ProtectionPill on={asset.protection.firewall} label="firewall" />
          <Badge className="text-ink-dim">rules {asset.protection.rulesVersion}</Badge>
          <Badge className="text-ink-dim">{asset.protection.agentVersion}</Badge>
          {asset.tags.map((tag) => (
            <Badge key={tag} className="text-ink-dim">
              {tag}
            </Badge>
          ))}
        </div>
        <div className="mt-2 flex gap-1.5">
          {asset.isolated ? (
            <Button variant="secondary" size="sm" disabled={busy} onClick={() => isolate(false)}>
              release from isolation
            </Button>
          ) : (
            <Button variant="danger" size="sm" disabled={busy} onClick={() => isolate(true)}>
              <ShieldOff className="h-3 w-3" />
              isolate host
            </Button>
          )}
        </div>
        <p className="mt-1.5 text-[10px] leading-snug text-ink-dim">
          Isolation cuts the host off the network while leaving the management path to this console
          up. Reversible from here at any time.
        </p>
      </div>

      <div className="flex flex-col gap-4 p-3">
        <div className="grid grid-cols-3 gap-2 text-[11px]">
          <div className="rounded-sm border border-edge bg-shell p-2">
            <div className="text-[10px] uppercase text-ink-dim">last seen</div>
            <div className="font-mono text-ink">{shortAge(asset.lastSeen)} ago</div>
          </div>
          <div className="rounded-sm border border-edge bg-shell p-2">
            <div className="text-[10px] uppercase text-ink-dim">last scan</div>
            <div className="font-mono text-ink">
              {asset.protection.lastScan
                ? new Date(asset.protection.lastScan).toLocaleDateString()
                : "never"}
            </div>
          </div>
          <div className="rounded-sm border border-edge bg-shell p-2">
            <div className="text-[10px] uppercase text-ink-dim">risk</div>
            <div className={cn("font-mono", riskColor(asset.riskScore))}>{asset.riskScore}/100</div>
          </div>
        </div>

        {hostIncidents.length > 0 ? (
          <div>
            <SectionTitle>Incidents</SectionTitle>
            <div className="flex flex-col gap-1">
              {hostIncidents.map((incident) => (
                <button
                  key={incident.id}
                  type="button"
                  onClick={() => {
                    selectIncident(incident.id);
                    setView("incidents");
                  }}
                  className="flex items-center gap-2 rounded-sm border border-edge bg-shell px-2 py-1 text-left text-[11px] hover:border-status"
                >
                  <span className="font-mono text-status">{incident.ref}</span>
                  <span className="truncate text-ink">{incident.title}</span>
                  <span className="ml-auto shrink-0 text-[10px] text-ink-dim">
                    {incident.status}
                  </span>
                </button>
              ))}
            </div>
          </div>
        ) : null}

        <div>
          <SectionTitle>Alerts on this host</SectionTitle>
          <div className="flex flex-col gap-1">
            {hostAlerts.slice(0, 12).map((alert) => (
              <button
                key={alert.id}
                type="button"
                onClick={() => {
                  selectAlert(alert.id);
                  setView("triage");
                }}
                className="flex items-center gap-2 rounded-sm border border-edge bg-shell px-2 py-1 text-left text-[11px] hover:border-status"
              >
                <span
                  className={cn(
                    "h-1.5 w-1.5 shrink-0 rounded-full",
                    severityBg(alert.event.severity),
                  )}
                />
                <span className="truncate font-mono text-ink">{alert.event.signature}</span>
                <span className="ml-auto shrink-0 font-mono text-[10px] text-ink-dim">
                  {alert.detection?.score ?? 0}
                </span>
                <span className="shrink-0 font-mono text-[10px] text-ink-dim">
                  {timeOf(alert.createdAt)}
                </span>
              </button>
            ))}
            {hostAlerts.length === 0 ? (
              <p className="text-[11px] text-ink-dim">Nothing has fired on this host.</p>
            ) : null}
          </div>
        </div>

        {processes.size > 0 ? (
          <div>
            <SectionTitle>Processes seen</SectionTitle>
            <div className="flex flex-col gap-1">
              {[...processes.entries()].map(([name, info]) => (
                <div
                  key={name}
                  className="rounded-sm border border-edge bg-shell px-2 py-1 text-[11px]"
                >
                  <div className="truncate font-mono text-ink" title={name}>
                    {name}
                  </div>
                  <div className="text-[10px] text-ink-dim">
                    {info.pid ? `pid ${info.pid}` : "pid unknown"}
                    {info.parent ? ` · parent ${info.parent}` : ""} · {info.count}×
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {files.size > 0 ? (
          <div>
            <SectionTitle>Files and hashes</SectionTitle>
            <div className="flex flex-col gap-1">
              {[...files.entries()].map(([path, sha]) => (
                <div
                  key={path}
                  className="rounded-sm border border-edge bg-shell px-2 py-1 text-[11px]"
                >
                  <div className="truncate font-mono text-ink" title={path}>
                    {path}
                  </div>
                  {sha ? (
                    <div className="truncate font-mono text-[10px] text-ink-dim" title={sha}>
                      sha256 {sha}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {hostActions.length > 0 || hostQuarantine.length > 0 ? (
          <div>
            <SectionTitle>Containment</SectionTitle>
            <div className="flex flex-col gap-1">
              {hostActions.map((action) => (
                <div
                  key={action.id}
                  className="flex items-center gap-2 rounded-sm border border-edge bg-shell px-2 py-1 text-[11px]"
                >
                  <span className="truncate font-mono text-ink">
                    {action.type.replace(/_/g, " ")} {action.target}
                  </span>
                  <span className="ml-auto shrink-0 text-[10px] text-ink-dim">
                    {action.status.replace(/_/g, " ")}
                  </span>
                </div>
              ))}
              {hostQuarantine.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center gap-2 rounded-sm border border-edge bg-shell px-2 py-1 text-[11px]"
                >
                  <span className="truncate font-mono text-ink">{item.value}</span>
                  <span className="ml-auto shrink-0 text-[10px] text-ink-dim">{item.status}</span>
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function AssetsView() {
  const assets = useStore((s) => s.assets);
  const selectedAssetId = useStore((s) => s.selectedAssetId);
  const stats = useStore((s) => s.stats);

  const sorted = [...assets].sort((a, b) => b.riskScore - a.riskScore);
  const selected = assets.find((asset) => asset.id === selectedAssetId) ?? sorted[0];

  return (
    <div className="flex h-full">
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex shrink-0 items-center gap-4 border-b border-edge bg-panel px-3 py-1.5 text-[10px] text-ink-dim">
          <span>
            {stats?.assetsOnline ?? 0}/{stats?.assetsTotal ?? 0} online
          </span>
          <span>{stats?.atRiskAssets ?? 0} at risk</span>
          <span>{stats?.assetsIsolated ?? 0} isolated</span>
          <span className="ml-auto">
            Risk decays on a 45-minute half-life, so a host that goes quiet returns to green on its
            own.
          </span>
        </div>
        <div className="flex-1 overflow-y-auto">
          {sorted.map((asset) => (
            <AssetCard key={asset.id} asset={asset} selected={asset.id === selected?.id} />
          ))}
        </div>
      </div>

      <aside className="flex w-[460px] shrink-0 flex-col border-l border-edge bg-panel">
        {selected ? (
          <AssetDetail asset={selected} />
        ) : (
          <p className="p-6 text-center text-xs text-ink-dim">No hosts registered.</p>
        )}
      </aside>
    </div>
  );
}
