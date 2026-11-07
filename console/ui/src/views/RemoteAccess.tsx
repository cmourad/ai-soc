import type { TailnetDevice } from "@aisoc/shared";
import { formatBytes } from "@aisoc/shared";
import {
  Laptop,
  Loader2,
  MonitorSmartphone,
  Power,
  Server,
  ShieldOff,
  Smartphone,
} from "lucide-react";
import { useState } from "react";
import { ReadinessChecklist } from "@/components/ReadinessChecklist";
import { Badge, Button, ListEditor, SectionTitle } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { cn, shortAge } from "@/lib/utils";
import { useStore } from "@/store";

const STATUS_COPY = {
  online: { label: "Reachable from your tailnet", tone: "text-ignore", dot: "bg-ignore" },
  login: { label: "Needs login", tone: "text-watch", dot: "bg-watch" },
  down: { label: "Tailnet down", tone: "text-ink-dim", dot: "bg-ink-dim" },
  missing: { label: "Tailscale unavailable", tone: "text-block", dot: "bg-block" },
} as const;

export function RemoteAccessView() {
  const remote = useStore((s) => s.remoteAccess);
  const settings = useStore((s) => s.settings);
  const pushToast = useStore((s) => s.pushToast);
  const [busy, setBusy] = useState(false);

  if (!remote) return null;

  const enabled = settings.remoteAccess.enabled;
  let key: keyof typeof STATUS_COPY = "missing";
  if (remote.present) {
    if (remote.online) key = "online";
    else if (remote.backendState === "NeedsLogin") key = "login";
    else key = "down";
  }
  const status = STATUS_COPY[key];

  const toggle = () => {
    setBusy(true);
    api
      .saveSettings({
        ...settings,
        remoteAccess: { ...settings.remoteAccess, enabled: !enabled },
      })
      .then(() =>
        pushToast("success", enabled ? "Remote access disabled." : "Remote access enabled."),
      )
      .catch((error: Error) => pushToast("error", error.message))
      .finally(() => setBusy(false));
  };

  return (
    <div className="h-full overflow-y-auto">
      <div className="flex flex-col gap-4 p-4">
        <div className="flex flex-col gap-3 rounded-sm border border-edge bg-panel p-4">
          <div className="flex items-center gap-3">
            <span className="relative flex h-3 w-3 items-center justify-center">
              <span
                className={cn("h-2.5 w-2.5 rounded-full", status.dot, key === "online" && "pulse")}
              />
            </span>
            <span className={cn("text-lg font-semibold", status.tone)}>{status.label}</span>
            {remote.funnelOn ? (
              <Badge
                className="border-[#7a2d2d] text-block"
                title="A serve proxy is publicly reachable — this console refuses that."
              >
                funnel on
              </Badge>
            ) : (
              <Badge
                className="text-ink-dim"
                title="tailscale serve only accepts tailnet peers; no public exposure."
              >
                tailnet only
              </Badge>
            )}
            <Button
              className="ml-auto min-w-32"
              variant={enabled ? "danger" : "primary"}
              disabled={busy}
              onClick={toggle}
            >
              {busy ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : enabled ? (
                <ShieldOff className="h-3 w-3" />
              ) : (
                <Power className="h-3 w-3" />
              )}
              {enabled ? "disable" : "enable"}
            </Button>
          </div>

          {!enabled ? (
            <p className="rounded-sm border border-[#7a5a2d] bg-[#2a2113] px-2 py-1.5 text-[11px] text-sev2">
              Remote access is off: nothing listens beyond loopback and the tailnet is not kept up.
            </p>
          ) : null}

          {remote.error ? (
            <p className="rounded-sm border border-[#5a2d2d] bg-[#321e1e] px-2 py-1.5 text-[11px] text-[#f5b8b8]">
              {remote.error}
            </p>
          ) : null}

          <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
            <Fact label="Node" value={remote.node || "—"} />
            <Fact label="Tailnet IP" value={remote.tailnetIP ?? "—"} />
            <Fact
              label="Tailnet name"
              value={remote.dnsName.replace(/\.$/, "") || "—"}
              sub={remote.online ? "reachable from other devices" : undefined}
            />
            <Fact
              label="Devices"
              value={`${remote.devices.filter((device) => device.online).length}/${remote.peerCount} online`}
              sub={
                remote.peerCount === 0
                  ? "sign another device in to see it here"
                  : "other tailnet devices"
              }
            />
          </div>
        </div>

        <Devices devices={remote.devices} />

        <ReadinessChecklist
          load={api.remoteAccessPreflight}
          signature={`${enabled}:${remote.online}:${remote.present}`}
          successText="Everything needed for remote access is in place."
        />

        <Access />
      </div>
    </div>
  );
}

const OS_ICON: Record<string, typeof Laptop> = {
  android: Smartphone,
  ios: Smartphone,
  iOS: Smartphone,
  linux: Server,
  macOS: Laptop,
  windows: Laptop,
};

/**
 * Every device on the tailnet as this host sees it. The `allowed` column is the
 * point: being on the tailnet and being permitted to reach this console are two
 * different things, and an operator should be able to see at a glance which
 * devices could actually get in.
 */
function Devices({ devices }: { devices: TailnetDevice[] }) {
  const online = devices.filter((device) => device.online).length;
  const canReach = devices.filter((device) => device.allowed && !device.self).length;

  return (
    <div>
      <div className="flex flex-wrap items-baseline gap-2">
        <SectionTitle>Devices on your tailnet</SectionTitle>
        <span className="mb-2 text-[10px] text-ink-dim">
          {online}/{devices.length} online · {canReach} allowed to reach this console
        </span>
      </div>

      <div className="overflow-hidden rounded-sm border border-edge">
        <div className="grid grid-cols-[20px_1fr_120px_130px_92px_88px] gap-2 border-b border-edge bg-panel px-3 py-1 text-[10px] uppercase tracking-wide text-ink-dim">
          <span />
          <span>device</span>
          <span>tailnet IP</span>
          <span>path</span>
          <span>traffic</span>
          <span>access</span>
        </div>

        {devices.map((device) => {
          const Icon = OS_ICON[device.os] ?? MonitorSmartphone;
          return (
            <div
              key={device.id}
              className={cn(
                "row-in grid grid-cols-[20px_1fr_120px_130px_92px_88px] items-center gap-2 border-b border-edge/60 px-3 py-1.5 text-[11px] last:border-b-0",
                device.self ? "bg-panel" : "hover:bg-hover",
              )}
            >
              <span className="relative flex items-center">
                <Icon className="h-3.5 w-3.5 text-ink-dim" />
                <span
                  className={cn(
                    "-right-1 absolute bottom-0 h-1.5 w-1.5 rounded-full",
                    device.online ? "bg-ignore" : "bg-ink-dim",
                  )}
                  title={device.online ? "online" : "offline"}
                />
              </span>

              <span className="min-w-0">
                <span className="block truncate text-ink">
                  {device.hostname || device.dnsName || "unnamed"}
                  {device.self ? (
                    <span className="ml-1.5 text-[10px] text-ink-dim">this host</span>
                  ) : null}
                  {device.exitNode ? (
                    <span className="ml-1.5 text-[10px] text-watch">exit node</span>
                  ) : null}
                </span>
                <span className="block truncate text-[10px] text-ink-dim">
                  {device.os || "unknown OS"}
                  {device.owner ? ` · ${device.owner}` : ""}
                  {!device.online && device.lastSeen
                    ? ` · seen ${shortAge(device.lastSeen)} ago`
                    : ""}
                </span>
              </span>

              <span className="truncate font-mono text-[10px] text-ink-dim">
                {device.tailnetIP ?? "—"}
              </span>

              <span className="truncate text-[10px] text-ink-dim">
                {device.self ? (
                  "—"
                ) : device.directAddr ? (
                  <span className="text-ignore">direct</span>
                ) : device.relay ? (
                  <>
                    relayed <span className="font-mono">{device.relay}</span>
                  </>
                ) : (
                  "idle"
                )}
              </span>

              <span className="font-mono text-[10px] text-ink-dim tabular-nums">
                {device.self || (device.rxBytes === 0 && device.txBytes === 0)
                  ? "—"
                  : `${formatBytes(device.rxBytes)} / ${formatBytes(device.txBytes)}`}
              </span>

              <span>
                {device.self ? (
                  <Badge className="text-ink-dim">host</Badge>
                ) : device.allowed ? (
                  <Badge className="border-[#2d5a3d] text-ignore">allowed</Badge>
                ) : (
                  <Badge
                    className="text-ink-dim"
                    title="On the tailnet, but its login is not on the console allowlist"
                  >
                    no access
                  </Badge>
                )}
              </span>
            </div>
          );
        })}

        {devices.length === 0 ? (
          <p className="bg-panel p-6 text-center text-xs text-ink-dim">
            No devices yet. Sign another device into the same tailnet and it appears here.
          </p>
        ) : null}
      </div>
      <p className="mt-1 text-[10px] leading-snug text-ink-dim">
        Devices are discovered from the tailscale daemon. "No access" means the device is on your
        tailnet but its login is not allowlisted above, so it cannot reach this console even though
        it can reach the host.
      </p>
    </div>
  );
}

function Fact({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-sm border border-edge bg-shell px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-ink-dim">{label}</div>
      <div className="truncate font-mono text-[13px] text-ink" title={value}>
        {value}
      </div>
      {sub ? <div className="truncate text-[10px] text-ink-dim">{sub}</div> : null}
    </div>
  );
}

/** Who may get in, and the surface they get. Saved to settings, applied at the boundary. */
function Access() {
  const settings = useStore((s) => s.settings);
  const pushToast = useStore((s) => s.pushToast);
  const allowedLogins = settings.remoteAccess.allowedLogins;

  const save = (allowedLogins: string[]) => {
    api
      .saveSettings({
        ...settings,
        remoteAccess: { ...settings.remoteAccess, allowedLogins },
      })
      .then(() => pushToast("success", "Access list saved."))
      .catch((error: Error) => pushToast("error", error.message));
  };

  return (
    <div className="flex flex-col gap-3 rounded-sm border border-edge bg-panel p-4">
      <SectionTitle>Who can get in</SectionTitle>
      <ListEditor
        label="Allowed tailnet logins"
        hint="Only these identities may reach the console over the tailnet. Every remote action is attributed to the login, so the audit trail shows who did what."
        values={allowedLogins}
        onChange={save}
        placeholder="alice@example.com"
      />
      <p className="text-[10px] leading-snug text-ink-dim">
        Reach it from another tailnet device at{" "}
        <span className="font-mono">https://{"{node}"}.example-tailnet.net:8443/</span>. The
        identity is verified by tailscale itself and injected after the peer authenticates — it
        cannot be spoofed by a remote caller, and the console never runs Funnel, so the surface
        stays tailnet-only.
      </p>
    </div>
  );
}
