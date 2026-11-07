import {
  AlertTriangle,
  Cpu,
  Layers,
  Pause,
  Play,
  Radio,
  RadioTower,
  ShieldCheck,
  ShieldOff,
  Terminal,
  Wifi,
  WifiOff,
} from "lucide-react";
import { api } from "@/lib/api";
import { cn, formatNumber } from "@/lib/utils";
import { useStore } from "@/store";

function Item({
  icon: Icon,
  children,
  onClick,
  title,
  className,
}: {
  icon?: typeof Wifi;
  children: React.ReactNode;
  onClick?: () => void;
  title?: string;
  className?: string;
}) {
  const Tag = onClick ? "button" : "div";
  return (
    <Tag
      {...(onClick ? { type: "button" as const, onClick } : {})}
      title={title}
      className={cn(
        "flex h-full items-center gap-1.5 px-2 text-[11px] tabular-nums",
        onClick && "hover:bg-white/15",
        className,
      )}
    >
      {Icon ? <Icon className="h-3 w-3" strokeWidth={2} /> : null}
      {children}
    </Tag>
  );
}

export function StatusBar() {
  const connected = useStore((s) => s.connected);
  const stats = useStore((s) => s.stats);
  const settings = useStore((s) => s.settings);
  const pushToast = useStore((s) => s.pushToast);
  const setView = useStore((s) => s.setView);
  const terminalOpen = useStore((s) => s.terminalOpen);
  const setTerminalOpen = useStore((s) => s.setTerminalOpen);

  const paused = settings.ingest.paused;
  const vpnStatus = stats?.vpnStatus ?? "disconnected";
  const downSensors = (stats?.sensors ?? []).filter((sensor) => !sensor.ok);
  const vpnUp = vpnStatus === "connected";

  return (
    <footer
      className={cn(
        "flex h-[22px] shrink-0 select-none items-stretch justify-between text-white",
        connected ? "bg-status" : "bg-[#8b1f1f]",
      )}
    >
      <div className="flex items-stretch">
        <Item icon={connected ? Wifi : WifiOff}>{connected ? "connected" : "backend offline"}</Item>
        <Item icon={Radio} title="Ingest source and rate">
          {stats?.ingestSource ?? "—"} · {stats?.eventsPerSecond.toFixed(1) ?? "0.0"} ev/s
        </Item>
        {downSensors.length > 0 ? (
          <Item
            icon={RadioTower}
            onClick={() => setView("traffic")}
            title={downSensors.map((sensor) => `${sensor.label}: ${sensor.detail}`).join("\n")}
          >
            <span className="text-[#ffd7d7]">
              {downSensors.length === 1
                ? `${downSensors[0]?.label} down`
                : `${downSensors.length} sensors down`}
            </span>
          </Item>
        ) : null}
        <Item
          icon={paused ? Play : Pause}
          onClick={() => {
            const action = paused ? api.resume() : api.pause();
            action.catch((error: Error) => pushToast("error", error.message));
          }}
          title={paused ? "Resume ingest" : "Pause ingest"}
        >
          {paused ? "paused" : "live"}
        </Item>
        {settings.vpn.enabled ? (
          <Item
            icon={vpnUp ? ShieldCheck : ShieldOff}
            onClick={() => setView("vpn")}
            title={
              stats?.vpnKillSwitch
                ? "VPN down with the kill switch engaged — egress is blocked"
                : "VPN tunnel status"
            }
          >
            {vpnUp
              ? `vpn ${stats?.vpnCountry ?? "up"}`
              : stats?.vpnKillSwitch
                ? "vpn down · egress blocked"
                : `vpn ${vpnStatus}`}
          </Item>
        ) : null}
      </div>

      <div className="flex items-stretch">
        <Item icon={AlertTriangle} title="Open alerts / awaiting a human">
          {stats?.openAlerts ?? 0} open · {stats?.needsHuman ?? 0} need a human
        </Item>
        <Item
          icon={Layers}
          title="Alerts queued for a triage slot. At capacity, the oldest are shed to a human rather than queued forever."
        >
          queue {stats?.queueDepth ?? 0}/{stats?.queueCapacity ?? 0}
        </Item>
        <Item icon={Cpu} title="LLM calls in flight / total / errors">
          {stats?.llmInFlight ?? 0} in flight · {formatNumber(stats?.llmTotal ?? 0)} calls
          {stats?.llmErrors ? ` · ${stats.llmErrors} failed` : ""}
        </Item>
        <Item title="Tokens consumed this session">{formatNumber(stats?.tokensUsed ?? 0)} tok</Item>
        <Item
          icon={Terminal}
          onClick={() => setTerminalOpen(!terminalOpen)}
          title="Toggle terminal (Ctrl+`)"
          className={terminalOpen ? "bg-white/15" : ""}
        >
          terminal
        </Item>
      </div>
    </footer>
  );
}
