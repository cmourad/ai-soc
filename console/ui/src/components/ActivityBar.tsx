import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Bell,
  BrainCircuit,
  BrickWall,
  Compass,
  Crosshair,
  FileBarChart,
  Globe,
  LayoutDashboard,
  ListChecks,
  MonitorSmartphone,
  RadioTower,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Vault,
  Zap,
} from "lucide-react";
import { Tooltip } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { useStore, type ViewId } from "@/store";

const ITEMS: { id: ViewId; label: string; icon: LucideIcon }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "traffic", label: "Traffic", icon: Activity },
  { id: "compass", label: "Network Compass", icon: Compass },
  { id: "dns", label: "DNS activity", icon: Globe },
  { id: "triage", label: "Triage queue", icon: ListChecks },
  { id: "incidents", label: "Incidents", icon: ShieldAlert },
  { id: "assets", label: "Hosts", icon: MonitorSmartphone },
  { id: "response", label: "Response", icon: Zap },
  { id: "firewall", label: "Firewall", icon: BrickWall },
  { id: "quarantine", label: "Quarantine & lists", icon: Vault },
  { id: "llm", label: "Analysis activity", icon: BrainCircuit },
  { id: "vpn", label: "VPN", icon: ShieldCheck },
  { id: "remoteaccess", label: "Remote access", icon: RadioTower },
  { id: "reports", label: "Reports & audit", icon: FileBarChart },
  { id: "pentest", label: "Pentest", icon: Crosshair },
];

export function ActivityBar() {
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const stats = useStore((s) => s.stats);
  const notificationsOpen = useStore((s) => s.notificationsOpen);
  const setNotificationsOpen = useStore((s) => s.setNotificationsOpen);

  const badgeFor = (id: ViewId): number => {
    if (id === "triage") return stats?.needsHuman ?? 0;
    if (id === "llm") return stats?.llmInFlight ?? 0;
    if (id === "incidents") return stats?.openSecurityIncidents ?? 0;
    if (id === "response") return stats?.pendingActions ?? 0;
    if (id === "assets") return stats?.atRiskAssets ?? 0;
    if (id === "quarantine") return stats?.quarantined ?? 0;
    return 0;
  };

  // Pending response actions and at-risk hosts are things a human has to decide
  // on, so they get the red badge; the rest are informational counts.
  const urgent = (id: ViewId): boolean =>
    id === "triage" || id === "response" || id === "incidents" || id === "assets";

  return (
    <nav className="flex w-12 shrink-0 flex-col items-center border-r border-edge bg-bar py-1">
      <div className="flex min-h-0 flex-1 flex-col items-center overflow-y-auto [-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
        {ITEMS.map((item) => {
          const active = view === item.id;
          const badge = badgeFor(item.id);
          return (
            <Tooltip key={item.id} label={item.label}>
              <button
                type="button"
                onClick={() => setView(item.id)}
                className={cn(
                  "relative flex h-11 w-12 items-center justify-center border-l-2 transition-colors",
                  active
                    ? "border-white text-ink-bright"
                    : "border-transparent text-ink-dim hover:text-ink",
                )}
                aria-label={item.label}
                aria-current={active ? "page" : undefined}
              >
                <item.icon className="h-5 w-5" strokeWidth={1.6} />
                {badge > 0 ? (
                  <span
                    className={cn(
                      "absolute right-1 bottom-1 min-w-4 rounded-full px-1 text-center text-[9px] font-bold leading-4 text-white",
                      urgent(item.id) ? "bg-sev1" : "bg-accent",
                    )}
                  >
                    {badge > 99 ? "99+" : badge}
                  </span>
                ) : null}
              </button>
            </Tooltip>
          );
        })}
      </div>

      <div className="flex shrink-0 flex-col items-center">
        <Tooltip label="Notifications">
          <button
            type="button"
            onClick={() => setNotificationsOpen(!notificationsOpen)}
            className={cn(
              "relative flex h-11 w-12 items-center justify-center border-l-2 transition-colors",
              notificationsOpen
                ? "border-white text-ink-bright"
                : "border-transparent text-ink-dim hover:text-ink",
            )}
            aria-label="Notifications"
          >
            <Bell className="h-5 w-5" strokeWidth={1.6} />
            {(stats?.unreadNotifications ?? 0) > 0 ? (
              <span className="absolute right-1 bottom-1 min-w-4 rounded-full bg-accent px-1 text-center text-[9px] font-bold leading-4 text-white">
                {(stats?.unreadNotifications ?? 0) > 99 ? "99+" : stats?.unreadNotifications}
              </span>
            ) : null}
          </button>
        </Tooltip>

        <Tooltip label="Settings">
          <button
            type="button"
            onClick={() => setView("settings")}
            className={cn(
              "flex h-11 w-12 items-center justify-center border-l-2 transition-colors",
              view === "settings"
                ? "border-white text-ink-bright"
                : "border-transparent text-ink-dim hover:text-ink",
            )}
            aria-label="Settings"
          >
            <Settings2 className="h-5 w-5" strokeWidth={1.6} />
          </button>
        </Tooltip>
      </div>
    </nav>
  );
}
