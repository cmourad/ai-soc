import { MessageSquare } from "lucide-react";
import { useEffect } from "react";
import { ActivityBar } from "@/components/ActivityBar";
import { AssistantPanel } from "@/components/AssistantPanel";
import { DetailPanel } from "@/components/DetailPanel";
import { NotificationCenter } from "@/components/NotificationCenter";
import { ServiceTerminal } from "@/components/ServiceTerminal";
import { StatusBar } from "@/components/StatusBar";
import { Toasts } from "@/components/Toasts";
import { Button } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { connect, useStore, type ViewId } from "@/store";
import { AssetsView } from "@/views/Assets";
import { DnsView } from "@/views/Dns";
import { FirewallView } from "@/views/Firewall";
import { IncidentsView } from "@/views/Incidents";
import { LlmActivityView } from "@/views/LlmActivity";
import { NetworkCompassView } from "@/views/NetworkCompass";
import { OverviewView } from "@/views/Overview";
import { PentestView } from "@/views/Pentest";
import { QuarantineView } from "@/views/Quarantine";
import { RemoteAccessView } from "@/views/RemoteAccess";
import { ReportsView } from "@/views/Reports";
import { ResponseView } from "@/views/Response";
import { SettingsView } from "@/views/Settings";
import { TrafficView } from "@/views/Traffic";
import { TriageView } from "@/views/Triage";
import { VpnView } from "@/views/Vpn";

const TITLES: Record<ViewId, string> = {
  overview: "Overview",
  traffic: "Traffic",
  compass: "Network Compass",
  dns: "DNS activity",
  triage: "Triage queue",
  incidents: "Incidents",
  assets: "Hosts",
  response: "Response",
  firewall: "Firewall",
  quarantine: "Quarantine & lists",
  llm: "Analysis activity",
  vpn: "VPN",
  remoteaccess: "Remote access",
  reports: "Reports & audit",
  pentest: "Pentest",
  settings: "Settings",
};

/** Ctrl/Cmd+1…9 in activity-bar order, matching the VS Code muscle memory. */
const SHORTCUTS: ViewId[] = [
  "overview",
  "traffic",
  "triage",
  "incidents",
  "assets",
  "response",
  "firewall",
  "quarantine",
  "llm",
  "vpn",
];

export function App() {
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const setNotificationsOpen = useStore((s) => s.setNotificationsOpen);
  const terminalOpen = useStore((s) => s.terminalOpen);
  const setTerminalOpen = useStore((s) => s.setTerminalOpen);
  const assistantOpen = useStore((s) => s.assistantOpen);
  const openAssistant = useStore((s) => s.openAssistant);
  const closeAssistant = useStore((s) => s.closeAssistant);

  useEffect(() => {
    connect();
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setNotificationsOpen(false);
        return;
      }
      if (!event.ctrlKey && !event.metaKey) return;
      if (event.key === ",") {
        event.preventDefault();
        setView("settings");
        return;
      }
      if (event.key === "`") {
        event.preventDefault();
        setTerminalOpen(!useStore.getState().terminalOpen);
        return;
      }
      const slot = Number(event.key);
      if (!Number.isInteger(slot) || slot < 1 || slot > SHORTCUTS.length) return;
      event.preventDefault();
      setView(SHORTCUTS[slot - 1]!);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setView, setNotificationsOpen, setTerminalOpen]);

  return (
    <div className="flex h-full flex-col">
      <header className="flex h-8 shrink-0 items-center border-b border-edge bg-bar px-3 text-[11px] tracking-wide text-ink-dim">
        <span className="font-semibold text-ink">AI SOC</span>
        <span className="mx-2 text-edge">›</span>
        <span>{TITLES[view]}</span>
        <Button
          size="icon"
          variant="ghost"
          className={cn("ml-auto", assistantOpen && "bg-active text-ink-bright")}
          title="Assistant conversations"
          aria-label="Assistant conversations"
          onClick={() => (assistantOpen ? closeAssistant() : openAssistant())}
        >
          <MessageSquare className="h-3.5 w-3.5" />
        </Button>
      </header>

      <div className="flex min-h-0 flex-1">
        <ActivityBar />
        <div className="flex min-w-0 flex-1 flex-col">
          <div className="flex min-h-0 flex-1">
            <main className="min-w-0 flex-1">
              {view === "overview" ? <OverviewView /> : null}
              {view === "traffic" ? <TrafficView /> : null}
              {view === "compass" ? <NetworkCompassView /> : null}
              {view === "dns" ? <DnsView /> : null}
              {view === "triage" ? <TriageView /> : null}
              {view === "incidents" ? <IncidentsView /> : null}
              {view === "assets" ? <AssetsView /> : null}
              {view === "response" ? <ResponseView /> : null}
              {view === "firewall" ? <FirewallView /> : null}
              {view === "quarantine" ? <QuarantineView /> : null}
              {view === "llm" ? <LlmActivityView /> : null}
              {view === "vpn" ? <VpnView /> : null}
              {view === "remoteaccess" ? <RemoteAccessView /> : null}
              {view === "reports" ? <ReportsView /> : null}
              {view === "pentest" ? <PentestView /> : null}
              {view === "settings" ? <SettingsView /> : null}
            </main>
            {view === "traffic" || view === "triage" ? <DetailPanel /> : null}
            {assistantOpen ? <AssistantPanel /> : null}
          </div>
          <ServiceTerminal open={terminalOpen} onClose={() => setTerminalOpen(false)} />
        </div>
      </div>

      <StatusBar />
      <NotificationCenter />
      <Toasts />
    </div>
  );
}
