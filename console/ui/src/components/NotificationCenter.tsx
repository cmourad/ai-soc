import type { NotificationKind } from "@aisoc/shared";
import { Bell, HardDrive, Phone, ScanSearch, Shield, X, Zap } from "lucide-react";
import { api } from "@/lib/api";
import { cn, shortAge } from "@/lib/utils";
import { useStore, type ViewId } from "@/store";

const KIND_ICON: Record<NotificationKind, typeof Bell> = {
  detection: ScanSearch,
  response: Zap,
  incident: Shield,
  asset: HardDrive,
  oncall: Phone,
  system: Bell,
};

const LEVEL_TONE = {
  critical: "text-block",
  warning: "text-sev2",
  info: "text-[#8ab4d8]",
} as const;

const VIEWS = new Set<string>([
  "overview",
  "traffic",
  "triage",
  "incidents",
  "assets",
  "response",
  "quarantine",
  "llm",
  "reports",
  "settings",
]);

export function NotificationCenter() {
  const open = useStore((s) => s.notificationsOpen);
  const setOpen = useStore((s) => s.setNotificationsOpen);
  const notifications = useStore((s) => s.notifications);
  const setView = useStore((s) => s.setView);
  const selectAlert = useStore((s) => s.selectAlert);
  const selectIncident = useStore((s) => s.selectIncident);
  const selectAsset = useStore((s) => s.selectAsset);
  const pushToast = useStore((s) => s.pushToast);

  if (!open) return null;

  const recent = [...notifications].reverse().slice(0, 60);

  const follow = (linkView: string | null, linkId: string | null) => {
    if (!linkView || !VIEWS.has(linkView)) return;
    if (linkView === "triage" && linkId) selectAlert(linkId);
    if (linkView === "incidents" && linkId) selectIncident(linkId);
    if (linkView === "assets" && linkId) selectAsset(linkId);
    setView(linkView as ViewId);
    setOpen(false);
  };

  return (
    <>
      <button
        type="button"
        aria-label="Close notifications"
        className="fixed inset-0 z-40 cursor-default"
        onClick={() => setOpen(false)}
      />
      <aside className="fixed right-0 top-8 bottom-[22px] z-50 flex w-[380px] flex-col border-l border-edge bg-panel shadow-2xl">
        <header className="flex h-8 shrink-0 items-center gap-2 border-b border-edge px-3">
          <span className="text-[11px] uppercase tracking-wide text-ink-dim">Notifications</span>
          <button
            type="button"
            className="ml-auto text-[11px] text-ink-dim hover:text-ink"
            onClick={() =>
              api
                .markNotificationsRead(null)
                .catch((error: Error) => pushToast("error", error.message))
            }
          >
            mark all read
          </button>
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="text-ink-dim hover:text-ink"
            aria-label="Close notifications"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </header>

        <div className="flex-1 overflow-y-auto">
          {recent.map((notification) => {
            const Icon = KIND_ICON[notification.kind];
            return (
              <button
                key={notification.id}
                type="button"
                onClick={() => {
                  api
                    .markNotificationsRead([notification.id])
                    .catch((error: Error) => pushToast("error", error.message));
                  follow(notification.linkView, notification.linkId);
                }}
                className={cn(
                  "flex w-full gap-2 border-b border-edge/60 px-3 py-2 text-left hover:bg-hover",
                  notification.read ? "opacity-60" : "",
                )}
              >
                <Icon
                  className={cn("mt-0.5 h-3.5 w-3.5 shrink-0", LEVEL_TONE[notification.level])}
                />
                <span className="min-w-0 flex-1">
                  <span className="flex items-baseline gap-2">
                    <span className="truncate text-[11px] text-ink">{notification.title}</span>
                    <span className="ml-auto shrink-0 font-mono text-[10px] text-ink-dim">
                      {shortAge(notification.at)}
                    </span>
                  </span>
                  <span className="mt-0.5 block text-[10px] leading-snug text-ink-dim">
                    {notification.body}
                  </span>
                </span>
                {!notification.read ? (
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-status" />
                ) : null}
              </button>
            );
          })}
          {recent.length === 0 ? (
            <p className="p-6 text-center text-xs text-ink-dim">
              Nothing yet. Per-feature switches live in Settings → Notifications.
            </p>
          ) : null}
        </div>
      </aside>
    </>
  );
}
