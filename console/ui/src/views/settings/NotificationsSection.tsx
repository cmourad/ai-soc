import { Card, Field, SectionTitle, Switch } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import type { SettingsSectionProps } from "./shared";
import { NOTIFICATION_KINDS } from "./shared";

export function NotificationsSection({ draft, patch }: SettingsSectionProps) {
  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>Notifications</SectionTitle>
      <p className="-mt-1 text-[10px] leading-snug text-ink-dim">
        Controls the in-app notification centre. On-call paging is separate and is governed by the
        rotation settings above — muting a kind here never silences a page.
      </p>
      {NOTIFICATION_KINDS.map((kind) => (
        <Switch
          key={kind.value}
          checked={draft.notifications[kind.value]}
          onCheckedChange={(value) => patch("notifications", { [kind.value]: value })}
          label={kind.label}
          hint={kind.hint}
        />
      ))}
      <Field
        label="Also push to Telegram"
        hint="These kinds go out of band as well as into the notification centre."
      >
        <div className="flex flex-wrap gap-1">
          {NOTIFICATION_KINDS.map((kind) => {
            const on = draft.notifications.telegramKinds.includes(kind.value);
            return (
              <button
                key={kind.value}
                type="button"
                onClick={() =>
                  patch("notifications", {
                    telegramKinds: on
                      ? draft.notifications.telegramKinds.filter((entry) => entry !== kind.value)
                      : [...draft.notifications.telegramKinds, kind.value],
                  })
                }
                className={cn(
                  "rounded-sm border px-2 py-0.5 text-[10px] transition-colors",
                  on ? "border-edge bg-active text-ink" : "border-edge text-ink-dim",
                )}
              >
                {kind.label}
              </button>
            );
          })}
        </div>
      </Field>
    </Card>
  );
}
