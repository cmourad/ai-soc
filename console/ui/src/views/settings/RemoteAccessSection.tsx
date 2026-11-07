import { Card, ListEditor, SectionTitle, Switch } from "@/components/ui/primitives";
import type { SettingsSectionProps } from "./shared";

export function RemoteAccessSection({ draft, patch }: SettingsSectionProps) {
  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>Remote access</SectionTitle>
      <Switch
        checked={draft.remoteAccess.enabled}
        onCheckedChange={(enabled) => patch("remoteAccess", { enabled })}
        label="Tailnet remote access"
        hint="Keeps the tailnet up so other devices on your tailnet can reach this console. Off remains fail-closed — nothing listens beyond localhost."
      />
      <ListEditor
        label="Allowed logins"
        hint="Tailnet identities (user@domain) that remote callers may use. Applied at the trust boundary when a request arrives tagged with a tailnet identity."
        values={draft.remoteAccess.allowedLogins}
        onChange={(allowedLogins) => patch("remoteAccess", { allowedLogins })}
        placeholder="alice@example.com"
      />
      <p className="text-[10px] leading-snug text-ink-dim">
        Bringing the tailnet up unprivileged needs <code>sudo tailscale set --operator=$USER</code>{" "}
        run once on the host.
      </p>
    </Card>
  );
}
