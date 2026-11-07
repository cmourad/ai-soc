import { Send } from "lucide-react";
import { useState } from "react";
import { Button, Card, Field, Input, SectionTitle, Switch } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { useStore } from "@/store";
import type { SettingsSectionProps } from "./shared";
import { SecretField } from "./shared";

export function SmtpSection({ draft, patch }: SettingsSectionProps) {
  const secrets = useStore((s) => s.secrets);
  const pushToast = useStore((s) => s.pushToast);
  const [testEmail, setTestEmail] = useState("");

  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>Email fallback (SMTP)</SectionTitle>
      <Switch
        label="Enable email"
        hint="Used when Telegram is off, muted by quiet hours, or fails."
        checked={draft.smtp.enabled}
        onCheckedChange={(enabled) => patch("smtp", { enabled })}
      />
      <div className="grid grid-cols-[1fr_100px] gap-3">
        <Field label="Host">
          <Input
            value={draft.smtp.host}
            onChange={(event) => patch("smtp", { host: event.target.value })}
          />
        </Field>
        <Field label="Port">
          <Input
            type="number"
            value={draft.smtp.port}
            onChange={(event) => patch("smtp", { port: Number(event.target.value) })}
          />
        </Field>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Username">
          <Input
            value={draft.smtp.user}
            onChange={(event) => patch("smtp", { user: event.target.value })}
          />
        </Field>
        <Field label="From address">
          <Input
            value={draft.smtp.from}
            onChange={(event) => patch("smtp", { from: event.target.value })}
          />
        </Field>
      </div>
      <SecretField
        label="SMTP password"
        name={draft.smtp.passwordSecret}
        present={Boolean(secrets[draft.smtp.passwordSecret])}
      />
      <Switch
        label="TLS on connect (port 465)"
        checked={draft.smtp.secure}
        onCheckedChange={(secure) => patch("smtp", { secure })}
      />
      <Switch
        label="Always send email, not only on Telegram failure"
        checked={draft.smtp.alwaysSend}
        onCheckedChange={(alwaysSend) => patch("smtp", { alwaysSend })}
      />
      <div className="flex gap-1.5">
        <Input
          value={testEmail}
          placeholder="test recipient"
          onChange={(event) => setTestEmail(event.target.value)}
        />
        <Button
          variant="primary"
          onClick={() =>
            api
              .testSmtp(testEmail || draft.smtp.from)
              .catch((error: Error) => pushToast("error", error.message))
          }
        >
          <Send className="h-3 w-3" />
          send test
        </Button>
      </div>
    </Card>
  );
}
