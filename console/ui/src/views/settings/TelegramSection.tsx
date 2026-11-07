import { Send } from "lucide-react";
import {
  Button,
  Card,
  Field,
  Input,
  SectionTitle,
  Select,
  Switch,
} from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { useStore } from "@/store";
import type { SettingsSectionProps } from "./shared";
import { SEVERITY_OPTIONS, SecretField } from "./shared";

export function TelegramSection({ draft, patch }: SettingsSectionProps) {
  const secrets = useStore((s) => s.secrets);
  const pushToast = useStore((s) => s.pushToast);

  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>Telegram</SectionTitle>
      <Switch
        label="Enable Telegram alerting"
        checked={draft.telegram.enabled}
        onCheckedChange={(enabled) => patch("telegram", { enabled })}
      />
      <SecretField
        label="Bot token"
        name={draft.telegram.botTokenSecret}
        present={Boolean(secrets[draft.telegram.botTokenSecret])}
        hint="Encrypted at rest with AES-256-GCM; never sent back to this UI."
      />
      <div className="grid grid-cols-2 gap-3">
        <Field label="Chat ID" hint="Used for the test message and as the default target.">
          <Input
            value={draft.telegram.chatId}
            onChange={(event) => patch("telegram", { chatId: event.target.value })}
          />
        </Field>
        <Field label="Minimum severity to notify">
          <Select
            value={String(draft.telegram.minSeverity)}
            onValueChange={(value) => patch("telegram", { minSeverity: Number(value) })}
            options={SEVERITY_OPTIONS}
          />
        </Field>
      </div>
      <Switch
        label="Quiet hours"
        hint="Mutes Telegram outside working hours. Severity 1 always goes through."
        checked={draft.telegram.quietHours.enabled}
        onCheckedChange={(enabled) =>
          patch("telegram", { quietHours: { ...draft.telegram.quietHours, enabled } })
        }
      />
      {draft.telegram.quietHours.enabled ? (
        <div className="grid grid-cols-2 gap-3">
          <Field label="Quiet from (hour)">
            <Input
              type="number"
              min="0"
              max="23"
              value={draft.telegram.quietHours.startHour}
              onChange={(event) =>
                patch("telegram", {
                  quietHours: {
                    ...draft.telegram.quietHours,
                    startHour: Number(event.target.value),
                  },
                })
              }
            />
          </Field>
          <Field label="Quiet until (hour)">
            <Input
              type="number"
              min="0"
              max="23"
              value={draft.telegram.quietHours.endHour}
              onChange={(event) =>
                patch("telegram", {
                  quietHours: {
                    ...draft.telegram.quietHours,
                    endHour: Number(event.target.value),
                  },
                })
              }
            />
          </Field>
        </div>
      ) : null}
      <Button
        variant="primary"
        onClick={() =>
          api.testTelegram().catch((error: Error) => pushToast("error", error.message))
        }
        className="self-start"
      >
        <Send className="h-3 w-3" />
        send test message
      </Button>
    </Card>
  );
}
