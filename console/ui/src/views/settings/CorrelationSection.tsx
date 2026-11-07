import { Card, Field, Input, SectionTitle, Switch } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import type { SettingsSectionProps } from "./shared";
import { GROUP_DIMENSIONS } from "./shared";

export function CorrelationSection({ draft, patch }: SettingsSectionProps) {
  return (
    <Card className="flex flex-col gap-3">
      <SectionTitle>Incident correlation</SectionTitle>
      <Switch
        checked={draft.incidents.enabled}
        onCheckedChange={(enabled) => patch("incidents", { enabled })}
        label="Group related alerts into incidents"
      />
      <div className="grid grid-cols-2 gap-3">
        <Field
          label="Correlation window (minutes)"
          hint="Alerts sharing an indicator inside this window join the same incident."
        >
          <Input
            type="number"
            min="1"
            value={draft.incidents.correlationWindowMinutes}
            onChange={(event) =>
              patch("incidents", {
                correlationWindowMinutes: Number(event.target.value),
              })
            }
          />
        </Field>
        <Field
          label="Narrate at alert count"
          hint="How many alerts an incident needs before the model is asked to write it up."
        >
          <Input
            type="number"
            min="1"
            value={draft.incidents.narrateAtAlertCount}
            onChange={(event) =>
              patch("incidents", { narrateAtAlertCount: Number(event.target.value) })
            }
          />
        </Field>
      </div>
      <Field label="Group by" hint="Checked deterministically, never by the model.">
        <div className="flex flex-wrap gap-1">
          {GROUP_DIMENSIONS.map((dimension) => {
            const on = draft.incidents.groupBy.includes(dimension.value);
            return (
              <button
                key={dimension.value}
                type="button"
                onClick={() =>
                  patch("incidents", {
                    groupBy: on
                      ? draft.incidents.groupBy.filter((entry) => entry !== dimension.value)
                      : [...draft.incidents.groupBy, dimension.value],
                  })
                }
                className={cn(
                  "rounded-sm border px-2 py-0.5 text-[10px] transition-colors",
                  on ? "border-edge bg-active text-ink" : "border-edge text-ink-dim",
                )}
              >
                {dimension.label}
              </button>
            );
          })}
        </div>
      </Field>
    </Card>
  );
}
